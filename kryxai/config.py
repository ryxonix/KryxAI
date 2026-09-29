"""Environment-driven configuration.

Every knob is overridable with a `KRYXAI_`-prefixed environment variable or a
line in `.env`. There is no code path that silently relaxes a gate; anything
that can be raised at runtime is printed when it is raised.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

from kryxai import CHAIN_ID

_LOG = logging.getLogger("kryxai.config")

# Read-only resources that ship inside the package. These must be resolved from
# the package directory, because that is where the wheel actually puts them.
PACKAGE_DIR = Path(__file__).resolve().parent

# The source checkout, i.e. the directory that contains the `kryxai` package.
_SOURCE_ROOT = PACKAGE_DIR.parent


def _default_data_root() -> Path:
    """Where writable state (database, reports, signing keys) belongs.

    An installed wheel must never write into ``site-packages``: it may be
    read-only under a system or distro package manager, and dropping the
    RSA-3072 report-signing key next to other packages puts private key material
    somewhere world-readable. A source checkout keeps its state beside the code
    so development still looks like the repository.
    """
    override = os.environ.get("KRYXAI_HOME")
    if override:
        return Path(override).expanduser()

    if (_SOURCE_ROOT / "pyproject.toml").is_file():
        return _SOURCE_ROOT

    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / "KryxAI"

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg).expanduser() / "kryxai"
    return Path.home() / ".local" / "share" / "kryxai"


DATA_ROOT = _default_data_root()

# Kept as a module-level name because it is the historical spelling and is
# re-exported in a few places; it is the same directory as DATA_ROOT.
BACKEND_ROOT = DATA_ROOT


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="KRYXAI_",
        env_file=str(DATA_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Identity ──────────────────────────────────────────────────────────
    chain_id: str = CHAIN_ID
    report_aad: bytes = b"kryxai-report-v1"

    # ── Storage ───────────────────────────────────────────────────────────
    # Writable state lives under DATA_ROOT, never inside site-packages.
    database_path: str = str(DATA_ROOT / "kryxai.db")
    reports_dir: str = str(DATA_ROOT / "reports")
    report_keys_dir: str = str(DATA_ROOT / "reports" / "keys")
    # Windows ships no Devanagari font on a default install, and a PDF cannot
    # render Devanagari without one. Point this at a .ttf (for example
    # NotoSansDevanagari-Regular.ttf) to get bilingual PDFs; when it is unset
    # and no known font is found, the PDF says Hindi text was omitted instead
    # of emitting blank glyphs.
    devanagari_font_path: str = ""
    # Read-only resources resolved from the installed package, not DATA_ROOT.
    policies_path: str = str(PACKAGE_DIR / "policies.json")
    statute_sources_path: str = str(PACKAGE_DIR / "compliance" / "sources.json")

    # ── Analysis ──────────────────────────────────────────────────────────
    # The fusion weights mirror the validated 0.7 model / 0.3 explainable split.
    fusion_model_weight: float = 0.7
    fusion_xai_weight: float = 0.3

    # Certificate validity is judged against the *capture* time, not the clock
    # at analysis time. This is the single most common source of wrong answers
    # in expiry analysis, so it is not configurable to anything else.
    expiry_reference: str = "capture_time"

    # Bytes of plaintext application data retained per direction for the
    # plaintext-leak detector. Nothing encrypted is ever retained.
    max_plaintext_sample_bytes: int = 4096

    # ── Risk banding ──────────────────────────────────────────────────────
    medium_edge: float = 0.35
    high_edge: float = 0.55
    critical_edge: float = 0.75

    # ── Evidence ledger ───────────────────────────────────────────────────
    # Local proof-of-work chain. Difficulty is stored per block and re-verified
    # against the stored value, never recomputed.
    blockchain_difficulty: int = 4

    # External anchor (Hyperledger Fabric + IPFS).
    #
    # ANCHOR_REQUIRED defaults to False on purpose. A fail-closed default means
    # every report endpoint returns 503 wherever Fabric is not running, which
    # is most free-tier deployments. The default is therefore permissive but
    # never dishonest: an unanchored report is reported as `pending` or
    # `demo`, never as `anchored`.
    blockchain_external_anchor: bool = False
    blockchain_anchor_required: bool = False

    nbf_gateway_url: str = "http://127.0.0.1:4000"
    nbf_channel: str = "mychannel"
    nbf_cc: str = "kryxai-posture"
    nbf_user: str = "User1"
    nbf_msp: str = "Org1MSP"
    nbf_cfgpath: str = ""
    nbf_ipfs_mode: str = "auto"
    ipfs_store_url: str = ""
    ipfs_api_port: int = 5001
    ipfs_gateway_port: int = 8080
    nbf_timeout_s: float = 20.0

    # ── Threat intelligence feeds ─────────────────────────────────────────
    # No public machine-readable CERT-In IoC API is known to exist. The
    # enrichment path is a pluggable adapter fed by a bundled, versioned,
    # clearly-labelled offline snapshot. `bundle` is the default and makes no
    # network call; `http` requires an operator-supplied endpoint.
    ioc_feed_mode: str = "bundle"
    ioc_feed_url: str = ""
    ioc_feed_path: str = str(PACKAGE_DIR / "feeds" / "ioc_snapshot.json")
    ioc_feed_dir: str = str(PACKAGE_DIR / "data" / "feeds")

    # Optional ONNX risk model, with three distinct states:
    #   None  -> auto: use a model installed alongside the package, if present
    #   ""    -> explicitly off: the rules alone, never auto-discovered
    #   path  -> use exactly this file
    # The default is None rather than "" so that installing a model makes it
    # take effect; making "" the default would leave the auto-discovery branch
    # unreachable and the installed model silently unused. A missing or
    # unloadable model never fails a scan.
    onnx_model_path: Optional[str] = None

    def resolved_onnx_model_path(self) -> str:
        """The model to load: explicit setting, else a bundled model, else none."""
        if self.onnx_model_path is not None:
            if self.onnx_model_path == "":
                # Explicitly disabled. A bundled model is deliberately not
                # discovered in this state.
                return ""
            return self.onnx_model_path
        bundled = PACKAGE_DIR / "scoring" / "risk_model.onnx"
        return str(bundled) if bundled.is_file() else ""

    # ── Alerting (all optional; missing credentials are skipped, not fatal)
    # Alerting is the only outbound network call this package makes, so a
    # default install must stay silent. `alerts_enabled` below is True; what
    # keeps it quiet is that no channel carries credentials by default, and
    # `dispatch` makes no request at all without one.
    alerts_enabled: bool = True
    # A finding at or above this severity notifies. "info" is present in every
    # scan, so alerting on it would page an operator for a clean capture.
    alert_min_severity: str = "high"
    # Per-attempt socket timeout. Worst case a scan spends
    # channels x (max_alert_retries + 1) x this on delivery.
    alert_timeout_s: float = 5.0
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    alert_email_to: str = ""
    ntfy_topic: str = ""
    ntfy_server: str = "https://ntfy.sh"
    webhook_url: str = ""
    max_alert_retries: int = 3

    # ── Server ────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: List[str] = ["http://localhost:5173", "http://localhost:5174"]

    def active_alert_channels(self) -> List[str]:
        """Channels that are actually configured. Never raises."""
        configured = {
            "telegram": bool(self.telegram_bot_token and self.telegram_chat_id),
            "email": bool(
                self.smtp_host and self.smtp_user and self.alert_email_to
            ),
            "ntfy": bool(self.ntfy_topic),
            "webhook": bool(self.webhook_url),
        }
        return [name for name, ready in configured.items() if ready]


settings = Settings()


def ensure_writable_dirs(settings: "Settings | None" = None) -> None:
    """Create the directories KryxAI writes to.

    Called at import so a first run on a clean machine cannot fail merely
    because the data root does not exist yet. Failures are logged and left to
    the operation that needs the directory, so a read-only data root produces a
    clear error at the point of use rather than a confusing one at import.
    """
    s = settings or Settings()
    for path in (s.database_path, s.reports_dir, s.report_keys_dir):
        try:
            target = Path(path)
            (target if target.suffix == "" else target.parent).mkdir(
                parents=True, exist_ok=True
            )
        except OSError as exc:  # pragma: no cover - depends on host permissions
            _LOG.warning("could not create KryxAI data directory for %s: %s", path, exc)


ensure_writable_dirs(settings)


def _report_relaxations() -> None:
    """Announce any gate that is not at its strictest setting.

    Logged at INFO, not WARNING: this is a normal, supported configuration on a
    machine with no Fabric network, and a warning on every import trains
    operators to ignore warnings. The scan summary and the report both state
    the effective chain state explicitly, which is where it actually matters.
    """
    if not settings.blockchain_anchor_required:
        _LOG.info(
            "KRYXAI_BLOCKCHAIN_ANCHOR_REQUIRED is false: reports are generated "
            "without a mandatory external anchor and are labelled pending/demo, "
            "never anchored."
        )
    if settings.ioc_feed_mode == "http" and not settings.ioc_feed_url:
        _LOG.info(
            "KRYXAI_IOC_FEED_MODE=http but KRYXAI_IOC_FEED_URL is empty; "
            "falling back to the bundled offline snapshot."
        )


_report_relaxations()
