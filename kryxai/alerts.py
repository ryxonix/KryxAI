"""Alert delivery for scan findings.

Every channel is optional and every channel is an outbound network call, which
is the one thing this package otherwise never does. KryxAI is a passive
observer: it reads a capture and reports on it, and it never touches the mail
servers it describes. Alerting is the single exception, it is opt-in, and it
only ever sends *out* what the scan already found.

Three properties are load-bearing, and the module is shaped around them:

**Alerting can never fail a scan.** A scan is evidence; losing it because a
webhook timed out would be exactly the wrong trade. Delivery failures are
recorded in `report["alerts"]` and the scan still returns.

**A failed delivery is never silent.** If the operator is not told, they will
believe they were notified. Every attempt is recorded with a status, so the
report can say "the Telegram delivery failed" rather than implying a page went
out that never did.

**No credential is ever logged or echoed.** Tokens and passwords appear only as
the literal they are used in. Delivery records carry the channel name and a
redacted target, never the secret.

Unconfigured channels are skipped, never fatal - so a default install, which
configures nothing, makes no network call at all.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Tuple

from .config import Settings

_LOG = logging.getLogger("kryxai.alerts")

# Most severe first. The index is the rank; lower sorts higher.
SEVERITY_ORDER: Tuple[str, ...] = ("critical", "high", "medium", "low", "info")
UNKNOWN_SEVERITY_RANK = len(SEVERITY_ORDER)

# A finding at or above this severity triggers a notification. "info" exists in
# every scan, so alerting on it would page an operator for a clean capture.
DEFAULT_MIN_SEVERITY = "high"

# Never let a delivery attempt block a scan indefinitely. Applied per attempt,
# so the worst case is channels x (retries + 1) x this.
DEFAULT_TIMEOUT_S = 5.0

# Backoff between retries, capped: a scan must not spend its time sleeping for
# a dead webhook.
RETRY_BACKOFF_S = 0.5
RETRY_BACKOFF_MAX_S = 4.0

# Upper bound on findings quoted in an alert body. An alert is a prompt to
# investigate, not a data dump; the full finding list is in the report.
MAX_LISTED_FINDINGS = 8


def severity_rank(severity: str) -> int:
    """Sort key for severities, with anything unrecognised ranked last."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return UNKNOWN_SEVERITY_RANK


@dataclass
class Delivery:
    """The record of one attempt to notify one channel.

    `error` is the operator's only explanation of what went wrong, so it holds
    the exception text with any credential-looking substring removed.
    """

    channel: str
    target: str
    status: str  # "sent" | "failed"
    attempts: int
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "channel": self.channel,
            # The target is a redaction, not the configured value: a Telegram
            # target is "bot<redacted>" and an SMTP one is a host, never a
            # password or a full chat id.
            "target": self.target,
            "status": self.status,
            "attempts": self.attempts,
            "error": self.error,
        }


@dataclass
class AlertResult:
    """What dispatch did, for the report to record."""

    enabled: bool
    min_severity: str
    triggered: bool
    deliveries: List[Delivery] = field(default_factory=list)
    skipped_reason: Optional[str] = None

    @property
    def ok(self) -> bool:
        return all(d.status == "sent" for d in self.deliveries)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "min_severity": self.min_severity,
            "triggered": self.triggered,
            # Always present, and always the full list. A caller that checks
            # `triggered` and then reads `failures` must not have to infer
            # success from an absent key.
            "channels_configured": sorted({d.channel for d in self.deliveries}),
            "deliveries": [d.to_dict() for d in self.deliveries],
            "failures": [d.to_dict() for d in self.deliveries if d.status != "sent"],
            "skipped_reason": self.skipped_reason,
            "note": (
                "Alert delivery is best-effort and never affects the scan result. "
                "A failure listed here means the operator was not notified; it is "
                "recorded rather than swallowed, so an unnotified scan is never "
                "mistaken for a notified one."
            ),
        }


def _redact(text: str, *secrets: str) -> str:
    """Remove any configured secret from a string bound for a log or a report.

    Applied to exception text because a urllib error can echo the URL it failed
    on, and a Telegram URL carries the bot token in the path.
    """
    out = text
    for secret in secrets:
        if secret:
            out = out.replace(secret, "<redacted>")
    return out


# ── message composition ───────────────────────────────────────────────────


def _triggering_findings(findings: List[Dict[str, Any]], min_severity: str) -> List[Dict[str, Any]]:
    cutoff = severity_rank(min_severity)
    return [
        f
        for f in findings
        if severity_rank(f.get("severity", "info")) <= cutoff
    ]


def _posture_line(report: Dict[str, Any]) -> str:
    posture = report.get("posture") or {}
    grade = posture.get("grade", "?")
    score = posture.get("score", "?")
    return f"posture {grade} ({score}/100) {posture.get('label', '')}".strip()


def build_message(report: Dict[str, Any], min_severity: str) -> Tuple[str, str]:
    """The shared subject and body, in plain text.

    Plain text on purpose: every supported channel renders it, and a body that
    only one channel can display is how a finding ends up invisible in the
    other three.
    """
    findings = _triggering_findings(report.get("findings") or [], min_severity)
    source = report.get("source") or {}
    counts = report.get("counts") or {}

    subject = (
        f"KryxAI {grade_word(report)} - "
        f"{len(findings)} finding(s) at or above {min_severity}"
    )

    lines = [
        f"KryxAI {report.get('version', '?')}  {_posture_line(report)}",
        "",
        f"capture : {source.get('path', '?')}",
        f"sha256  : {source.get('sha256', '?')}",
        f"packets : {counts.get('sessions', 0)} session(s), "
        f"{counts.get('findings', 0)} finding(s) total",
        "",
        f"At or above {min_severity}:",
    ]
    for f in findings[:MAX_LISTED_FINDINGS]:
        risk = f.get("risk") or {}
        lines.append(
            f"  [{f.get('severity', '?')}] {risk.get('priority', '?')} "
            f"{f.get('code', '?')}  {f.get('endpoint') or '-'}"
        )
    if len(findings) > MAX_LISTED_FINDINGS:
        lines.append(f"  ... and {len(findings) - MAX_LISTED_FINDINGS} more")
    if not findings:
        lines.append("  (none)")
    return subject, "\n".join(lines)


def grade_word(report: Dict[str, Any]) -> str:
    """A short summary for the subject line, where the grade is the point."""
    grade = str((report.get("posture") or {}).get("grade", "?")).upper()
    return f"posture {grade}"


# ── channels ──────────────────────────────────────────────────────────────


def _post_json(url: str, payload: Dict[str, Any], timeout: float, headers: Dict[str, str]) -> None:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    for key, value in headers.items():
        req.add_header(key, value)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if not 200 <= resp.status < 300:
            raise RuntimeError(f"HTTP {resp.status}")


def send_telegram(settings: Settings, subject: str, body: str, timeout: float) -> str:
    token = settings.telegram_bot_token
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    _post_json(
        url,
        {"chat_id": settings.telegram_chat_id, "text": f"{subject}\n\n{body}"},
        timeout,
        {},
    )
    return "bot<redacted>"


def send_ntfy(settings: Settings, subject: str, body: str, timeout: float) -> str:
    base = settings.ntfy_server.rstrip("/")
    url = f"{base}/{urllib.parse.quote(settings.ntfy_topic, safe='')}"
    req = urllib.request.Request(url, data=body.encode("utf-8"), method="POST")
    req.add_header("Title", subject)
    req.add_header("Markdown", "no")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if not 200 <= resp.status < 300:
            raise RuntimeError(f"HTTP {resp.status}")
    return f"topic {settings.ntfy_topic}"


def send_webhook(settings: Settings, subject: str, body: str, timeout: float) -> str:
    parts = urllib.parse.urlsplit(settings.webhook_url)
    _post_json(
        settings.webhook_url,
        {"subject": subject, "body": body, "source": "kryxai"},
        timeout,
        {},
    )
    return f"host {parts.hostname or '?'}"


def send_email(settings: Settings, subject: str, body: str, timeout: float) -> str:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_user
    message["To"] = ", ".join(
        x.strip() for x in settings.alert_email_to.split(",") if x.strip()
    )
    message.set_content(body)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=timeout) as smtp:
        smtp.ehlo()
        # starttls() only if the server advertises it. A mail server that
        # accepts the alert in cleartext is the operator's own mail path, not
        # the traffic KryxAI analyses, so this degrades rather than raising.
        if smtp.has_extn("starttls"):
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        if settings.smtp_password:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(message)
    return f"host {settings.smtp_host}"


CHANNELS = {
    "telegram": send_telegram,
    "email": send_email,
    "ntfy": send_ntfy,
    "webhook": send_webhook,
}


def _deliver(
    channel: str,
    settings: Settings,
    subject: str,
    body: str,
    timeout: float,
    retries: int,
) -> Delivery:
    """One channel, with bounded retries.

    Retries exist because a transient DNS or connection failure should not
    silence a critical finding, but they are bounded and the backoff is capped:
    an unreachable channel must cost seconds, not minutes, because the scan
    that triggered it is still running.
    """
    fn = CHANNELS[channel]
    attempts = 0
    last_error: Optional[str] = None
    target = "?"
    for attempt in range(max(1, retries + 1)):
        attempts += 1
        try:
            target = fn(settings, subject, body, timeout)
            return Delivery(channel=channel, target=target, status="sent", attempts=attempts)
        except Exception as exc:  # noqa: BLE001 - a channel must not escape
            last_error = _redact(
                f"{type(exc).__name__}: {exc}",
                settings.telegram_bot_token,
                settings.smtp_password,
                settings.webhook_url,
            )
            if attempt < retries:
                time.sleep(min(RETRY_BACKOFF_S * (2**attempt), RETRY_BACKOFF_MAX_S))
    _LOG.warning("alert delivery via %s failed: %s", channel, last_error)
    return Delivery(
        channel=channel,
        target=target,
        status="failed",
        attempts=attempts,
        error=last_error,
    )


# ── entry point ───────────────────────────────────────────────────────────


def dispatch(report: Dict[str, Any], settings: Optional[Settings] = None) -> AlertResult:
    """Notify the configured channels about this scan's serious findings.

    Never raises. An operator with no channels configured gets a disabled
    result and no network call, which is what a default install does.
    """
    s = settings or Settings()
    min_severity = (s.alert_min_severity or DEFAULT_MIN_SEVERITY).lower()
    if min_severity not in SEVERITY_ORDER:
        min_severity = DEFAULT_MIN_SEVERITY

    channels = [c for c in s.active_alert_channels() if c in CHANNELS]
    if not s.alerts_enabled:
        return AlertResult(
            enabled=False, min_severity=min_severity, triggered=False,
            skipped_reason="alerting is disabled (KRYXAI_ALERTS_ENABLED=false)",
        )
    if not channels:
        return AlertResult(
            enabled=False, min_severity=min_severity, triggered=False,
            skipped_reason="no alert channel is configured",
        )

    findings = _triggering_findings(report.get("findings") or [], min_severity)
    if not findings:
        return AlertResult(
            enabled=True, min_severity=min_severity, triggered=False,
            skipped_reason=(
                f"no finding at or above {min_severity}; "
                f"{len(report.get('findings') or [])} finding(s) below the threshold"
            ),
        )

    subject, body = build_message(report, min_severity)
    timeout = float(s.alert_timeout_s or DEFAULT_TIMEOUT_S)
    retries = max(0, int(s.max_alert_retries))

    deliveries = [
        _deliver(c, s, subject, body, timeout, retries) for c in sorted(channels)
    ]
    return AlertResult(
        enabled=True,
        min_severity=min_severity,
        triggered=True,
        deliveries=deliveries,
    )
