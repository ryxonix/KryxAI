"""Report rendering, signing and export.

Everything the package hands to a human goes through here: the signed JSON
artefact, the two HTML renderings, and the optional PDF. The order those are
produced in is not incidental and is enforced below - the coverage row has to
be settled before the JSON is serialised, because the JSON is itself one of the
exports that row describes.

The PDF is a genuine optional extra. A base install has no ReportLab, and the
usual failure mode for that is a report command that dies halfway through with
an ImportError. Here the PDF is simply not produced, ``write`` returns without
a ``pdf`` key so no caller can mistake a skipped format for an empty file, and
the CLI prints why. Nothing in this module raises to say "no PDF" - the
absence is reported, which is what the README promises.
"""

from __future__ import annotations

import html
import json
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from kryxai import CHAIN_ID
from kryxai.coverage import refresh_export_coverage
from kryxai.i18n import DISCLAIMER_EN, disclaimer, section_title

from .sign import SIGNING_KEY_BITS, ReportSignature, sign, signing_payload
from .verify import verify

PDF_UNAVAILABLE_HINT = (
    "PDF skipped: the optional reports extra is not installed. "
    "Install it with `pip install -e \".[reports]\"` - or install the "
    "`kryxai[reports]` extra - to also get a PDF. The JSON and HTML exports "
    "were written in full."
)

_KEY_FILE = "report_signing_key.pem"

DEFAULT_LANGS = ("en", "hi")


# ── optional PDF backend ───────────────────────────────────────────────────


def pdf_available() -> bool:
    """Whether ReportLab can be imported.

    Looked up as a module global on every call so a caller (or a test) can
    replace it and have ``write`` honour that, rather than having the decision
    baked in at import time.
    """
    try:
        import reportlab  # noqa: F401
    except Exception:  # noqa: BLE001 - a broken install is just "unavailable"
        return False
    return True


# ── signing key custody ────────────────────────────────────────────────────


def _key_path(settings: Any) -> Path:
    return Path(settings.report_keys_dir) / _KEY_FILE


def load_or_create_key(settings: Any) -> tuple:
    """Return ``(private_key, mode)`` for report signing.

    ``mode`` is ``"loaded"`` or ``"generated"`` and is surfaced in the report,
    because a signature made with a freshly minted key says something different
    from one made with the key the operator has been using all along.

    The private key is written with owner-only permissions where the platform
    supports it. On Windows the mode bits are largely advisory, so this is a
    best effort rather than a guarantee, and the README says as much.
    """
    path = _key_path(settings)
    if path.is_file():
        key = serialization.load_pem_private_key(
            path.read_bytes(), password=None
        )
        return key, "loaded"

    key = rsa.generate_private_key(public_exponent=65537, key_size=SIGNING_KEY_BITS)
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    try:
        path.chmod(0o600)
    except (OSError, NotImplementedError):
        # Advisory on Windows; the key is still only as readable as the
        # per-user data directory that holds it.
        pass
    return key, "generated"


# ── naming ─────────────────────────────────────────────────────────────────


def _slug(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(text)).strip("._-")
    return cleaned[:64] or "capture"


def report_basename(report: Dict[str, Any]) -> str:
    """The stem every artefact for this report shares.

    When the scan recorded an id, the stem *is* that id and nothing else. The
    API rehydrates a report written by a previous process by reading
    ``<reports_dir>/<scan_id>.json``, and ``list_scans`` reads the file stem
    back as the scan id, so a decorative prefix here would make a report
    unreachable after a restart. Characters that could escape the reports
    directory are stripped rather than sanitised into something that still
    looks like an id.
    """
    evidence = report.get("evidence") or {}
    scan_id = str(evidence.get("scan_id") or "").strip()
    if scan_id:
        safe = re.sub(r"[^A-Za-z0-9_-]", "", scan_id)[:64]
        if safe:
            return safe

    # No id: the scan ran without persistence, so nothing will look this file
    # up later. Fall back to something readable and collision-resistant.
    source = report.get("source") or {}
    stem = _slug(Path(str(source.get("path") or "capture")).stem)
    digest = str(source.get("sha256") or "")[:12]
    return f"kryxai-{stem}-{digest}" if digest else f"kryxai-{stem}"


# ── HTML ───────────────────────────────────────────────────────────────────


_STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
       margin: 0; padding: 2rem 1.25rem; line-height: 1.55;
       background: #f6f7f9; color: #14161a; }
main { max-width: 60rem; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.15rem; margin: 2rem 0 .5rem;
     padding-bottom: .3rem; border-bottom: 2px solid #d8dce3; }
h3 { font-size: 1rem; margin: 1.25rem 0 .35rem; }
.sub { color: #5b6270; margin: 0 0 1.25rem; font-size: .9rem; }
.card { background: #fff; border: 1px solid #dfe3ea; border-radius: 8px;
       padding: 1rem 1.1rem; margin: .75rem 0; }
.banner { padding: .7rem .9rem; border-radius: 6px; font-size: .9rem;
          margin: 1rem 0; border-left: 4px solid; }
.banner.signed { background: #e8f5ec; border-color: #2e7d4f; color: #1b4d31; }
.banner.unsigned { background: #fdf3e3; border-color: #b8860b; color: #6b4e07; }
.grade { font-size: 2.6rem; font-weight: 700; line-height: 1; }
table { border-collapse: collapse; width: 100%; font-size: .88rem; }
th, td { text-align: left; padding: .4rem .5rem;
         border-bottom: 1px solid #e6e9ef; vertical-align: top; }
th { background: #f0f2f6; font-weight: 600; }
code, .mono { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
              font-size: .85em; word-break: break-all; }
.sev { font-weight: 700; }
.sev-critical, .sev-high { color: #b3261e; }
.sev-medium { color: #9a6700; }
.sev-low, .sev-info { color: #3b5b8c; }
.muted { color: #5b6270; }
.bar { height: .5rem; background: #e6e9ef; border-radius: 3px;
       overflow: hidden; margin-top: .3rem; }
.bar > span { display: block; height: 100%; background: #3b6ea5; }
.disclaimer { margin-top: 2.5rem; padding: .8rem .9rem; font-size: .85rem;
             color: #4a5160; background: #eef1f5; border-radius: 6px; }
"""


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _bar(value: Any) -> str:
    try:
        pct = max(0.0, min(100.0, float(value)))
    except (TypeError, ValueError):
        return ""
    return f'<div class="bar"><span style="width:{pct:.1f}%"></span></div>'


def _signature_banner(report: Dict[str, Any], lang: str) -> str:
    """State plainly whether this document is signed.

    An unsigned report says so in the same place a signed one does. A reader
    must never have to infer the signing state from an absence.
    """
    sig = report.get("signature")
    if sig:
        return (
            '<div class="banner signed"><strong>Signed.</strong> Detached '
            f'{_e(sig.get("algorithm"))} signature over chain '
            f'{_e(sig.get("chain_id"))} (AAD {_e(sig.get("aad"))}), key '
            f'{_e(sig.get("public_key_fingerprint"))}, created '
            f'{_e(sig.get("created_at"))}. Verification: '
            f'{_e(report.get("signature_verification"))}</div>'
        )
    return (
        '<div class="banner unsigned"><strong>This report is unsigned.</strong> '
        "No detached signature is attached, so nothing in this document proves "
        "it has not been altered since it was produced. Treat it as an "
        "unattested rendering rather than as evidence.</div>"
    )


def _executive_summary(report: Dict[str, Any], lang: str) -> str:
    posture = report.get("posture") or {}
    counts = report.get("counts") or {}
    sev = counts.get("by_severity") or {}
    source = report.get("source") or {}
    capture = report.get("capture") or {}

    rows = [
        ("Grade", f"{posture.get('grade', '?')} ({posture.get('score', '?')}/100)"),
        ("Posture", posture.get("label", "")),
        ("Capture", source.get("path", "?")),
        ("SHA-256", source.get("sha256", "")),
        ("Format", source.get("format", "")),
        ("Packets", f"{capture.get('packet_count', '?')} "
                    f"({capture.get('decoded', 0)} decoded, "
                    f"{capture.get('undecoded', 0)} undecoded)"),
        ("Sessions", f"{counts.get('sessions', 0)} total, "
                     f"{counts.get('mail_sessions', 0)} mail, "
                     f"{counts.get('tls_upgraded', 0)} upgraded to TLS"),
        ("Findings", f"{counts.get('findings', 0)} "
                     + ", ".join(f"{k} {v}" for k, v in sorted(sev.items()) if v)),
    ]

    hi = lang == "hi"
    head = ["Metric", "मान"] if hi else ["Metric", "Value"]
    body = "".join(
        f"<tr><th>{_e(k)}</th><td class='mono'>{_e(v)}</td></tr>" for k, v in rows
    )
    return f"<table><thead><tr><th>{_e(head[0])}</th><th>{_e(head[1])}</th></tr></thead><tbody>{body}</tbody></table>"


def _posture_section(report: Dict[str, Any], lang: str) -> str:
    posture = report.get("posture") or {}
    dims = posture.get("dimensions") or {}
    explain = posture.get("dimension_explanation") or {}
    weights = posture.get("weights") or {}

    rows = ""
    for name, score in dims.items():
        meta = explain.get(name) or {}
        rows += (
            f"<tr><td>{_e(name)}</td><td>{_e(score)}{_bar(score)}</td>"
            f"<td class='muted'>{_e(weights.get(name, ''))}</td>"
            f"<td class='muted'>{_e(meta.get('rationale', ''))}</td></tr>"
        )
    if not rows:
        return "<p class='muted'>No dimensions were scored.</p>"

    not_assessed = posture.get("not_assessed") or []
    extra = (
        f"<p class='muted'>Not assessed: {_e(', '.join(not_assessed))}. "
        "A dimension that could not be measured is reported as such rather "
        "than scored as zero.</p>"
        if not_assessed
        else ""
    )
    return f"<table><thead><tr><th>Dimension</th><th>Score</th><th>Weight</th><th>Why not 100</th></tr></thead><tbody>{rows}</tbody></table>{extra}"


def _title_for(finding: Dict[str, Any], lang: str) -> str:
    if lang == "hi" and finding.get("title_hi"):
        return str(finding["title_hi"])
    return str(finding.get("title") or finding.get("code", ""))


def _findings_section(report: Dict[str, Any], lang: str) -> str:
    findings = report.get("findings") or []
    if not findings:
        return "<p class='muted'>No findings were raised for this capture.</p>"
    out = ""
    for f in findings:
        risk = f.get("risk") or {}
        sev = str(f.get("severity", "info"))
        out += (
            "<div class='card'>"
            f"<h3><span class='sev sev-{_e(sev)}'>{_e(sev.upper())}</span> "
            f"{_e(risk.get('priority', ''))} &mdash; {_e(_title_for(f, lang))}</h3>"
            f"<p class='muted mono'>{_e(f.get('code'))} &middot; "
            f"{_e(f.get('endpoint') or 'n/a')}</p>"
            f"<p>{_e(f.get('detail', ''))}</p>"
        )
        if f.get("remediation"):
            label = "उपचार" if lang == "hi" else "Remediation"
            out += (
                f"<p><strong>{_e(label)}:</strong> {_e(f.get('remediation'))}</p>"
            )
        if risk:
            out += (
                f"<p class='muted'>Risk {_e(risk.get('total'))}/100 "
                f"({_e(risk.get('rule_score', '?'))} rules"
                + (f", {_e(risk.get('model_score'))} model" if risk.get("model_score") is not None else "")
                + f")</p>"
            )
        out += "</div>"
    return out


def _sessions_section(report: Dict[str, Any], lang: str) -> str:
    sessions = report.get("sessions") or []
    if not sessions:
        return "<p class='muted'>No conversations were reconstructed.</p>"
    rows = ""
    for s in sessions:
        tls = s.get("tls") or {}
        starttls = s.get("starttls") or {}
        rows += (
            f"<tr><td class='mono'>{_e(s.get('endpoint'))}</td>"
            f"<td>{_e(s.get('protocol'))}</td>"
            f"<td>{_e(starttls.get('state'))}</td>"
            f"<td>{_e(tls.get('version') or '-')}</td>"
            f"<td class='mono'>{_e(tls.get('cipher_suite') or '-')}</td>"
            f"<td>{_e(tls.get('forward_secrecy'))}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Endpoint</th><th>Protocol</th><th>STARTTLS</th>"
        "<th>TLS</th><th>Cipher</th><th>PFS</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _compliance_section(report: Dict[str, Any], lang: str) -> str:
    items = ((report.get("compliance") or {}).get("items")) or []
    if not items:
        return "<p class='muted'>No finding mapped to a statutory provision.</p>"
    rows = ""
    for item in items:
        prov = item.get("provision") or {}
        rows += (
            f"<tr><td class='mono'>{_e(prov.get('act', ''))} "
            f"{_e(prov.get('section', ''))}</td>"
            f"<td>{_e(item.get('observation', ''))}</td>"
            f"<td class='muted'>{_e(prov.get('text', ''))}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Provision</th><th>Observation</th>"
        f"<th>Statutory text</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def _interception_section(report: Dict[str, Any], lang: str) -> str:
    ices = report.get("interception") or {}
    if not ices:
        return ""
    out = f"<p>{_e(ices.get('headline', ''))}</p>"
    sessions = ices.get("sessions") or []
    if sessions:
        rows = "".join(
            f"<tr><td class='mono'>{_e(s.get('endpoint'))}</td>"
            f"<td class='mono'>{_e(s.get('expected_token'))}</td>"
            f"<td class='mono'>{_e(s.get('observed_tokens'))}</td>"
            f"<td>{_e('+'.join(s.get('signatures') or []))}</td></tr>"
            for s in sessions
            if s.get("signatures")
        )
        if rows:
            out += (
                "<table><thead><tr><th>Endpoint</th><th>Expected</th>"
                f"<th>Observed</th><th>Signatures</th></tr></thead><tbody>{rows}</tbody></table>"
            )
    return out


def _anomalies_section(report: Dict[str, Any], lang: str) -> str:
    anomalies = report.get("anomalies") or []
    if not anomalies:
        return "<p class='muted'>No anomaly crossed its capture-local baseline.</p>"
    rows = "".join(
        f"<tr><td class='mono'>{_e(a.get('code'))}</td>"
        f"<td class='mono'>{_e(a.get('endpoint') or 'n/a')}</td>"
        f"<td>{_e(a.get('detail', ''))}</td></tr>"
        for a in anomalies
    )
    return (
        "<table><thead><tr><th>Code</th><th>Endpoint</th><th>Detail</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
    )


def _list_section(items: Any, empty: str) -> str:
    items = items or []
    if not items:
        return f"<p class='muted'>{_e(empty)}</p>"
    return "<ul>" + "".join(f"<li>{_e(i)}</li>" for i in items) + "</ul>"


def _evidence_section(report: Dict[str, Any], lang: str) -> str:
    ev = report.get("evidence") or {}
    if not ev:
        return "<p class='muted'>This scan recorded no evidence block.</p>"
    rows = "".join(
        f"<tr><th>{_e(k)}</th><td class='mono'>{_e(v)}</td></tr>"
        for k, v in ev.items()
    )
    return f"<table><tbody>{rows}</tbody></table>"


def _coverage_section(report: Dict[str, Any], lang: str) -> str:
    cov = report.get("coverage") or {}
    items = cov.get("items") or []
    if not items:
        return ""
    rows = ""
    for item in items:
        evidence = "".join(
            f"<li class='mono'>{_e(e)}</li>" for e in (item.get("evidence") or [])[:4]
        )
        rows += (
            f"<tr><td>{_e(item.get('requirement'))}</td>"
            f"<td class='mono'>{_e(item.get('status'))}</td>"
            f"<td>{_e(item.get('detail', ''))}"
            + (f"<ul>{evidence}</ul>" if evidence else "")
            + "</td></tr>"
        )
    return (
        "<table><thead><tr><th>Requirement</th><th>Status</th><th>Detail and evidence</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
    )


def _alerts_section(report: Dict[str, Any], lang: str) -> str:
    alerts = report.get("alerts")
    if not isinstance(alerts, dict):
        return ""
    deliveries = alerts.get("deliveries") or []
    if not deliveries:
        return f"<p class='muted'>{_e(alerts.get('skipped_reason') or 'No alert was sent.')}</p>"
    rows = "".join(
        f"<tr><td>{_e(d.get('channel'))}</td><td class='mono'>{_e(d.get('target'))}</td>"
        f"<td class='sev sev-{_e(d.get('status'))}'>{_e(d.get('status'))}</td>"
        f"<td class='muted'>{_e(d.get('attempts'))}"
        + (f" &mdash; {_e(d.get('error'))}" if d.get("error") else "")
        + "</td></tr>"
        for d in deliveries
    )
    return (
        f"<p class='muted'>{_e(alerts.get('note', ''))}</p>"
        "<table><thead><tr><th>Channel</th><th>Target</th><th>Status</th>"
        f"<th>Attempts</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def render_html(report: Dict[str, Any], lang: str = "en") -> str:
    """Render the report as a self-contained HTML document.

    No external stylesheet, font or script, so a report can be archived as a
    single file and still be readable years later with no network. ``lang="hi"``
    switches the section headings and finding titles to Devanagari; the data
    itself is language-neutral and is never translated.
    """
    lang = lang if lang in ("en", "hi") else "en"
    posture = report.get("posture") or {}
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    sections: List[tuple] = [
        ("executive_summary", _executive_summary(report, lang)),
        ("posture", _posture_section(report, lang)),
        ("sessions", _sessions_section(report, lang)),
        ("findings", _findings_section(report, lang)),
    ]
    interception = _interception_section(report, lang)
    if interception:
        sections.append(("interception", interception))
    sections.extend(
        [
            ("anomalies", _anomalies_section(report, lang)),
            ("compliance", _compliance_section(report, lang)),
            ("remediation", _list_section(
                [f.get("remediation") for f in (report.get("findings") or []) if f.get("remediation")],
                "No remediation was attached to any finding.",
            )),
            ("ioc", _list_section(
                ((report.get("ioc") or {}).get("sources") or [])
                and [f"{s}" for s in ((report.get("ioc") or {}).get("sources") or [])],
                "No threat-intelligence feed contributed to this scan.",
            )),
            ("limitations", _list_section(
                report.get("limitations"),
                "No limitation was recorded for this capture.",
            )),
            ("evidence", _evidence_section(report, lang)),
        ]
    )
    coverage = _coverage_section(report, lang)
    if coverage:
        sections.append(("requirements", coverage))
    alerts = _alerts_section(report, lang)
    if alerts:
        sections.append(("alerts", alerts))

    body = ""
    for key, content in sections:
        body += (
            f"<h2>{_e(section_title(key, lang))}</h2>"
            f"<div class='card'>{content}</div>"
        )

    sub = (
        f"{report.get('tool', 'KryxAI')} {report.get('version', '')} &middot; "
        f"chain {_e(report.get('chain_id', CHAIN_ID))} &middot; "
        f"generated {generated}"
    )
    return (
        "<!DOCTYPE html>\n"
        f"<html lang=\"{_e(lang)}\">\n<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_e(report_basename(report))}</title>\n"
        f"<style>{_STYLE}</style>\n</head>\n<body>\n<main>\n"
        f"<h1>KryxAI forensic report</h1>\n"
        f"<p class='sub'>{sub}</p>\n"
        f"{_signature_banner(report, lang)}\n"
        f"{body}\n"
        f"<div class='disclaimer'>{_e(disclaimer(lang))}</div>\n"
        "</main>\n</body>\n</html>\n"
    )


# ── PDF ────────────────────────────────────────────────────────────────────


def devanagari_font(settings: Any = None) -> Optional[Path]:
    """A Devanagari-capable TTF, or None.

    Windows ships none by default and a PDF cannot render Devanagari without
    one, so this returns None on most installs. The PDF then says the Hindi
    text was omitted rather than emitting blank glyphs, which is the honest
    outcome and the one the README promises.
    """
    configured = str(getattr(settings, "devanagari_font_path", "") or "")
    candidates: List[Path] = []
    if configured:
        candidates.append(Path(configured))
    candidates.extend(
        [
            Path("/usr/share/fonts/truetype/noto/NotoSansDevanagari-Regular.ttf"),
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            Path("C:/Windows/Fonts/Nirmala.ttf"),
            Path("C:/Windows/Fonts/Mangal.ttf"),
        ]
    )
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def _pdf_paragraphs(report: Dict[str, Any], font_name: Optional[str]) -> List[Any]:
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import Paragraph, Spacer

    # ReportLab rejects a style built from an overlapping kwargs dict, so the
    # shared attributes are merged explicitly rather than splatted twice.
    shared = {"fontName": font_name or "Helvetica"}

    def style(name: str, **overrides: Any) -> Any:
        return ParagraphStyle(name, **{**shared, **overrides})

    h1 = style("kryxH1", fontSize=17, leading=21, spaceAfter=6)
    h2 = style("kryxH2", fontSize=12.5, leading=16, spaceBefore=14, spaceAfter=5)
    body = style("kryxBody", fontSize=9.5, leading=13, spaceAfter=5)
    small = style("kryxSmall", fontSize=8, leading=11, textColor="#555555")

    def para(text: str, style: Any = body) -> Any:
        return Paragraph(_e(text).replace("\n", "<br/>"), style)

    story: List[Any] = [
        para("KryxAI forensic report", h1),
        para(
            f"{report.get('tool', 'KryxAI')} {report.get('version', '')}  |  "
            f"chain {report.get('chain_id', CHAIN_ID)}  |  "
            f"generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}",
            small,
        ),
        Spacer(1, 10),
    ]

    sig = report.get("signature")
    if sig:
        story.append(
            para(
                f"SIGNED. Detached {sig.get('algorithm')} signature over chain "
                f"{sig.get('chain_id')} (AAD {sig.get('aad')}), key "
                f"{sig.get('public_key_fingerprint')}, created "
                f"{sig.get('created_at')}. Verification: "
                f"{report.get('signature_verification')}",
                body,
            )
        )
    else:
        story.append(
            para(
                "UNSIGNED. No detached signature is attached, so nothing in "
                "this document proves it has not been altered since it was "
                "produced.",
                body,
            )
        )

    if not font_name:
        story.append(
            para(
                "Devanagari (Hindi) text was omitted from this PDF: no "
                "Devanagari-capable font is available to ReportLab. Set "
                "KRYXAI_DEVANAGARI_FONT_PATH to a .ttf such as "
                "NotoSansDevanagari-Regular.ttf to include it. The HTML and "
                "JSON exports are fully bilingual regardless.",
                small,
            )
        )

    posture = report.get("posture") or {}
    counts = report.get("counts") or {}
    story += [
        para("Executive summary", h2),
        para(f"Posture grade {posture.get('grade', '?')} "
             f"({posture.get('score', '?')}/100) - {posture.get('label', '')}", body),
        para(f"Sessions: {counts.get('sessions', 0)} "
             f"({counts.get('mail_sessions', 0)} mail, "
             f"{counts.get('tls_upgraded', 0)} upgraded to TLS). "
             f"Findings: {counts.get('findings', 0)}", body),
    ]

    story.append(para("Findings", h2))
    findings = report.get("findings") or []
    if not findings:
        story.append(para("No findings were raised for this capture.", body))
    for f in findings:
        risk = f.get("risk") or {}
        story.append(
            para(
                f"[{str(f.get('severity', 'info')).upper()}] "
                f"{risk.get('priority', '')} {f.get('title') or f.get('code')} "
                f"({f.get('endpoint') or 'n/a'})",
                body,
            )
        )
        if f.get("detail"):
            story.append(para(str(f["detail"]), small))
        if f.get("remediation"):
            story.append(para(f"Remediation: {f['remediation']}", small))

    if report.get("limitations"):
        story.append(para("Limitations of this analysis", h2))
        for note in report["limitations"]:
            story.append(para(f"- {note}", small))

    story.append(para("Evidence chain", h2))
    evidence = report.get("evidence") or {}
    if evidence:
        for key in sorted(evidence):
            story.append(para(f"{key}: {evidence[key]}", small))
    else:
        story.append(para("This scan recorded no evidence block.", small))

    story += [Spacer(1, 12), para(DISCLAIMER_EN, small)]
    return story


def render_pdf(report: Dict[str, Any], path: Path, settings: Any = None) -> Path:
    """Render the report to a PDF and return the path written."""
    if not pdf_available():
        raise RuntimeError(PDF_UNAVAILABLE_HINT)

    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    font_name = None
    ttf = devanagari_font(settings)
    if ttf is not None:
        try:
            # Nirmala/Mangal are display faces whose family name matters less
            # to us than the glyph coverage, so a fixed internal name is fine.
            pdfmetrics.registerFont(TTFont("KryxaiDevanagari", str(ttf)))
            font_name = "KryxaiDevanagari"
        except Exception:  # noqa: BLE001 - an unusable font falls back to English
            font_name = None

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="KryxAI forensic report",
        author=str(report.get("tool", "KryxAI")),
    )
    doc.build(_pdf_paragraphs(report, font_name))
    return path


# ── write ──────────────────────────────────────────────────────────────────


def write(
    report: Dict[str, Any],
    out_dir: Path,
    settings: Any,
    langs: Optional[Sequence[str]] = None,
    sign_reports: bool = True,
) -> Dict[str, Path]:
    """Write the JSON, HTML and (when available) PDF artefacts.

    The order here is load-bearing. ``refresh_export_coverage`` edits the
    report to record that exports happened, and the JSON is one of those
    exports, so it must be settled *before* the JSON is serialised - otherwise
    the file claims no export took place. Signing happens after that, and
    covers everything except the signature envelope, which is why the file on
    disk still verifies against its own contents.

    Returns a mapping of format name to path. ``pdf`` is absent rather than
    present-and-empty when ReportLab is missing, so a caller cannot mistake a
    skipped format for a written one.
    """
    langs = [x for x in (langs or DEFAULT_LANGS) if x in DEFAULT_LANGS] or ["en"]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    stem = report_basename(report)
    with_pdf = pdf_available()

    # Plan every filename first: the coverage row has to name the real exports,
    # and the PDF's presence is only knowable before it is written.
    planned: Dict[str, Path] = {"json": out_dir / f"{stem}.json"}
    for lang in langs:
        planned[f"html_{lang}"] = out_dir / f"{stem}.{lang}.html"
    if with_pdf:
        planned["pdf"] = out_dir / f"{stem}.pdf"

    refresh_export_coverage(report, {k: str(v) for k, v in planned.items()})

    if sign_reports:
        key, mode = load_or_create_key(settings)
        # Recorded *before* signing, not after. Anything added once the
        # signature exists but is not part of the envelope would fall outside
        # the signed payload, and the file on disk would then fail its own
        # verification - which is exactly what test_corpus's round-trip test
        # exists to catch.
        report["signature_key_mode"] = mode
        signature = sign(
            report, key, chain_id=str(getattr(settings, "chain_id", CHAIN_ID))
        )
        report["signature"] = signature.to_dict()
        ok, why = verify(report, signature, key.public_key())
        report["signature_verification"] = why if ok else f"INVALID: {why}"
    else:
        report.pop("signature", None)
        report.pop("signature_key_mode", None)
        report["signature_verification"] = (
            "absent: this report was written with signing disabled, so nothing "
            "here attests that it has not been altered"
        )

    written: Dict[str, Path] = {}
    written["json"] = out_dir / f"{stem}.json"
    written["json"].write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    for lang in langs:
        target = out_dir / f"{stem}.{lang}.html"
        target.write_text(render_html(report, lang=lang), encoding="utf-8")
        written[f"html_{lang}"] = target

    if with_pdf:
        target = out_dir / f"{stem}.pdf"
        try:
            written["pdf"] = render_pdf(report, target, settings)
        except Exception:  # noqa: BLE001 - a PDF failure must not lose the scan
            # The scan is evidence; the PDF is a convenience rendering of it.
            # Losing the JSON and HTML because ReportLab misbehaved would be
            # the wrong trade, so the failure is recorded in the report and
            # the format is simply not offered.
            written.pop("pdf", None)
            report.setdefault("report_warnings", []).append(
                "PDF rendering failed and was omitted; the JSON and HTML "
                "exports are complete."
            )

    return written
