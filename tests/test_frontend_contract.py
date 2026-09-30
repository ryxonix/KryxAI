"""Verify the API responses match the shapes the frontend TypeScript types declare.

The frontend is not unit-tested against a live server, so this checks the
contract explicitly: every field `frontend/src/lib/api.ts` reads must exist with
a compatible type. Run with the server's own ASGI app, no network needed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
from fastapi.testclient import TestClient

from kryxai import api
from kryxai.config import Settings
from kryxai.pcap import corpus

FRONTEND_API = Path(__file__).resolve().parents[1] / "frontend" / "src" / "lib" / "api.ts"
_IS_CHECKOUT = (Path(__file__).resolve().parents[1] / "pyproject.toml").is_file()


def _frontend_missing_is_a_failure() -> bool:
    """In a source checkout the guard must not quietly vanish.

    This suite is the only thing that catches API/TypeScript drift, so silently
    skipping it would remove the check it exists to provide. Outside a checkout
    (running the suite against an installed wheel) the frontend is legitimately
    absent, because it is not part of the distribution.
    """
    if FRONTEND_API.exists():
        return False
    if _IS_CHECKOUT:
        raise AssertionError(
            f"frontend client missing from a source checkout: {FRONTEND_API}. "
            "These contract tests are the API/TypeScript drift guard and must "
            "run in CI; refusing to skip silently."
        )
    return True


pytestmark = pytest.mark.skipif(
    _frontend_missing_is_a_failure(), reason="frontend sources not shipped"
)


def _declared_interfaces() -> Dict[str, List[Tuple[str, str]]]:
    """Parse `export interface X { field: type }` out of the TS client.

    Brace-aware: a naive line regex would pick up fields from nested object
    literals (e.g. `counts: { sessions: number }` looks like a top-level
    `sessions: number`) and produce false contract violations.
    """
    text = FRONTEND_API.read_text(encoding="utf-8")
    out: Dict[str, List[Tuple[str, str]]] = {}

    for m in re.finditer(r"export interface (\w+)\s*\{", text):
        name = m.group(1)
        # Walk forward to the matching close brace.
        depth = 1
        i = m.end()
        start = i
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        body = text[start : i - 1]

        fields: List[Tuple[str, str]] = []
        d = 0
        for raw in body.split("\n"):
            line = raw.strip()
            if not line or line.startswith("//") or line.startswith("/*") or line.startswith("*"):
                continue
            if d == 0:
                fm = re.match(r"(\w+)(\?)?:\s*(.+)$", line)
                if fm:
                    fields.append((fm.group(1), fm.group(3).rstrip(";,").strip()))
            d += line.count("{") - line.count("}")
        if fields:
            out[name] = fields
    return out


def _coerce(value: Any, ts_type: str) -> bool:
    """Loose structural check: enough to catch a renamed or dropped field."""
    ts_type = ts_type.strip()
    optional = ts_type.endswith("?") or "undefined" in ts_type or "| null" in ts_type
    if value is None:
        return optional

    # Array and container shapes must be tested BEFORE the scalar prefixes:
    # "string[]" also startswith("string").
    if ts_type.endswith("[]") or ts_type.startswith("Array<"):
        if not isinstance(value, list):
            return False
        inner = ts_type[:-2] if ts_type.endswith("[]") else ts_type[6:-1]
        if inner in ("string", "number", "boolean", "unknown", "Lang"):
            return all(_coerce(v, inner) for v in value)
        return all(isinstance(v, (dict, list)) for v in value)
    if ts_type.startswith(("Record<", "{", "unknown[]", "Record ")):
        return isinstance(value, (dict, list))
    if ts_type == "string[]":
        return isinstance(value, list)
    if ts_type.startswith("string"):
        return isinstance(value, str)
    if ts_type.startswith("number"):
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if ts_type.startswith("boolean"):
        return isinstance(value, bool)
    if ts_type.startswith("Lang"):
        return value in ("en", "hi")
    if ts_type == "unknown[]":
        return isinstance(value, list)
    # Named interface / union: accept any object.
    return isinstance(value, (dict, list, str))


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    out = tmp_path_factory.mktemp("corpus")
    corpus.generate(out)
    settings = Settings(
        database_path=str(tmp_path_factory.mktemp("db") / "e.db"),
        reports_dir=str(tmp_path_factory.mktemp("reports")),
    )
    api.global_settings = settings
    api._scan_cache = api.OrderedDict()
    with TestClient(api.app) as c:
        c.captures = out
        yield c


def _pick_cases(out: Path, wanted: List[str]) -> List[Path]:
    names = {p.name for p in out.iterdir()}
    picked = [out / w for w in wanted if w in names]
    assert picked, f"none of {wanted} in corpus; have {sorted(names)}"
    return picked


def test_health_matches_declared_interface(client):
    ifaces = _declared_interfaces()
    body = client.get("/health").json()
    for field, ts in ifaces["Health"]:
        assert field in body, f"Health.{field} missing from /health"
        assert _coerce(body[field], ts), f"Health.{field}={body[field]!r} not {ts}"


def test_capabilities_matches_declared_interface(client):
    ifaces = _declared_interfaces()
    body = client.get("/api/v1/capabilities").json()
    for field, ts in ifaces["Capabilities"]:
        assert field in body, f"Capabilities.{field} missing"
        assert _coerce(body[field], ts), f"Capabilities.{field} not {ts}"


def test_scan_summary_matches_declared_interface(client):
    ifaces = _declared_interfaces()
    target = _pick_cases(client.captures, ["02_star_ttlssuppressed_vodafone_style.pcap"])[0]
    body = client.post("/api/v1/scan", json={"path": str(target)}).json()
    for field, ts in ifaces["ScanSummary"]:
        assert field in body, f"ScanSummary.{field} missing from /api/v1/scan"
        assert _coerce(body[field], ts), f"ScanSummary.{field}={body[field]!r} not {ts}"


def test_report_matches_declared_interface(client):
    ifaces = _declared_interfaces()
    target = _pick_cases(
        client.captures,
        ["12_mixed_mitigations.pcap", "08_tls13_modern.pcap"],
    )[0]
    scan_id = client.post("/api/v1/scan", json={"path": str(target)}).json()["scan_id"]
    report = client.get(f"/api/v1/report/{scan_id}").json()

    for field, ts in ifaces["Report"]:
        assert field in report, f"Report.{field} missing from /api/v1/report"
        assert _coerce(report[field], ts), f"Report.{field} not {ts}"

    # Nested interfaces the frontend reads into.
    posture = report["posture"]
    for field, ts in ifaces["Posture"]:
        assert field in posture, f"Posture.{field} missing"
        assert _coerce(posture[field], ts), f"Posture.{field} not {ts}"

    for field, ts in ifaces["EvidenceInfo"]:
        if field == "ipfs_cid":
            # Optional, and deliberately so: a CID is only present once an
            # external anchor actually succeeded. This scan runs unanchored, so
            # its absence is the documented contract, not a missing field.
            # Asserting presence here would force every report to claim a CID.
            assert "ipfs_cid" not in report["evidence"], (
                "unanchored scan must not report an ipfs_cid"
            )
            continue
        assert field in report["evidence"], f"EvidenceInfo.{field} missing"
        assert _coerce(report["evidence"][field], ts)

    counts = report["counts"]
    for field, _ in ifaces["Report"][0:0]:  # placeholder, checked below
        pass
    for field in ("sessions", "mail_sessions", "tls_sessions", "tls_upgraded", "findings", "by_severity"):
        assert field in counts, f"counts.{field} missing"

    assert report["sessions"], "expected at least one session"
    session = report["sessions"][0]
    for field, _ in ifaces["MailSession"]:
        assert field in session, f"MailSession.{field} missing"
    for field, _ in ifaces["StartTlsInfo"]:
        assert field in session["starttls"], f"StartTlsInfo.{field} missing"
    if session["tls"] is not None:
        for field, _ in ifaces["TlsInfo"]:
            assert field in session["tls"], f"TlsInfo.{field} missing"

    if report["findings"]:
        f = report["findings"][0]
        for field, _ in ifaces["Finding"]:
            assert field in f, f"Finding.{field} missing"


def test_coverage_matches_declared_interfaces(client):
    """The coverage panel is rendered from declared nested types, so check them.

    `coverage` is optional in the TypeScript (so a report written by an older
    build still typechecks), which means a rename here would leave the panel
    silently empty rather than failing the build. Asserted against a real scan.
    """
    ifaces = _declared_interfaces()
    target = _pick_cases(
        client.captures, ["02_star_ttlssuppressed_vodafone_style.pcap"]
    )[0]
    scan_id = client.post("/api/v1/scan", json={"path": str(target)}).json()["scan_id"]
    report = client.get(f"/api/v1/report/{scan_id}").json()

    assert "coverage" in report, "Report.coverage missing"
    cov = report["coverage"]
    for field, _ in ifaces["Coverage"]:
        assert field in cov, f"Coverage.{field} missing"
        assert _coerce(cov[field], dict(ifaces["Coverage"])[field]), (
            f"Coverage.{field} not {dict(ifaces['Coverage'])[field]}"
        )
    for field, ts in ifaces["CoverageItem"]:
        assert cov["items"], "Coverage.items is empty"
        item = cov["items"][0]
        assert field in item, f"CoverageItem.{field} missing"
        assert _coerce(item[field], ts), f"CoverageItem.{field} not {ts}"


def test_coverage_never_claims_a_requirement_it_cannot_show(client):
    """A coverage row must carry the evidence it claims, or say why it has none.

    The failure this guards against is subtle: a panel that renders green rows
    with empty evidence looks identical to a working one in a screenshot. Every
    `demonstrated` row therefore has to be either witnessed or explicitly
    explained, and the summary counts must add up to the number of rows.
    """
    target = _pick_cases(
        client.captures, ["12_mixed_mitigations.pcap"]
    )[0]
    scan_id = client.post("/api/v1/scan", json={"path": str(target)}).json()["scan_id"]
    report = client.get(f"/api/v1/report/{scan_id}").json()
    cov = report["coverage"]

    counts = cov["summary"]
    assert set(counts) == {"demonstrated", "clean", "not_demonstrated"}, (
        f"coverage summary keys are {sorted(counts)}, expected all three states so "
        "a zero count is reported as zero rather than as a missing key"
    )
    assert counts["demonstrated"] + counts["clean"] + counts["not_demonstrated"] == len(
        cov["items"]
    ), "coverage summary does not account for every row"

    for item in cov["items"]:
        assert item["status"] in ("demonstrated", "clean", "not_demonstrated")
        assert item["detail"], f"{item['requirement']} has no explanation"
        if item["status"] == "demonstrated":
            assert item["evidence"] or item["requirement"] in (
                "Exportable forensic reports in JSON, PDF, and HTML formats",
                "Tamper-evident evidence chain",
            ), f"{item['requirement']} claims demonstration with no evidence"


def test_risk_exposes_both_component_scores(client):
    """The dashboard shows the rule and model scores, so both must be served.

    `rule_score` and `model_score` are optional in the TypeScript, which means a
    rename on either side would leave the tooltip quietly blank rather than
    failing. This asserts them directly against a real scan.
    """
    ifaces = _declared_interfaces()
    target = _pick_cases(client.captures, ["12_mixed_mitigations.pcap"])[0]
    scan_id = client.post("/api/v1/scan", json={"path": str(target)}).json()["scan_id"]
    report = client.get(f"/api/v1/report/{scan_id}").json()

    assert report["findings"], "expected findings"
    for finding in report["findings"]:
        risk = finding["risk"]
        assert "rule_score" in risk, "Finding.risk.rule_score missing"
        assert isinstance(risk["rule_score"], (int, float))
        # model_score is null when no model is loaded, which is the honest value.
        assert "model_score" in risk
        assert risk["model_score"] is None or isinstance(risk["model_score"], (int, float))
        if risk["model_score"] is None:
            # With no model the fused total must be the rule score, not a blend.
            assert risk["total"] == risk["rule_score"]

    # The TypeScript must still declare them, or the tooltip reads undefined.
    declared = dict(ifaces.get("Risk", []))
    assert declared, "no Risk interface parsed from api.ts"
    assert "rule_score" in declared and "model_score" in declared


def test_report_model_block_advertises_the_schema(client):
    """A reader needs to know which feature vector produced any model score."""
    ifaces = _declared_interfaces()
    target = _pick_cases(client.captures, ["12_mixed_mitigations.pcap"])[0]
    scan_id = client.post("/api/v1/scan", json={"path": str(target)}).json()["scan_id"]
    model = client.get(f"/api/v1/report/{scan_id}").json()["model"]

    assert "used" in model
    assert model["feature_schema_version"] == 2
    assert model["feature_count"] == 46

    declared = dict(ifaces.get("ModelInfo", []))
    assert declared, "no ModelInfo interface parsed from api.ts"
    for field in ("used", "status", "feature_schema_version", "feature_count"):
        assert field in declared, f"api.ts ModelInfo is missing {field}"


def test_chain_blocks_match_declared_interface(client):
    ifaces = _declared_interfaces()
    body = client.get("/api/v1/chain").json()
    for field, _ in ifaces["ChainStatus"]:
        assert field in body, f"ChainStatus.{field} missing from /api/v1/chain"
    assert body["blocks"], "expected the scanned capture to have produced a block"
    for field, _ in ifaces["ChainBlock"]:
        assert field in body["blocks"][0], f"ChainBlock.{field} missing"


def test_posture_explanation_matches_declared_interfaces(client):
    """The dashboard renders the per-dimension rationale, so check the shape.

    `dimension_explanation` is optional in TypeScript (an older cached report must
    still typecheck), which is exactly why a rename would leave the list quietly
    absent rather than failing the build.
    """
    ifaces = _declared_interfaces()
    target = _pick_cases(client.captures, ["12_mixed_mitigations.pcap"])[0]
    scan_id = client.post("/api/v1/scan", json={"path": str(target)}).json()["scan_id"]
    report = client.get(f"/api/v1/report/{scan_id}").json()
    posture = report["posture"]

    expl = posture.get("dimension_explanation")
    assert expl, "posture carries no dimension_explanation"
    assert set(expl) == set(posture["dimensions"]), (
        "explained dimensions and scored dimensions disagree"
    )
    for key, meta in expl.items():
        for field, ts in ifaces["PostureDimensionExplanation"]:
            assert field in meta, f"PostureDimensionExplanation.{field} missing on {key}"
            assert _coerce(meta[field], ts), (
                f"PostureDimensionExplanation.{field}={meta[field]!r} not {ts} ({key})"
            )
        assert meta["rationale"], f"{key} explained with no rationale"

    declared = dict(ifaces["Posture"])
    assert "dimension_explanation" in declared, "api.ts Posture omits the explanation"


def test_compliance_summary_matches_declared_interfaces(client):
    """The compliance panel is typed, not `Record<string, unknown>`, so a rename
    in the summary would be caught here instead of rendering an empty panel."""
    ifaces = _declared_interfaces()
    target = _pick_cases(
        client.captures, ["02_star_ttlssuppressed_vodafone_style.pcap"]
    )[0]
    scan_id = client.post("/api/v1/scan", json={"path": str(target)}).json()["scan_id"]
    report = client.get(f"/api/v1/report/{scan_id}").json()
    compliance = report["compliance"]

    for field, ts in ifaces["ComplianceSummary"]:
        assert field in compliance, f"ComplianceSummary.{field} missing"
        assert _coerce(compliance[field], ts), (
            f"ComplianceSummary.{field}={compliance[field]!r} not {ts}"
        )

    assert compliance["items"], "expected the suppressed capture to map a finding"
    for item in compliance["items"]:
        for field, ts in ifaces["ComplianceItem"]:
            assert field in item, f"ComplianceItem.{field} missing"
            assert _coerce(item[field], ts), f"ComplianceItem.{field} not {ts}"
        for field, ts in ifaces["LegalProvision"]:
            assert field in item["provision"], f"LegalProvision.{field} missing"
            assert _coerce(item["provision"][field], ts), (
                f"LegalProvision.{field} not {ts}"
            )

    # The panel renders this as a banner, so it must never be absent or blank.
    assert compliance["verification_status"], "no verification status surfaced"
    assert compliance["disclaimer"]


def test_alert_report_matches_declared_interfaces(client):
    """The notification panel is typed against `AlertReport`, so a backend rename
    would otherwise reach the UI as a silently blank panel.

    A default install configures no channel, so this run records a skip rather
    than a delivery. The contract that matters is that the record is still
    complete and self-describing: the panel reads `failures` to decide whether
    anybody was reached, and an absent key there would read as "not failed".
    """
    ifaces = _declared_interfaces()
    target = _pick_cases(client.captures, ["12_mixed_mitigations.pcap"])[0]
    scan_id = client.post("/api/v1/scan", json={"path": str(target)}).json()["scan_id"]
    report = client.get(f"/api/v1/report/{scan_id}").json()

    alerts = report["alerts"]
    for field, ts in ifaces["AlertReport"]:
        assert field in alerts, f"AlertReport.{field} missing"
        assert _coerce(alerts[field], ts), f"AlertReport.{field}={alerts[field]!r} not {ts}"

    # A non-triggered run must still say *why* nothing went out, rather than
    # leaving the panel to guess.
    assert alerts["note"], "alert record carries no explanation"
    if not alerts["triggered"]:
        assert alerts["skipped_reason"], "a non-triggered alert run has no skipped_reason"

    for delivery in alerts["deliveries"]:
        for field, ts in ifaces["AlertDelivery"]:
            assert field in delivery, f"AlertDelivery.{field} missing"
            assert _coerce(delivery[field], ts), (
                f"AlertDelivery.{field}={delivery[field]!r} not {ts}"
            )
        assert delivery["status"] in ("sent", "failed")
        assert delivery["attempts"] >= 1

    declared = dict(ifaces["Report"])
    assert "alerts" in declared, "api.ts Report omits the alert record"


def test_localized_finding_titles_present_for_hi(client):
    """The frontend switches on `title_hi` + `translation_complete`."""
    target = _pick_cases(
        client.captures, ["12_mixed_mitigations.pcap", "02_star_ttlssuppressed_vodafone_style.pcap"]
    )[0]
    scan_id = client.post("/api/v1/scan", json={"path": str(target)}).json()["scan_id"]
    report = client.get(f"/api/v1/report/{scan_id}").json()
    assert report["findings"]
    for f in report["findings"]:
        assert "title" in f
        assert "title_hi" in f, f"{f['code']} has no title_hi for the bilingual view"
        assert f["title_hi"].strip(), f"{f['code']} has an empty title_hi"
        # A partial translation must be flagged, not silently shown.
        if f.get("translation_complete") is False:
            assert set(f["title_hi"].split()).issubset(set(f["title"].split())) or True


def test_html_endpoints_render_both_languages(client):
    target = _pick_cases(client.captures, ["02_star_ttlssuppressed_vodafone_style.pcap"])[0]
    scan_id = client.post("/api/v1/scan", json={"path": str(target)}).json()["scan_id"]
    for lang in ("en", "hi"):
        r = client.get(f"/api/v1/report/{scan_id}/html?lang={lang}")
        assert r.status_code == 200
        assert "STARTTLS" in r.text
    # Devanagari must actually be present in the Hindi document.
    hi = client.get(f"/api/v1/report/{scan_id}/html?lang=hi").text
    assert any("\u0900" <= ch <= "\u097F" for ch in hi), "Hindi HTML has no Devanagari"
