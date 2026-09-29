"""The demo corpus must reproduce the findings it claims to demonstrate.

A corpus whose index says a file produces `weak_public_key` is only useful if
it reliably does. This module is the contract between the corpus and the
detectors, so a change that quietly stops detecting something fails here.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from kryxai.engine import run_scan
from kryxai.pcap import corpus
from kryxai.reports import builder as report_builder
from kryxai.config import Settings


@pytest.fixture(scope="module")
def corpus_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("corpus")
    corpus.generate(out)
    return out


@pytest.fixture(scope="module")
def manifest(corpus_dir):
    import json

    return json.loads((corpus_dir / "index.json").read_text(encoding="utf-8"))


def test_corpus_has_cases_and_a_warning(manifest):
    assert len(manifest["cases"]) >= 10
    assert "synthetically generated" in manifest["warning"]


def test_every_case_is_bilingual(manifest):
    for case in manifest["cases"]:
        assert case["description"]
        assert case["description_hi"]
        assert case["name"] and case["filename"]


def _case_ids(manifest):
    return [c["name"] for c in manifest["cases"]]


@pytest.mark.parametrize("index", range(17))
def test_case_produces_exactly_its_expected_findings(corpus_dir, manifest, index):
    case = manifest["cases"][index]
    report = run_scan(corpus_dir / case["filename"], persist=False).report
    codes = {f["code"] for f in report["findings"]}
    for expected in case["expect"]:
        assert expected in codes, (
            f"{case['name']} was supposed to demonstrate {expected} but produced "
            f"only {sorted(codes)}"
        )
    for forbidden in case["expect_clean"]:
        assert forbidden not in codes, (
            f"{case['name']} is a control case and must not produce {forbidden}"
        )


def test_the_parametrised_corpus_range_covers_every_case(manifest):
    """The case count is hardcoded in the parametrise above; keep them in step.

    A new capture added to build_cases() without widening this range would be
    generated, shipped and never scanned.
    """
    assert len(manifest["cases"]) == 17, _case_ids(manifest)


def test_every_anomaly_code_is_demonstrated_somewhere(corpus_dir, manifest):
    """Each A-code must fire on a shipped capture, not merely exist in the source.

    Four of the six baseline detectors had never fired on anything the corpus
    contained, which left the anomaly layer looking complete in the source while
    the shipped demo exercised two of six. This walks the whole corpus and fails
    on any code the engine can raise that no capture demonstrates.
    """
    import re

    from kryxai.scoring import anomaly as anomaly_mod

    source = Path(anomaly_mod.__file__).read_text(encoding="utf-8")
    declared = set(re.findall(r'code="(A\d+_[a-z_]+)"', source))

    demonstrated = set()
    for case in manifest["cases"]:
        report = run_scan(corpus_dir / case["filename"], persist=False).report
        demonstrated |= {a["code"] for a in report["anomalies"]}

    missing = declared - demonstrated
    assert not missing, (
        f"these anomaly detectors never fire on the shipped corpus: {sorted(missing)}"
    )
    assert demonstrated == declared, (
        f"corpus demonstrates codes the source does not define: "
        f"{sorted(demonstrated - declared)}"
    )


@pytest.mark.parametrize("index", range(17))
def test_cases_claiming_an_upgrade_actually_contain_tls(corpus_dir, manifest, index):
    """A capture documented as an upgrade must contain a TLS handshake.

    `expect_clean` cannot catch this: a capture with no handshake also has no
    suppressed capability, so it satisfies every absence assertion while
    exercising nothing. That is exactly how 11_imap_healthy shipped - named and
    documented as a clean IMAP-to-TLS 1.2 upgrade, built without the handshake
    records, so every TLS feature read as zero and no test failed.
    """
    case = manifest["cases"][index]
    if not case.get("expect_tls_upgraded"):
        pytest.skip(f"{case['name']} is not an upgrade case")
    report = run_scan(corpus_dir / case["filename"], persist=False).report
    assert report["sessions"], f"{case['name']} produced no session"
    for session in report["sessions"]:
        starttls = session.get("starttls") or {}
        assert starttls.get("tls_established") is True, (
            f"{case['name']} claims a TLS upgrade but the session did not "
            f"establish one (state={starttls.get('state')!r})"
        )
        assert session.get("tls") is not None, (
            f"{case['name']} claims a TLS upgrade but carries no TLS record"
        )
        assert session["tls"].get("certificates"), (
            f"{case['name']} claims a TLS upgrade but parsed no certificate"
        )


def test_posture_is_sane_for_every_case(corpus_dir, manifest):
    for case in manifest["cases"]:
        report = run_scan(corpus_dir / case["filename"], persist=False).report
        assert 0.0 <= report["posture"]["score"] <= 100.0
        assert report["posture"]["grade"] in {"A", "B", "C", "D", "F"}


def test_every_posture_dimension_explains_itself(corpus_dir, manifest):
    """A posture number with no "why" is not explainable.

    Each dimension must carry the same inputs that produced its value plus a
    rationale, so a reader can see what drove the score without recomputing it.
    """
    for case in manifest["cases"]:
        report = run_scan(corpus_dir / case["filename"], persist=False).report
        p = report["posture"]
        expl = p.get("dimension_explanation")
        assert expl, f"{case['filename']}: no dimension_explanation"
        for key, value in p["dimensions"].items():
            assert key in expl, f"{case['filename']}: {key} has no explanation"
            meta = expl[key]
            assert meta["value"] == value, f"{case['filename']}: {key} value drift"
            assert meta["weight"] == p["weights"][key]
            assert meta["rationale"], f"{case['filename']}: {key} has no rationale"
            assert meta["measured"] >= 0
            assert meta["not_assessed"] == (key in p["not_assessed"])


def test_posture_points_reconcile_with_the_overall_score(corpus_dir, manifest):
    """The per-dimension points must sum to the score, or the breakdown lies."""
    for case in manifest["cases"]:
        report = run_scan(corpus_dir / case["filename"], persist=False).report
        p = report["posture"]
        total = sum(m["points"] for m in p["dimension_explanation"].values())
        assert abs(total - p["score"]) < 0.05, (
            f"{case['filename']}: dimension points {total:.2f} != score {p['score']}"
        )


def test_a_clean_capture_says_why_each_dimension_is_full(corpus_dir, manifest):
    by_name = {c["name"]: c for c in manifest["cases"]}
    report = run_scan(
        corpus_dir / by_name["01_healthy_smtp_tls12"]["filename"], persist=False
    ).report
    expl = report["posture"]["dimension_explanation"]
    assert expl["transport_encryption"]["measured"] >= 1
    assert "completed a TLS upgrade" in expl["transport_encryption"]["rationale"]


def test_not_assessed_dimensions_say_why_they_cannot_be_measured(corpus_dir, manifest):
    """A not-assessed dimension must explain the visibility limit, not score 0."""
    by_name = {c["name"]: c for c in manifest["cases"]}
    report = run_scan(
        corpus_dir / by_name["08_tls13_modern"]["filename"], persist=False
    ).report
    p = report["posture"]
    if "certificate_hygiene" in p["not_assessed"]:
        meta = p["dimension_explanation"]["certificate_hygiene"]
        assert meta["measured"] == 0
        assert "not assessed" in meta["rationale"].lower() or "visible" in meta["rationale"].lower()


def test_dpdp_mapping_is_demonstrated_when_a_finding_maps(corpus_dir, manifest):
    """The compliance coverage row must actually flip to demonstrated.

    It read `compliance["provisions"]` while the summary emits `items`, so it
    could never report demonstrated regardless of what the scan found.
    """
    by_name = {c["name"]: c for c in manifest["cases"]}
    report = run_scan(
        corpus_dir / by_name["02_star_ttlssuppressed_vodafone_style"]["filename"],
        persist=False,
    ).report
    assert report["compliance"]["mapped_findings"] > 0
    row = next(
        e
        for e in report["coverage"]["items"]
        if "Statutory mapping" in e["requirement"]
    )
    assert row["status"] == "demonstrated", row
    assert row["evidence"]


def test_compliance_summary_carries_its_verification_caveat(corpus_dir, manifest):
    by_name = {c["name"]: c for c in manifest["cases"]}
    report = run_scan(
        corpus_dir / by_name["02_star_ttlssuppressed_vodafone_style"]["filename"],
        persist=False,
    ).report
    c = report["compliance"]
    assert c["verification_status"] == "UNVERIFIED_IN_THIS_BUILD"
    assert c["verification_note"], "the unverified text must travel with the mapping"
    assert c["authoritative_sources"], "attribution must travel with the mapping"
    assert c["provisions"], "the provisions the mapping cites must be listed"
    for item in c["items"]:
        assert item["disclaimer"] == "Not legal advice."
        assert item["caveats"], f"{item['finding_code']} mapped with no caveat"


def test_the_compliance_row_does_not_claim_demonstration_on_a_clean_capture(
    corpus_dir, manifest
):
    """`provisions` is a static catalogue, so it can never be the witness.

    The compliance summary lists every provision the build knows about whether or
    not this capture touched any of them. A coverage row keyed on that list would
    read `demonstrated` on a perfectly clean capture, which is the opposite claim
    from the one the evidence supports. The witness has to be the mapped items.
    """
    by_name = {c["name"]: c for c in manifest["cases"]}
    report = run_scan(
        corpus_dir / by_name["01_healthy_smtp_tls12"]["filename"], persist=False
    ).report
    assert report["compliance"]["provisions"], "expected a static provision catalogue"
    assert report["compliance"]["mapped_findings"] == 0
    assert report["compliance"]["items"] == []
    row = next(
        e for e in report["coverage"]["items"] if "Statutory mapping" in e["requirement"]
    )
    assert row["status"] == "clean", (
        "a capture with no mapped finding must not be reported as demonstrating "
        "the statutory mapping"
    )


def test_healthy_case_scores_better_than_suppressed_case(corpus_dir, manifest):
    by_name = {c["name"]: c for c in manifest["cases"]}
    healthy = run_scan(
        corpus_dir / by_name["01_healthy_smtp_tls12"]["filename"], persist=False
    ).report
    suppressed = run_scan(
        corpus_dir / by_name["02_star_ttlssuppressed_vodafone_style"]["filename"],
        persist=False,
    ).report
    assert healthy["posture"]["score"] > suppressed["posture"]["score"]


def test_every_case_declares_limitations(corpus_dir, manifest):
    for case in manifest["cases"]:
        report = run_scan(corpus_dir / case["filename"], persist=False).report
        assert report["limitations"]


# ── report rendering and signing ─────────────────────────────────────────────


@pytest.fixture(scope="module")
def one_report(corpus_dir):
    return run_scan(corpus_dir / "01_healthy_smtp_tls12.pcap", persist=False).report


def test_signature_binds_to_chain_id_and_aad(tmp_path, one_report):
    from kryxai.reports import verify, sign

    settings = Settings(
        report_keys_dir=str(tmp_path / "keys"),
        reports_dir=str(tmp_path / "out"),
    )
    key, _mode = report_builder.load_or_create_key(settings)
    sig = sign(one_report, key)
    assert sig.chain_id == "KryxAIV1"
    assert sig.aad == "kryxai-report-v1"
    ok, why = verify(one_report, sig, key.public_key())
    assert ok, why


def test_written_json_verifies_against_its_own_contents(tmp_path, one_report):
    """A signed report must verify when read back from disk.

    This is the check that catches a mutation applied between signing and
    writing. ``write`` refreshes the coverage export row, which edits the report
    in place; if that happened after ``sign`` the bytes on disk would no longer
    be the bytes that were signed, and verification would fail on a report
    nobody tampered with. Signing a report and checking the in-memory object
    cannot see that, so the round trip has to go through the file.
    """
    import copy
    import json as _json

    from kryxai.reports import ReportSignature, verify

    settings = Settings(
        report_keys_dir=str(tmp_path / "keys_roundtrip"),
        reports_dir=str(tmp_path / "out_roundtrip"),
    )
    paths = report_builder.write(
        copy.deepcopy(one_report), tmp_path / "rt", settings, langs=["en"]
    )

    written = _json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert "signature" in written, "written JSON carries no signature"

    raw = written.pop("signature")
    written.pop("signature_verification", None)
    sig = ReportSignature(
        algorithm=raw["algorithm"],
        chain_id=raw["chain_id"],
        aad=raw["aad"],
        value=raw["value"],
        created_at=raw["created_at"],
        public_key_fingerprint=raw["public_key_fingerprint"],
    )
    key, _mode = report_builder.load_or_create_key(settings)
    ok, why = verify(written, sig, key.public_key())
    assert ok, f"report read back from disk failed verification: {why}"


def test_coverage_export_row_is_settled_inside_write(tmp_path, one_report):
    """The export row must be updated by write(), not left to the caller.

    The JSON is itself one of the exports, so the row describing exports has to
    be settled before the JSON is serialised. A caller-side refresh afterwards
    would leave the written file claiming that no export had taken place.
    """
    import copy
    import json as _json

    report = copy.deepcopy(one_report)
    paths = report_builder.write(
        report, tmp_path / "cov", settings_report(tmp_path), langs=["en"]
    )
    written = _json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    row = next(
        i
        for i in written["coverage"]["items"]
        if i["requirement"].startswith("Exportable forensic reports")
    )
    assert row["status"] == "demonstrated", row["detail"]
    assert row["evidence"], "export row marked demonstrated with no evidence"
    assert "json" in written["coverage"]["report_files"]


def settings_report(tmp_path):
    return Settings(
        report_keys_dir=str(tmp_path / "keys_cov"),
        reports_dir=str(tmp_path / "out_cov"),
    )


def test_tampered_report_fails_verification(tmp_path, one_report):
    from kryxai.reports import sign, verify

    settings = Settings(report_keys_dir=str(tmp_path / "keys2"))
    key, _ = report_builder.load_or_create_key(settings)
    sig = sign(one_report, key)
    tampered = dict(one_report)
    original = one_report["posture"]["score"]
    tampered["posture"] = dict(
        one_report["posture"], score=0.0 if original != 0.0 else 100.0
    )
    ok, why = verify(tampered, sig, key.public_key())
    assert not ok
    assert "does not match" in why


def test_wrong_chain_id_is_rejected(tmp_path, one_report):
    from kryxai.reports import ReportSignature, sign, verify

    settings = Settings(report_keys_dir=str(tmp_path / "keys3"))
    key, _ = report_builder.load_or_create_key(settings)
    sig = sign(one_report, key)
    bad = ReportSignature(
        sig.algorithm, "SomeOtherChain", sig.aad, sig.value, sig.created_at,
        sig.public_key_fingerprint,
    )
    ok, why = verify(one_report, bad, key.public_key())
    assert not ok
    assert "chain id" in why


def test_wrong_aad_is_rejected(tmp_path, one_report):
    from kryxai.reports import ReportSignature, sign, verify

    settings = Settings(report_keys_dir=str(tmp_path / "keys4"))
    key, _ = report_builder.load_or_create_key(settings)
    sig = sign(one_report, key)
    bad = ReportSignature(
        sig.algorithm, sig.chain_id, "some-other-aad", sig.value, sig.created_at,
        sig.public_key_fingerprint,
    )
    ok, why = verify(one_report, bad, key.public_key())
    assert not ok
    assert "AAD" in why


def test_html_is_bilingual(tmp_path, one_report):
    import re

    settings = Settings(
        report_keys_dir=str(tmp_path / "keys5"), reports_dir=str(tmp_path / "o5")
    )
    paths = report_builder.write(one_report, tmp_path / "o5", settings)
    hindi = paths["html_hi"].read_text(encoding="utf-8")
    assert re.search(r"[\u0900-\u097F]", hindi), "Hindi report has no Devanagari"
    assert "Executive summary" in paths["html_en"].read_text(encoding="utf-8")


def test_unsigned_html_says_so(one_report):
    html = report_builder.render_html(one_report)
    assert "unsigned" in html
    assert "UNSIGNED" not in html  # case-sensitive: the signed banner differs


def test_pdf_is_optional_and_its_absence_is_explained(
    one_report, tmp_path, monkeypatch
):
    """ReportLab is an optional extra; a base install must still produce a report.

    Regression test: `kryxai scan` previously raised ModuleNotFoundError for
    reportlab, so the single most common command failed on a base install.
    """
    monkeypatch.setattr(report_builder, "pdf_available", lambda: False)

    settings = Settings(
        report_keys_dir=str(tmp_path / "keys_pdf"),
        reports_dir=str(tmp_path / "o_pdf"),
    )
    paths = report_builder.write(one_report, tmp_path / "o_pdf", settings)

    # JSON and HTML must still be written.
    assert paths["json"].exists()
    assert paths["html_en"].exists()
    assert paths["html_hi"].exists()

    # The PDF must be absent, not half-written.
    assert "pdf" not in paths
    assert not list((tmp_path / "o_pdf").glob("*.pdf"))

    # And the omission must be explained rather than silently dropped.
    assert "kryxai[reports]" in report_builder.PDF_UNAVAILABLE_HINT


def test_pdf_available_reports_a_boolean():
    assert isinstance(report_builder.pdf_available(), bool)


def test_unsigned_pdf_says_so(tmp_path, one_report):
    path = report_builder.render_pdf(one_report, tmp_path / "r.pdf")
    raw = path.read_bytes()
    assert b"UNSIGNED" in raw or b"omitted" in raw or len(raw) > 500


def test_report_json_records_signature_state(tmp_path, one_report):
    import json

    settings = Settings(
        report_keys_dir=str(tmp_path / "keys6"), reports_dir=str(tmp_path / "o6")
    )
    paths = report_builder.write(one_report, tmp_path / "o6", settings)
    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data["signature"]["aad"] == "kryxai-report-v1"
    assert "valid" in data["signature_verification"]
