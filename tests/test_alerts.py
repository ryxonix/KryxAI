"""Alerting.

The three properties that matter are tested here, because each is a property
that is easy to *claim* and hard to notice losing:

  - a broken channel must not fail the scan;
  - a broken channel must be recorded, not swallowed;
  - a secret must never reach a log, a report, or an exception string.
"""

import logging

import pytest

from kryxai import alerts
from kryxai.config import Settings


def _report(findings, **over):
    report = {
        "version": "0.1.0",
        "posture": {"grade": "D", "score": 31.0, "label": "poor"},
        "source": {"path": "/tmp/x.pcap", "sha256": "ab" * 32},
        "counts": {"sessions": 2, "findings": len(findings)},
        "findings": findings,
    }
    report.update(over)
    return report


def _finding(severity, code="starttls_capability_suppressed", endpoint="10.0.0.5:25"):
    return {
        "severity": severity,
        "code": code,
        "endpoint": endpoint,
        "risk": {"priority": "P1"},
    }


# â”€â”€ the default install must be silent â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_no_channels_configured_makes_no_call(monkeypatch):
    """The default install configures nothing, so it must send nothing.

    A default that dialled out would be a real defect: this package is passive
    by design, and alerting is the one exception it is allowed to make.
    """
    monkeypatch.setattr(
        alerts, "_deliver", lambda *a, **k: pytest.fail("delivered with no channel")
    )
    result = alerts.dispatch(_report([_finding("critical")]), Settings())
    assert result.enabled is False
    assert result.deliveries == []
    assert "no alert channel" in result.skipped_reason


def test_alerts_can_be_disabled_even_when_configured(monkeypatch):
    monkeypatch.setattr(
        alerts, "_deliver", lambda *a, **k: pytest.fail("delivered while disabled")
    )
    s = Settings(alerts_enabled=False, ntfy_topic="ops")
    result = alerts.dispatch(_report([_finding("critical")]), s)
    assert result.enabled is False
    assert result.deliveries == []


# â”€â”€ the severity threshold â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_below_threshold_does_not_notify(monkeypatch):
    monkeypatch.setattr(
        alerts, "_deliver", lambda *a, **k: pytest.fail("notified below threshold")
    )
    s = Settings(ntfy_topic="ops")
    result = alerts.dispatch(_report([_finding("medium"), _finding("info")]), s)
    assert result.enabled is True
    assert result.triggered is False
    assert "no finding at or above high" in result.skipped_reason


def test_a_clean_capture_never_pages():
    s = Settings(ntfy_topic="ops")
    result = alerts.dispatch(_report([]), s)
    assert result.triggered is False
    assert result.deliveries == []


def test_threshold_is_honoured_when_raised(monkeypatch):
    sent = []
    monkeypatch.setattr(
        alerts, "_deliver", lambda c, *a, **k: sent.append(c) or alerts.Delivery(
            channel=c, target="t", status="sent", attempts=1
        )
    )
    s = Settings(ntfy_topic="ops", alert_min_severity="medium")
    result = alerts.dispatch(_report([_finding("medium")]), s)
    assert result.triggered is True
    assert sent == ["ntfy"]


def test_unrecognised_threshold_falls_back_to_the_default():
    s = Settings(ntfy_topic="ops", alert_min_severity="nonsense")
    result = alerts.dispatch(_report([_finding("medium")]), s)
    assert result.min_severity == alerts.DEFAULT_MIN_SEVERITY
    assert result.triggered is False


# â”€â”€ a failing channel must not fail the scan, and must be recorded â”€â”€â”€â”€â”€â”€â”€â”€


def test_dispatch_never_raises_when_a_channel_explodes(monkeypatch):
    """The guarantee is that a *channel* failing cannot escape. A broken channel
    is the ordinary case, not an exotic one: an SMTP server that refuses auth is
    a configuration mistake the operator has to be told about, not a crash."""
    monkeypatch.setattr(alerts.time, "sleep", lambda *_: None)

    def boom(_s, _subject, _body, _timeout):
        raise RuntimeError("connection refused")

    monkeypatch.setitem(alerts.CHANNELS, "ntfy", boom)
    s = Settings(ntfy_topic="ops", max_alert_retries=0)
    result = alerts.dispatch(_report([_finding("critical")]), s)
    assert result.triggered is True
    assert result.ok is False
    assert "connection refused" in result.deliveries[0].error


def test_delivery_failure_is_recorded_with_attempts(monkeypatch):
    monkeypatch.setattr(alerts.time, "sleep", lambda *_: None)
    calls = []

    def flaky(_s, _subject, _body, _timeout):
        calls.append(1)
        raise ConnectionError("dns failure")

    monkeypatch.setitem(alerts.CHANNELS, "ntfy", flaky)
    s = Settings(ntfy_topic="ops", max_alert_retries=2)
    result = alerts.dispatch(_report([_finding("critical")]), s)
    d = result.deliveries[0]
    assert d.status == "failed"
    assert d.attempts == 3  # one try plus two retries
    assert "dns failure" in d.error
    assert result.ok is False
    assert [f["channel"] for f in result.to_dict()["failures"]] == ["ntfy"]


def test_a_retry_that_succeeds_reports_sent(monkeypatch):
    monkeypatch.setattr(alerts.time, "sleep", lambda *_: None)
    state = {"n": 0}

    def flaky(_s, _subject, _body, _timeout):
        state["n"] += 1
        if state["n"] < 2:
            raise ConnectionError("transient")
        return "topic ops"

    monkeypatch.setitem(alerts.CHANNELS, "ntfy", flaky)
    s = Settings(ntfy_topic="ops", max_alert_retries=3)
    result = alerts.dispatch(_report([_finding("critical")]), s)
    assert result.ok is True
    assert result.deliveries[0].status == "sent"
    assert result.deliveries[0].attempts == 2


def test_one_bad_channel_does_not_stop_the_others(monkeypatch):
    """A dead webhook must not suppress a working Telegram page."""
    monkeypatch.setattr(alerts.time, "sleep", lambda *_: None)

    def dead(_s, _subject, _body, _timeout):
        raise OSError("unreachable")

    def ok(_s, _subject, _body, _timeout):
        return "bot<redacted>"

    monkeypatch.setitem(alerts.CHANNELS, "webhook", dead)
    monkeypatch.setitem(alerts.CHANNELS, "telegram", ok)
    s = Settings(
        telegram_bot_token="t", telegram_chat_id="c", webhook_url="http://x/y",
        max_alert_retries=0,
    )
    result = alerts.dispatch(_report([_finding("critical")]), s)
    by_channel = {d.channel: d for d in result.deliveries}
    assert by_channel["webhook"].status == "failed"
    assert by_channel["telegram"].status == "sent"
    assert result.ok is False  # still not "everything was delivered"


# â”€â”€ secrets must never leak â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_token_never_appears_in_a_failure_record(monkeypatch):
    """A urllib error can echo the URL, and a Telegram URL carries the token."""
    monkeypatch.setattr(alerts.time, "sleep", lambda *_: None)
    secret = "123456:SUPERSECRETTOKEN"

    def leak(_s, _subject, _body, _timeout):
        raise OSError(f"failed to POST https://api.telegram.org/bot{secret}/sendMessage")

    monkeypatch.setitem(alerts.CHANNELS, "telegram", leak)
    s = Settings(telegram_bot_token=secret, telegram_chat_id="c", max_alert_retries=0)
    result = alerts.dispatch(_report([_finding("critical")]), s)
    blob = str(result.to_dict())
    assert secret not in blob
    assert "<redacted>" in result.deliveries[0].error


def test_password_never_appears_in_a_failure_record(monkeypatch):
    monkeypatch.setattr(alerts.time, "sleep", lambda *_: None)

    def leak(_s, _subject, _body, _timeout):
        raise OSError("535 auth failed for password=hunter2")

    monkeypatch.setitem(alerts.CHANNELS, "email", leak)
    s = Settings(
        smtp_host="h", smtp_user="u", smtp_password="hunter2",
        alert_email_to="a@b.c", max_alert_retries=0,
    )
    result = alerts.dispatch(_report([_finding("critical")]), s)
    assert "hunter2" not in str(result.to_dict())


def test_delivery_target_is_a_redaction_not_the_secret():
    """The recorded target is a description of *where* it went, not a value
    that could be replayed by whoever reads the report."""
    d = alerts.Delivery(channel="telegram", target="bot<redacted>", status="sent", attempts=1)
    assert d.to_dict()["target"] == "bot<redacted>"


# â”€â”€ the message body â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_message_quotes_only_findings_at_or_above_the_threshold():
    subject, body = alerts.build_message(
        _report([_finding("critical"), _finding("medium"), _finding("low")]),
        "high",
    )
    assert "starttls_capability_suppressed" in body
    assert "1 finding(s) at or above high" in subject
    assert "posture D" in body
    assert "/tmp/x.pcap" in body


def test_message_caps_the_finding_list():
    many = [_finding("high", code=f"code_{i}") for i in range(alerts.MAX_LISTED_FINDINGS + 4)]
    _subject, body = alerts.build_message(_report(many), "high")
    assert "and 4 more" in body
    assert body.count("code_") == alerts.MAX_LISTED_FINDINGS


def test_message_says_none_when_nothing_matches():
    _subject, body = alerts.build_message(_report([_finding("low")]), "high")
    assert "(none)" in body


# â”€â”€ integration with the engine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_scan_records_the_alert_section(tmp_path, corpus_path):
    """A scan must carry the outcome, so an unnotified scan is never mistaken
    for a notified one."""
    from kryxai.engine import run_scan

    result = run_scan(corpus_path, Settings(), persist=False)
    alerts_block = result.report["alerts"]
    assert set(alerts_block) >= {
        "enabled", "min_severity", "triggered", "deliveries", "failures",
    }
    assert alerts_block["enabled"] is False  # nothing configured in the test env
    assert alerts_block["failures"] == []


def test_scan_survives_an_alert_dispatch_that_raises(tmp_path, corpus_path, monkeypatch):
    """The scan is evidence. It must survive an alerting bug."""
    from kryxai.engine import run_scan

    def boom(*_a, **_k):
        raise RuntimeError("alerts module is broken")

    monkeypatch.setattr(alerts, "dispatch", boom)
    result = run_scan(corpus_path, Settings(), persist=False)
    assert result.report["alerts"]["triggered"] is False
    assert "RuntimeError" in result.report["alerts"]["skipped_reason"]


def test_alert_section_never_reaches_the_evidence_chain(tmp_path, corpus_path):
    """Delivery status varies run to run, so it must not be committed to the
    chain: two scans of the same capture must anchor to the same content."""
    from kryxai.engine import _chain_payload, run_scan

    result = run_scan(corpus_path, Settings(), persist=False)
    assert "alerts" not in _chain_payload(result.report)


def test_active_channels_track_configuration():
    """/health and `kryxai capabilities` both publish this list, so it has to
    describe what will actually be used."""
    assert Settings().active_alert_channels() == []
    assert Settings(ntfy_topic="ops").active_alert_channels() == ["ntfy"]
    # Half-configured is not configured: a token without a chat id sends nothing.
    assert Settings(telegram_bot_token="t").active_alert_channels() == []

