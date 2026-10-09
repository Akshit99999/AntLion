"""
Tests for alert deduplication and suppression.

A public honeypot under credential-stuffing load must emit one alert per
window, not thousands.
"""

import pytest

from antlion.alerts.dedup import AlertDeduplicator, DedupStats
from antlion.alerts.dispatcher import AlertDispatcher
from antlion.core.types import AttackCategory, SeverityLevel, Verdict


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def make_verdict(
    ip="1.2.3.4",
    attack=AttackCategory.CREDENTIAL_BRUTE_FORCE,
    severity=SeverityLevel.HIGH,
    confidence=0.8,
):
    return Verdict(
        source_ip=ip,
        target_service="SSH",
        attack_type=attack,
        severity=severity,
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Deduplicator core behaviour
# ---------------------------------------------------------------------------


def test_first_alert_is_emitted():
    dedup = AlertDeduplicator(window_seconds=60)
    should_emit, count = dedup.check(make_verdict())
    assert should_emit is True
    assert count == 1


def test_repeats_within_window_are_suppressed():
    clock = FakeClock()
    dedup = AlertDeduplicator(window_seconds=60, time_source=clock)

    dedup.check(make_verdict())
    for _ in range(20):
        should_emit, count = dedup.check(make_verdict())
        assert should_emit is False
        assert count > 1

    assert dedup.stats.suppressed == 20
    assert dedup.stats.emitted == 1


def test_summary_emitted_after_window_elapses():
    clock = FakeClock()
    dedup = AlertDeduplicator(window_seconds=60, time_source=clock)

    dedup.check(make_verdict())
    dedup.check(make_verdict())
    dedup.check(make_verdict())
    assert dedup.flush_expired() == []

    clock.advance(61)
    summaries = dedup.flush_expired()

    assert len(summaries) == 1
    summary = summaries[0]
    assert summary.source_ip == "1.2.3.4"
    assert summary.raw_evidence["suppressed_count"] == 3
    assert summary.raw_evidence["summary_alert"] is True


def test_different_ips_are_independent():
    clock = FakeClock()
    dedup = AlertDeduplicator(window_seconds=60, time_source=clock)

    dedup.check(make_verdict(ip="1.1.1.1"))
    should_emit, _ = dedup.check(make_verdict(ip="2.2.2.2"))
    assert should_emit is True


def test_different_attack_types_are_independent():
    dedup = AlertDeduplicator(window_seconds=60)

    dedup.check(make_verdict(attack=AttackCategory.CREDENTIAL_BRUTE_FORCE))
    should_emit, _ = dedup.check(make_verdict(attack=AttackCategory.WEB_EXPLOIT))
    assert should_emit is True


def test_summary_tracks_peak_severity():
    clock = FakeClock()
    dedup = AlertDeduplicator(window_seconds=60, time_source=clock)

    dedup.check(make_verdict(severity=SeverityLevel.HIGH, confidence=0.7))
    dedup.check(make_verdict(severity=SeverityLevel.CRITICAL, confidence=0.95))
    dedup.check(make_verdict(severity=SeverityLevel.MEDIUM, confidence=0.5))

    clock.advance(61)
    summary = dedup.flush_expired()[0]

    assert summary.severity == SeverityLevel.CRITICAL
    assert summary.confidence == pytest.approx(0.95)


def test_summary_preserves_contributing_signals():
    from antlion.core.types import ContributingSignals

    clock = FakeClock()
    dedup = AlertDeduplicator(window_seconds=60, time_source=clock)

    v = make_verdict()
    v.contributing_signals = ContributingSignals(
        decoy_signal={"service": "SSH"},
        ml_signal=None,
        heuristic_signals=[],
        congruence_factor=0.08,
        depth_multiplier=0.96,
    )

    dedup.check(v)
    dedup.check(make_verdict())
    clock.advance(61)

    summary = dedup.flush_expired()[0]
    assert summary.contributing_signals is not None
    assert summary.contributing_signals.congruence_factor == pytest.approx(0.08)
    assert summary.contributing_signals.decoy_signal["summary_alert"] is True


def test_continuous_traffic_does_not_starve_summaries():
    """A steady stream must still release matured windows."""
    clock = FakeClock()
    dedup = AlertDeduplicator(window_seconds=30, time_source=clock)

    dedup.check(make_verdict())
    released = 0

    for i in range(100):
        clock.advance(1)
        dedup.check(make_verdict())
        released += len(dedup.flush_expired())

    assert released >= 3, "windows should mature even under continuous load"


def test_disabled_deduplicator_always_emits():
    dedup = AlertDeduplicator(window_seconds=60, enabled=False)
    for _ in range(5):
        should_emit, count = dedup.check(make_verdict())
        assert should_emit is True
        assert count == 1


def test_zero_window_always_emits():
    dedup = AlertDeduplicator(window_seconds=0)
    for _ in range(3):
        assert dedup.check(make_verdict())[0] is True


def test_pending_count_tracks_open_windows():
    dedup = AlertDeduplicator(window_seconds=60)
    dedup.check(make_verdict(ip="1.1.1.1"))
    dedup.check(make_verdict(ip="2.2.2.2"))
    assert dedup.pending_count() == 2


def test_stats_suppression_ratio():
    stats = DedupStats(emitted=1, suppressed=9)
    assert stats.total == 10
    assert stats.suppression_ratio == pytest.approx(0.9)
    assert stats.to_dict()["suppressed"] == 9


def test_reset_clears_state():
    dedup = AlertDeduplicator(window_seconds=60)
    dedup.check(make_verdict())
    dedup.reset()
    assert dedup.pending_count() == 0
    assert dedup.stats.total == 0


# ---------------------------------------------------------------------------
# Dispatcher integration
# ---------------------------------------------------------------------------


def test_dispatcher_suppresses_repeat_webhooks(monkeypatch):
    """Only the first alert should hit the network."""
    import antlion.alerts.dispatcher as disp

    sent = []
    monkeypatch.setattr(
        disp.AlertDispatcher, "_send_webhooks", lambda self, v: sent.append(v)
    )

    clock = FakeClock()
    dedup = AlertDeduplicator(window_seconds=60, time_source=clock)
    dispatcher = AlertDispatcher(
        webhook_urls=["https://siem.test/hook"],
        min_severity=SeverityLevel.HIGH,
        deduplicator=dedup,
    )

    import time as _time

    monkeypatch.setattr(_time, "sleep", lambda *_: None)

    for _ in range(25):
        dispatcher.notify(make_verdict())
        # Allow the worker thread to run before inspecting.
        import threading

        for t in threading.enumerate():
            if t is not threading.current_thread():
                t.join(timeout=0.5)

    assert len(sent) == 1
    assert dispatcher.deduplicator.stats.suppressed == 24


def test_dispatcher_respects_severity_threshold():
    import antlion.alerts.dispatcher as disp

    sent = []
    disp.AlertDispatcher._send_webhooks = lambda self, v: sent.append(v)

    dispatcher = AlertDispatcher(
        webhook_urls=["https://siem.test/hook"],
        min_severity=SeverityLevel.HIGH,
        deduplicator=AlertDeduplicator(window_seconds=60),
    )

    dispatcher.notify(make_verdict(severity=SeverityLevel.LOW))
    dispatcher.notify(make_verdict(severity=SeverityLevel.MEDIUM))

    assert sent == []


def test_flush_summaries_delivers_pending():
    import antlion.alerts.dispatcher as disp

    sent = []
    disp.AlertDispatcher._send_webhooks = lambda self, v: sent.append(v)

    clock = FakeClock()
    dispatcher = AlertDispatcher(
        webhook_urls=["https://siem.test/hook"],
        min_severity=SeverityLevel.HIGH,
        deduplicator=AlertDeduplicator(window_seconds=60, time_source=clock),
    )

    dispatcher.notify(make_verdict())
    dispatcher.notify(make_verdict())
    dispatcher.notify(make_verdict())

    clock.advance(61)
    summaries = dispatcher.flush_summaries()

    assert len(summaries) == 1
    assert summaries[0].raw_evidence["suppressed_count"] == 3


def test_cef_message_annotates_summaries():
    dispatcher = AlertDispatcher(deduplicator=AlertDeduplicator(enabled=False))

    single = dispatcher.format_cef(make_verdict())
    assert "Intrusion captured in decoy pit" in single

    summary = make_verdict()
    summary.raw_evidence = {"suppressed_count": 42}
    assert "Suppressed 42" in dispatcher.format_cef(summary)


# ---------------------------------------------------------------------------
# Config wiring
# ---------------------------------------------------------------------------


def test_engine_builds_deduplicator_from_config():
    from antlion.core.config import AntlionConfig
    from antlion.storage.database import AntlionDatabase
    from antlion.verdict.engine import VerdictEngine
    import tempfile
    from pathlib import Path

    cfg = AntlionConfig(data_dir=Path(tempfile.mkdtemp()))
    cfg.alert_dedup_window_sec = 120

    engine = VerdictEngine(config=cfg, db=AntlionDatabase(cfg.get_db_path()))
    assert engine.alerts.deduplicator.window_seconds == 120
    assert engine.alerts.deduplicator.enabled is True


def test_dedup_env_vars_read(monkeypatch):
    from antlion.core.config import AntlionConfig

    monkeypatch.setenv("ANTLION_ALERT_DEDUP_WINDOW_SEC", "900")
    monkeypatch.setenv("ANTLION_ALERT_DEDUP_ENABLED", "false")

    cfg = AntlionConfig.from_env()
    assert cfg.alert_dedup_window_sec == 900
    assert cfg.alert_dedup_enabled is False