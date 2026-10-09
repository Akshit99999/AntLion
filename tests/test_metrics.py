"""
Tests for the Prometheus metrics registry and /metrics endpoint.

The registry emits the text exposition format directly, so these tests assert
on the rendered output rather than on a client library's data model.
"""

import tempfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from antlion.core.metrics import (
    REGISTRY,
    MetricsRegistry,
    record_alert_delivery,
    record_alert_suppression,
    record_decoy_event,
    record_verdict,
    refresh_suppression_gauge,
    register_default_metrics,
    set_database_gauges,
)
from antlion.core.types import SeverityLevel
from antlion.storage.database import AntlionDatabase


@pytest.fixture
def registry():
    return MetricsRegistry()


def parse_exposition(text):
    """Parses exposition text into (name, labels dict, value) samples."""
    samples = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        metric_part, _, value = line.rpartition(" ")
        if "{" in metric_part:
            name, _, label_str = metric_part.partition("{")
            labels = {}
            for pair in label_str.rstrip("}").split(","):
                if not pair:
                    continue
                k, _, v = pair.partition("=")
                labels[k] = v.strip('"')
            samples[(name, tuple(sorted(labels.items())))] = float(value)
        else:
            samples[(metric_part, ())] = float(value)
    return samples


# ---------------------------------------------------------------------------
# Registry mechanics
# ---------------------------------------------------------------------------


def test_registered_metric_appears_at_zero(registry):
    registry.register("antlion_test_gauge", "A test gauge", "gauge")
    out = registry.render()
    assert "# HELP antlion_test_gauge A test gauge" in out
    assert "# TYPE antlion_test_gauge gauge" in out


def test_counter_increments(registry):
    registry.inc("hits")
    registry.inc("hits")
    assert registry.get("hits") == 2.0


def test_counter_with_labels_is_independent(registry):
    registry.inc("hits", kind="a")
    registry.inc("hits", kind="b")
    registry.inc("hits", kind="a")

    assert registry.get("hits", kind="a") == 2.0
    assert registry.get("hits", kind="b") == 1.0


def test_label_order_does_not_create_duplicate_series(registry):
    registry.inc("hits", b="2", a="1")
    registry.inc("hits", a="1", b="2")
    assert registry.get("hits", a="1", b="2") == 2.0


def test_set_overwrites_gauge(registry):
    registry.set("temp", 10)
    registry.set("temp", 25)
    assert registry.get("temp") == 25.0


def test_get_missing_returns_zero(registry):
    assert registry.get("never_set") == 0.0


def test_value_alias_matches_get(registry):
    registry.set("x", 7)
    assert registry.value("x") == registry.get("x")


def test_render_includes_help_and_type(registry):
    registry.register("m", "Help text", "counter")
    registry.inc("m")
    out = registry.render()
    assert "# HELP m Help text" in out
    assert "# TYPE m counter" in out
    assert "m 1" in out


def test_render_escapes_label_values(registry):
    registry.inc("m", label='has "quotes" and \\backslash')
    out = registry.render()
    assert '\\"quotes\\"' in out
    assert "\\\\backslash" in out


def test_render_escapes_newlines(registry):
    registry.inc("m", label="line1\nline2")
    out = registry.render()
    assert "\\n" in out
    assert "line1\nline2" not in out


def test_render_whole_floats_have_no_decimal(registry):
    registry.set("g", 3.0)
    assert "g 3\n" in registry.render()


def test_render_fractional_floats(registry):
    registry.set("g", 0.1234567)
    assert "0.123457" in registry.render()


def test_render_is_deterministic(registry):
    registry.inc("z", k="1")
    registry.inc("a", k="2")
    assert registry.render() == registry.render()


def test_reset_not_required_between_renders(registry):
    registry.inc("c")
    first = registry.render()
    registry.inc("c")
    second = registry.render()
    assert first != second


# ---------------------------------------------------------------------------
# Default metric helpers
# ---------------------------------------------------------------------------


def test_record_verdict_labels_severity_and_attack(registry):
    record_verdict(SeverityLevel.HIGH, "Credential Brute-Force", 0.9, registry)
    samples = parse_exposition(registry.render())
    assert samples[("antlion_verdicts_total", (("attack_type", "Credential Brute-Force"), ("severity", "HIGH")))] == 1.0


def test_record_verdict_sets_confidence_gauge(registry):
    record_verdict(SeverityLevel.CRITICAL, "Web Exploit", 0.95, registry)
    samples = parse_exposition(registry.render())
    assert samples[("antlion_verdict_confidence", (("attack_type", "Web Exploit"),))] == 0.95


def test_record_decoy_event(registry):
    record_decoy_event("SSH", "auth_attempt", registry)
    samples = parse_exposition(registry.render())
    assert samples[("antlion_decoy_events_total", (("depth", "auth_attempt"), ("service", "SSH")))] == 1.0


def test_record_alert_delivery_result_label(registry):
    record_alert_delivery("success", registry)
    record_alert_delivery("failure", registry)
    samples = parse_exposition(registry.render())
    assert samples[("antlion_alerts_delivered_total", (("result", "success"),))] == 1.0
    assert samples[("antlion_alerts_delivered_total", (("result", "failure"),))] == 1.0


def test_record_alert_suppression(registry):
    record_alert_suppression(registry)
    record_alert_suppression(registry)
    assert registry.get("antlion_alerts_suppressed_total") == 2.0


def test_refresh_suppression_gauges(registry):
    refresh_suppression_gauge(emitted=10, suppressed=90, registry=registry)
    assert registry.get("antlion_alerts_emitted_total") == 10.0
    assert registry.get("antlion_alerts_suppressed_total") == 90.0


def test_set_database_gauges(registry):
    set_database_gauges(
        registry=registry,
        total_verdicts=100,
        distinct_attackers=7,
        decoy_events=250,
        flow_records=42,
    )
    assert registry.get("antlion_verdicts_stored") == 100.0
    assert registry.get("antlion_distinct_attackers") == 7.0
    assert registry.get("antlion_decoy_events_stored") == 250.0
    assert registry.get("antlion_flow_records_stored") == 42.0


def test_register_default_metrics_is_idempotent(registry):
    register_default_metrics(registry)
    register_default_metrics(registry)
    out = registry.render()
    assert out.count("# HELP antlion_verdicts_stored") == 1


# ---------------------------------------------------------------------------
# /metrics endpoint
# ---------------------------------------------------------------------------


@pytest.fixture
def metrics_client():
    from antlion.query.api import create_query_api

    cfg_dir = Path(tempfile.mkdtemp())
    db = AntlionDatabase(cfg_dir / "metrics.db")
    return TestClient(create_query_api(db=db))


def test_metrics_endpoint_is_public(metrics_client):
    """Scrape endpoint must work without the API key."""
    resp = metrics_client.get("/metrics")
    assert resp.status_code == 200


def test_metrics_content_type(metrics_client):
    resp = metrics_client.get("/metrics")
    assert "text/plain" in resp.headers["content-type"]


def test_metrics_exposes_core_series(metrics_client):
    out = metrics_client.get("/metrics").text
    assert "antlion_verdicts_stored" in out
    assert "antlion_decoy_events_stored" in out
    assert "antlion_flow_records_stored" in out
    assert "antlion_distinct_attackers" in out


def test_metrics_reflects_database_contents(metrics_client):
    from antlion.core.types import AttackCategory, Verdict

    db = AntlionDatabase(Path(tempfile.mkdtemp()) / "g.db")
    for ip in ("1.1.1.1", "2.2.2.2"):
        db.persist_verdict(
            Verdict(
                source_ip=ip,
                attack_type=AttackCategory.RECON_SCAN,
                severity=SeverityLevel.MEDIUM,
                confidence=0.5,
            )
        )

    from antlion.query.api import create_query_api

    client = TestClient(create_query_api(db=db))
    samples = parse_exposition(client.get("/metrics").text)

    assert samples[("antlion_verdicts_stored", ())] == 2.0
    assert samples[("antlion_distinct_attackers", ())] == 2.0


def test_metrics_survives_database_error(metrics_client):
    """A scrape must never 500 because of a storage problem."""

    class BrokenDB:
        def get_system_stats(self):
            raise RuntimeError("database exploded")

    from antlion.query.api import create_query_api

    client = TestClient(create_query_api(db=BrokenDB()))
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "antlion_verdicts_stored" in resp.text


def test_metrics_does_not_leak_sensitive_data(metrics_client):
    """No captured credentials or attacker IPs in the scrape output."""
    from antlion.core.types import AttackCategory, Verdict

    db = AntlionDatabase(Path(tempfile.mkdtemp()) / "leak.db")
    db.persist_verdict(
        Verdict(
            source_ip="203.0.113.99",
            attack_type=AttackCategory.CREDENTIAL_BRUTE_FORCE,
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            raw_evidence={"password": "supersecret", "username": "root"},
        )
    )

    from antlion.query.api import create_query_api

    client = TestClient(create_query_api(db=db))
    out = client.get("/metrics").text

    assert "supersecret" not in out
    assert "203.0.113.99" not in out


# ---------------------------------------------------------------------------
# Engine integration
# ---------------------------------------------------------------------------


def test_engine_records_verdict_metrics():
    """The engine writes to the process-wide registry."""
    from antlion.core.config import AntlionConfig
    from antlion.core.types import DecoyEvent, DecoyServiceType, InteractionDepth
    from antlion.verdict.engine import VerdictEngine

    reg = REGISTRY
    before = parse_exposition(reg.render()).get(
        ("antlion_verdicts_total", ()), 0.0
    )
    baseline = sum(
        v
        for (name, _), v in parse_exposition(reg.render()).items()
        if name == "antlion_verdicts_total"
    )

    cfg = AntlionConfig(data_dir=Path(tempfile.mkdtemp()))
    engine = VerdictEngine(config=cfg, db=AntlionDatabase(cfg.get_db_path()))

    event = DecoyEvent(
        source_ip="5.5.5.5",
        source_port=1234,
        target_service=DecoyServiceType.SSH,
        depth=InteractionDepth.AUTHENTICATION_ATTEMPT,
        username="root",
        password="toor",
    )
    verdict = engine.process_decoy_event(event)

    samples = parse_exposition(reg.render())
    key = (
        "antlion_verdicts_total",
        (("attack_type", verdict.attack_type.value), ("severity", verdict.severity.value)),
    )
    after = sum(
        v
        for (name, _), v in samples.items()
        if name == "antlion_verdicts_total"
    )

    assert after == baseline + 1.0
    assert key in samples


def test_metrics_failure_does_not_break_verdict(monkeypatch):
    """A broken registry must not prevent persistence or alerting."""
    from antlion.core.config import AntlionConfig
    from antlion.core.types import DecoyEvent, DecoyServiceType, InteractionDepth
    from antlion.verdict.engine import VerdictEngine

    cfg = AntlionConfig(data_dir=Path(tempfile.mkdtemp()))
    db = AntlionDatabase(cfg.get_db_path())
    engine = VerdictEngine(config=cfg, db=db)

    import antlion.verdict.engine as eng

    def boom(*a, **kw):
        raise RuntimeError("metrics down")

    monkeypatch.setattr(eng, "record_verdict", boom)
    monkeypatch.setattr(eng, "record_decoy_event", boom)

    verdict = engine.process_decoy_event(
        DecoyEvent(
            source_ip="6.6.6.6",
            source_port=1,
            target_service=DecoyServiceType.WEB_ADMIN,
            depth=InteractionDepth.WEB_ENDPOINT_PROBE,
        )
    )

    assert verdict.verdict_id
    assert len(db.query_verdicts(limit=10)) == 1