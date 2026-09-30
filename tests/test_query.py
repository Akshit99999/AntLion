"""
Tests for Antlion Query REST API and CLI query handlers.
"""

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from antlion.core.types import (
    AttackCategory,
    ContributingSignals,
    DecoyEvent,
    DecoyServiceType,
    InteractionDepth,
    SeverityLevel,
    Verdict,
)
from antlion.query.api import create_query_api
from antlion.query.cli import handle_query_intel, handle_query_stats, handle_query_verdicts
from antlion.storage.database import AntlionDatabase


@pytest.fixture
def populated_db():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        db = AntlionDatabase(tmp.name)

        # Seed sample verdict
        v1 = Verdict(
            verdict_id="test-verdict-101",
            source_ip="198.51.100.5",
            target_service="SSH",
            attack_type=AttackCategory.CREDENTIAL_BRUTE_FORCE,
            severity=SeverityLevel.HIGH,
            confidence=0.88,
            contributing_signals=ContributingSignals(
                decoy_signal={"depth": "auth_attempt"},
                ml_signal={"predicted": "BruteForce"},
                heuristic_signals=[],
                congruence_factor=0.12,
                depth_multiplier=0.75,
            ),
            raw_evidence={"user": "root"},
        )
        db.persist_verdict(v1)

        # Seed sample decoy event
        evt = DecoyEvent(
            source_ip="198.51.100.5",
            source_port=49120,
            target_service=DecoyServiceType.SSH,
            depth=InteractionDepth.AUTHENTICATION_ATTEMPT,
            username="root",
            password="password",
        )
        db.persist_decoy_event(evt)

        yield db, tmp.name


def test_query_api_endpoints(populated_db):
    db, db_path = populated_db
    app = create_query_api(db=db)
    client = TestClient(app)

    # 1. Health check
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

    # 2. List verdicts
    res = client.get("/api/v1/verdicts")
    assert res.status_code == 200
    verdicts = res.json()
    assert len(verdicts) == 1
    assert verdicts[0]["verdict_id"] == "test-verdict-101"
    assert verdicts[0]["source_ip"] == "198.51.100.5"

    # 3. Filter by severity
    res_high = client.get("/api/v1/verdicts?severity=HIGH")
    assert len(res_high.json()) == 1
    res_low = client.get("/api/v1/verdicts?severity=LOW")
    assert len(res_low.json()) == 0

    # 4. Get verdict by ID
    res_v = client.get("/api/v1/verdicts/test-verdict-101")
    assert res_v.status_code == 200
    assert res_v.json()["attack_type"] == AttackCategory.CREDENTIAL_BRUTE_FORCE.value

    # 5. IP Intelligence Dossier
    res_intel = client.get("/api/v1/intel/198.51.100.5")
    assert res_intel.status_code == 200
    intel = res_intel.json()
    assert intel["total_verdicts"] == 1
    assert intel["total_decoy_hits"] == 1
    assert intel["highest_severity"] == "HIGH"

    # 6. Global Stats
    res_stats = client.get("/api/v1/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert stats["total_verdicts"] == 1
    assert stats["total_decoy_hits"] == 1
    assert "HIGH" in stats["severity_breakdown"]


def test_cli_query_handlers(populated_db, capsys):
    db, db_path = populated_db
    path_obj = Path(db_path)

    # Test verdicts CLI
    handle_query_verdicts(path_obj, limit=5)
    captured = capsys.readouterr()
    assert "198.51.100.5" in captured.out
    assert "CREDENTIAL_BRUTE_FORCE" in captured.out or "Credential Brute-Force" in captured.out

    # Test intel CLI
    handle_query_intel(path_obj, source_ip="198.51.100.5")
    captured = capsys.readouterr()
    assert "ANTLION THREAT DOSSIER" in captured.out
    assert "Total Verdicts:          1" in captured.out

    # Test stats CLI
    handle_query_stats(path_obj)
    captured = capsys.readouterr()
    assert "ANTLION HONEYPOT PLATFORM STATISTICS" in captured.out
    assert "Total Threat Verdicts:      1" in captured.out
