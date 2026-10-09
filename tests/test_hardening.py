"""
Regression tests for the Phase 1-3 hardening work.

Covers: env var wiring, double-counted verdicts, CORS/auth, MAX(severity)
aggregation, exploit-detection precision, and heuristic regex boundaries.
"""

import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from antlion.core.config import AntlionConfig
from antlion.core.types import SeverityLevel, Verdict
from antlion.decoys.web.app import create_web_decoy_app
from antlion.storage.database import AntlionDatabase
from antlion.verdict.heuristics import BehavioralHeuristicsEngine


class _RecordingEngine:
    """Captures decoy events instead of persisting them."""

    def __init__(self):
        self.events = []

    def process_decoy_event(self, event):
        self.events.append(event)
        return Verdict(source_ip=event.source_ip)


@pytest.fixture
def engine():
    return _RecordingEngine()


@pytest.fixture
def client(engine):
    return TestClient(create_web_decoy_app(verdict_engine=engine))


# ---------------------------------------------------------------------------
# Phase 1.1 — environment variable wiring
# ---------------------------------------------------------------------------


def test_from_env_reads_db_path_and_webhooks(monkeypatch):
    monkeypatch.setenv("ANTLION_DB_PATH", "/tmp/antlion-test.db")
    monkeypatch.setenv("ANTLION_DISCORD_WEBHOOK", "https://discord.test/abc")
    monkeypatch.setenv("ANTLION_SLACK_WEBHOOK", "https://slack.test/xyz")
    monkeypatch.setenv("ANTLION_ALERT_SEVERITY", "CRITICAL")

    cfg = AntlionConfig.from_env()

    assert cfg.get_db_path() == Path("/tmp/antlion-test.db")
    assert "https://discord.test/abc" in cfg.webhook_urls
    assert "https://slack.test/xyz" in cfg.webhook_urls
    assert cfg.min_alert_severity == "CRITICAL"


def test_from_env_ignores_blank_values(monkeypatch):
    monkeypatch.setenv("ANTLION_DB_PATH", "   ")
    monkeypatch.setenv("ANTLION_DISCORD_WEBHOOK", "")

    cfg = AntlionConfig.from_env()

    # Blank ANTLION_DB_PATH must fall back to data_dir, not become a literal path.
    assert cfg.db_path_override is None
    assert cfg.webhook_urls == []


def test_from_env_rejects_invalid_severity(monkeypatch):
    monkeypatch.setenv("ANTLION_ALERT_SEVERITY", "NOT_A_LEVEL")
    assert AntlionConfig.from_env().min_alert_severity == "HIGH"


def test_from_env_falls_back_on_invalid_port(monkeypatch):
    monkeypatch.setenv("ANTLION_WEB_PORT", "not-a-number")
    assert AntlionConfig.from_env().web_port == 8080


def test_verdict_engine_builds_dispatcher_from_config(monkeypatch):
    from antlion.verdict.engine import VerdictEngine

    monkeypatch.setenv("ANTLION_DISCORD_WEBHOOK", "https://discord.test/x")
    monkeypatch.setenv("ANTLION_ALERT_SEVERITY", "CRITICAL")

    with tempfile.TemporaryDirectory() as tmp:
        cfg = AntlionConfig.from_env()
        cfg.data_dir = Path(tmp)
        cfg.webhook_urls = ["https://discord.test/x"]
        cfg.min_alert_severity = "CRITICAL"

        engine = VerdictEngine(config=cfg, db=AntlionDatabase(cfg.get_db_path()))

        assert engine.alerts.webhook_urls == ["https://discord.test/x"]
        assert engine.alerts.min_severity == SeverityLevel.CRITICAL


def test_compose_healthcheck_matches_real_route():
    """docker-compose must probe a route that actually exists."""
    compose = Path(__file__).resolve().parents[1] / "docker-compose.yml"
    text = compose.read_text()
    # The bare /health probe is stale; the real route is /api/v1/health.
    assert 'localhost:8000/health"' not in text
    assert "localhost:8000/api/v1/health" in text

    from antlion.query.api import create_query_api

    routes = {r.path for r in create_query_api().routes if hasattr(r, "path")}
    assert "/api/v1/health" in routes


# ---------------------------------------------------------------------------
# Phase 1.2 — one login attempt must produce exactly one verdict
# ---------------------------------------------------------------------------


def test_post_login_emits_single_verdict(client, engine):
    response = client.post("/login", data={"username": "root", "password": "admin"})

    assert response.status_code == 401
    assert len(engine.events) == 1
    assert engine.events[0].depth.value == "auth_attempt"
    assert engine.events[0].username == "root"


def test_get_paths_still_emit_verdicts(client, engine):
    client.get("/api/v1/cluster/status")
    assert len(engine.events) == 1
    assert engine.events[0].depth.value == "web_endpoint_probe"


# ---------------------------------------------------------------------------
# Phase 2.1 — CORS allowlist and API key auth
# ---------------------------------------------------------------------------


def _api_client(api_key):
    from antlion.query.api import create_query_api

    cfg = AntlionConfig(data_dir=Path(tempfile.mkdtemp()))
    cfg.api_key = api_key
    cfg.cors_origins = ["http://localhost:8000"]
    return TestClient(create_query_api(db=AntlionDatabase(cfg.get_db_path()), config=cfg))


def test_api_rejects_missing_key():
    client = _api_client("s3cret-key")
    assert client.get("/api/v1/stats").status_code == 401


def test_api_rejects_wrong_key():
    client = _api_client("s3cret-key")
    assert client.get("/api/v1/stats", headers={"X-API-Key": "wrong"}).status_code == 401


def test_api_accepts_valid_key():
    client = _api_client("s3cret-key")
    assert client.get("/api/v1/stats", headers={"X-API-Key": "s3cret-key"}).status_code == 200


def test_api_accepts_bearer_token():
    client = _api_client("s3cret-key")
    resp = client.get("/api/v1/stats", headers={"Authorization": "Bearer s3cret-key"})
    assert resp.status_code == 200


def test_health_stays_public_without_key():
    client = _api_client("s3cret-key")
    assert client.get("/api/v1/health").status_code == 200


def test_cors_does_not_reflect_arbitrary_origin():
    client = _api_client(None)
    resp = client.get("/api/v1/stats", headers={"Origin": "https://evil.example"})
    assert resp.headers.get("access-control-allow-origin") != "https://evil.example"


def test_wildcard_origin_falls_back_to_localhost():
    from antlion.query.api import create_query_api

    cfg = AntlionConfig(data_dir=Path(tempfile.mkdtemp()))
    cfg.cors_origins = ["*"]
    client = TestClient(create_query_api(db=AntlionDatabase(cfg.get_db_path()), config=cfg))

    resp = client.get("/api/v1/stats", headers={"Origin": "https://evil.example"})
    assert resp.headers.get("access-control-allow-origin") != "https://evil.example"


# ---------------------------------------------------------------------------
# Phase 2.2 — X-Forwarded-For must not be trusted by default
# ---------------------------------------------------------------------------


def test_xff_ignored_by_default(client, engine):
    client.get("/api/v1/nodes", headers={"X-Forwarded-For": "6.6.6.6"})
    # Peer IP (testclient) is used, not the spoofed header value.
    assert engine.events[0].source_ip != "6.6.6.6"
    assert engine.events[0].raw_metadata["claimed_xff"] == "6.6.6.6"
    assert engine.events[0].raw_metadata["xff_trusted"] is False


def test_xff_honoured_when_trust_enabled(engine):
    from antlion.core.config import AntlionConfig

    cfg = AntlionConfig()
    cfg.trust_proxy_headers = True
    client = TestClient(create_web_decoy_app(verdict_engine=engine, config=cfg))

    client.get("/api/v1/nodes", headers={"X-Forwarded-For": "6.6.6.6"})
    assert engine.events[0].source_ip == "6.6.6.6"


# ---------------------------------------------------------------------------
# Phase 3.1 — peak_severity must respect rank, not alphabetical order
# ---------------------------------------------------------------------------


def test_peak_severity_is_not_lexicographic():
    from antlion.core.types import AttackCategory

    with tempfile.TemporaryDirectory() as tmp:
        db = AntlionDatabase(Path(tmp) / "t.db")

        # HIGH + MEDIUM + LOW: alphabetical MAX() would wrongly return MEDIUM.
        for sev in ("HIGH", "MEDIUM", "LOW"):
            db.persist_verdict(
                Verdict(
                    source_ip="9.9.9.9",
                    attack_type=AttackCategory.UNKNOWN_MALICIOUS,
                    severity=SeverityLevel[sev],
                    confidence=0.5,
                )
            )

        stats = db.get_system_stats()
        entry = next(a for a in stats["top_attackers"] if a["source_ip"] == "9.9.9.9")
        assert entry["peak_severity"] == "HIGH"


def test_peak_severity_critical_wins():
    from antlion.core.types import AttackCategory

    with tempfile.TemporaryDirectory() as tmp:
        db = AntlionDatabase(Path(tmp) / "t.db")
        for sev in ("MEDIUM", "CRITICAL", "HIGH"):
            db.persist_verdict(
                Verdict(
                    source_ip="8.8.8.8",
                    attack_type=AttackCategory.UNKNOWN_MALICIOUS,
                    severity=SeverityLevel[sev],
                    confidence=0.5,
                )
            )

        stats = db.get_system_stats()
        entry = next(a for a in stats["top_attackers"] if a["source_ip"] == "8.8.8.8")
        assert entry["peak_severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Phase 3.2 / 3.3 — exploit detection precision
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/invalid",
        "/grid",
        "/api/v1/video",
        "/identity/verify",
        "/api/v1/nodes",
        "/latest/meta-data/",
        "/api/v1/cluster/status",
        "/healthz",
    ],
)
def test_ordinary_paths_are_not_exploits(client, engine, path):
    client.get(path)
    assert engine.events[0].depth.value == "web_endpoint_probe"


@pytest.mark.parametrize(
    "path",
    [
        "/?q=union select",
        "/?q=union+select",
        "/?q=union%20select",
        "/x?id=../../etc/passwd",
        "/.env",
        "/a?c=sleep(5)",
        "/api/v1/debug/eval?c=eval(1)",
    ],
)
def test_real_exploits_are_flagged(client, engine, path):
    client.get(path)
    assert engine.events[0].depth.value == "web_exploit_payload"


def test_cmd_system_recon_ignores_embedded_id():
    """'id' must not match inside vid/gridctl."""
    engine = BehavioralHeuristicsEngine()
    pat = next(
        p for p in engine.CMD_PATTERNS if p[0] == "CMD_SYSTEM_RECON"
    )[1]

    assert pat.search("id") is not None
    assert pat.search("whoami") is not None
    assert pat.search("vid -i test.mp4") is None
    assert pat.search("gridctl status") is None


# ---------------------------------------------------------------------------
# Phase 3.4 — missing typing import
# ---------------------------------------------------------------------------


def test_filesystem_module_annotations_resolve():
    import typing

    from antlion.decoys.ssh_telnet import filesystem

    # Would raise NameError if 'Any' were not imported.
    typing.get_type_hints(filesystem.FakeFilesystem.__init__)