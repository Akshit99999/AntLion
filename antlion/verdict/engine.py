"""
Antlion Verdict Engine: Central orchestrator synthesizing Decoy telemetry,
Network Flow ML predictions, and Behavioral Heuristics into auditable threat verdicts.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from antlion.alerts.dispatcher import AlertDispatcher
from antlion.core.config import DEFAULT_CONFIG, AntlionConfig
from antlion.core.types import (
    AttackCategory,
    DecoyEvent,
    FlowRecord,
    HeuristicMatch,
    MLPrediction,
    SeverityLevel,
    Verdict,
)
from antlion.storage.database import AntlionDatabase
from antlion.verdict.heuristics import BehavioralHeuristicsEngine
from antlion.verdict.scoring import MultiSignalScorer

logger = logging.getLogger("antlion.verdict")


class VerdictEngine:
    """End-to-end threat attribution engine coordinating telemetry, ML, and heuristics."""

    def __init__(
        self,
        config: Optional[AntlionConfig] = None,
        db: Optional[AntlionDatabase] = None,
        alert_dispatcher: Optional[AlertDispatcher] = None,
    ):
        self.config = config or DEFAULT_CONFIG
        self.db = db or AntlionDatabase(self.config.get_db_path())
        self.heuristics = BehavioralHeuristicsEngine(
            rate_window_seconds=self.config.heuristics.rate_window_seconds,
            burst_threshold=self.config.heuristics.burst_threshold_per_window,
        )
        self.scorer = MultiSignalScorer(weights=self.config.scoring)
        self.alerts = alert_dispatcher or AlertDispatcher()

    def process_decoy_event(
        self,
        event: DecoyEvent,
        flow_record: Optional[FlowRecord] = None,
        ml_prediction: Optional[MLPrediction] = None,
    ) -> Verdict:
        """Processes a decoy event, fuses all signals, persists results, and returns verdict."""
        # 1. Persist raw decoy event telemetry
        self.db.persist_decoy_event(event)

        # 2. Evaluate behavioral heuristics
        heuristic_matches: List[HeuristicMatch] = self.heuristics.evaluate_event(event)

        # 3. Fuse signals using original Tri-Signal Scoring
        verdict: Verdict = self.scorer.evaluate(
            decoy_event=event,
            heuristic_matches=heuristic_matches,
            ml_prediction=ml_prediction,
        )

        # 4. Persist network flow record if supplied
        if flow_record:
            self.db.persist_flow_record(flow_record, ml_prediction)

        # 5. Persist verdict to database
        self.db.persist_verdict(verdict)

        # 6. Notify SIEM and chat webhooks if high/critical
        self.alerts.notify(verdict)

        logger.info(
            "Verdict generated: IP=%s Target=%s Category=%s Severity=%s Confidence=%.2f",
            verdict.source_ip,
            verdict.target_service,
            verdict.attack_type.value,
            verdict.severity.value,
            verdict.confidence,
        )

        return verdict

    def get_recent_verdicts(
        self,
        limit: int = 50,
        source_ip: Optional[str] = None,
        severity: Optional[str] = None,
        attack_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Queries stored verdicts."""
        return self.db.query_verdicts(
            limit=limit,
            source_ip=source_ip,
            severity=severity,
            attack_type=attack_type,
        )

    def get_ip_intel(self, source_ip: str) -> Dict[str, Any]:
        """Queries threat intelligence history for a specific IP."""
        return self.db.get_ip_intel(source_ip)

    def get_system_stats(self) -> Dict[str, Any]:
        """Queries summary telemetry and threat distribution metrics."""
        return self.db.get_system_stats()
