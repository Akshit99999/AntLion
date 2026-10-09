"""
SQLite persistence engine for Antlion decoy telemetry, network flows, and verdicts.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from antlion.core.types import (
    AttackCategory,
    ContributingSignals,
    DecoyEvent,
    DecoyServiceType,
    FlowRecord,
    InteractionDepth,
    MLPrediction,
    SeverityLevel,
    Verdict,
)


class AntlionDatabase:
    """Thread-safe SQLite storage abstraction for all Antlion operational data."""

    def __init__(self, db_path: Union[str, Path] = "antlion.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        """Initializes tables and indexes."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Verdicts table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS verdicts (
                    verdict_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    target_service TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    contributing_signals TEXT,
                    raw_evidence TEXT
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_verdicts_ip ON verdicts(source_ip);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_verdicts_time ON verdicts(timestamp);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_verdicts_sev ON verdicts(severity);"
            )

            # 2. Decoy interaction telemetry table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS decoy_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    target_service TEXT NOT NULL,
                    depth TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    session_id TEXT,
                    username TEXT,
                    password TEXT,
                    commands TEXT,
                    http_method TEXT,
                    http_path TEXT,
                    http_headers TEXT,
                    http_payload TEXT,
                    raw_metadata TEXT
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_decoy_ip ON decoy_events(source_ip);"
            )

            # 3. Network flow records table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS flow_records (
                    flow_id TEXT PRIMARY KEY,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    features TEXT NOT NULL,
                    ml_prediction TEXT
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_flow_src_ip ON flow_records(src_ip);"
            )

            conn.commit()

    def persist_verdict(self, verdict: Verdict) -> None:
        """Saves a classified verdict."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO verdicts (
                    verdict_id, timestamp, source_ip, target_service,
                    attack_type, severity, confidence, contributing_signals, raw_evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    verdict.verdict_id,
                    verdict.timestamp.isoformat(),
                    verdict.source_ip,
                    verdict.target_service,
                    verdict.attack_type.value,
                    verdict.severity.value,
                    verdict.confidence,
                    json.dumps(verdict.contributing_signals.to_dict())
                    if verdict.contributing_signals
                    else None,
                    json.dumps(verdict.raw_evidence),
                ),
            )
            conn.commit()

    def persist_decoy_event(self, event: DecoyEvent) -> int:
        """Saves raw decoy event telemetry."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO decoy_events (
                    source_ip, source_port, target_service, depth, timestamp,
                    session_id, username, password, commands, http_method,
                    http_path, http_headers, http_payload, raw_metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event.source_ip,
                    event.source_port,
                    event.target_service.value,
                    event.depth.value,
                    event.event_timestamp.isoformat(),
                    event.session_id,
                    event.username,
                    event.password,
                    json.dumps(event.commands),
                    event.http_method,
                    event.http_path,
                    json.dumps(event.http_headers),
                    event.http_payload,
                    json.dumps(event.raw_metadata),
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def persist_flow_record(
        self, flow: FlowRecord, ml_prediction: Optional[MLPrediction] = None
    ) -> None:
        """Saves network flow features and model inferences."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO flow_records (
                    flow_id, src_ip, src_port, dst_ip, dst_port,
                    protocol, timestamp, features, ml_prediction
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    flow.flow_id,
                    flow.src_ip,
                    flow.src_port,
                    flow.dst_ip,
                    flow.dst_port,
                    flow.protocol,
                    flow.timestamp.isoformat(),
                    json.dumps(flow.features),
                    json.dumps(ml_prediction.to_dict()) if ml_prediction else None,
                ),
            )
            conn.commit()

    def get_verdict(self, verdict_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single verdict by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM verdicts WHERE verdict_id = ?;", (verdict_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_verdict_dict(row)

    def query_verdicts(
        self,
        limit: int = 50,
        source_ip: Optional[str] = None,
        severity: Optional[str] = None,
        attack_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Queries verdicts with optional filters."""
        query = "SELECT * FROM verdicts WHERE 1=1"
        params: List[Any] = []

        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if attack_type:
            query += " AND attack_type = ?"
            params.append(attack_type)

        query += " ORDER BY timestamp DESC LIMIT ?;"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._row_to_verdict_dict(r) for r in rows]

    def get_ip_intel(self, source_ip: str) -> Dict[str, Any]:
        """Gathers aggregate intelligence and forensic timeline for a given source IP."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Verdicts for this IP
            cursor.execute(
                "SELECT * FROM verdicts WHERE source_ip = ? ORDER BY timestamp DESC;",
                (source_ip,),
            )
            verdicts = [self._row_to_verdict_dict(r) for r in cursor.fetchall()]

            # Decoy interactions
            cursor.execute(
                "SELECT * FROM decoy_events WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 100;",
                (source_ip,),
            )
            decoy_events = []
            for r in cursor.fetchall():
                decoy_events.append(
                    {
                        "target_service": r["target_service"],
                        "depth": r["depth"],
                        "timestamp": r["timestamp"],
                        "username": r["username"],
                        "commands": json.loads(r["commands"]) if r["commands"] else [],
                        "http_path": r["http_path"],
                    }
                )

            max_severity = "LOW"
            severities = [v["severity"] for v in verdicts]
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if s in severities:
                    max_severity = s
                    break

            attack_types = list({v["attack_type"] for v in verdicts})

            return {
                "source_ip": source_ip,
                "total_verdicts": len(verdicts),
                "total_decoy_hits": len(decoy_events),
                "highest_severity": max_severity,
                "observed_attack_types": attack_types,
                "recent_verdicts": verdicts[:10],
                "recent_decoy_interactions": decoy_events[:10],
            }

    def get_system_stats(self) -> Dict[str, Any]:
        """Calculates global platform metrics and threat distributions."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) AS total FROM verdicts;")
            total_verdicts = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) AS total FROM decoy_events;")
            total_decoy_events = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) AS total FROM flow_records;")
            total_flows = cursor.fetchone()["total"]

            # Severity distribution
            cursor.execute(
                "SELECT severity, COUNT(*) as count FROM verdicts GROUP BY severity;"
            )
            severity_counts = {r["severity"]: r["count"] for r in cursor.fetchall()}

            # Attack type distribution
            cursor.execute(
                "SELECT attack_type, COUNT(*) as count FROM verdicts GROUP BY attack_type ORDER BY count DESC;"
            )
            attack_type_counts = {
                r["attack_type"]: r["count"] for r in cursor.fetchall()
            }

            # Top attacker IPs
            cursor.execute(
                """
                SELECT
                    source_ip,
                    COUNT(*) as count,
                    MAX(confidence) as max_conf,
                    -- MAX() on a TEXT column sorts lexicographically, so
                    -- "MEDIUM" would beat "HIGH". Rank explicitly in a
                    -- subquery, then map the winning rank back to a label.
                    CASE MAX(sev_rank)
                        WHEN 4 THEN 'CRITICAL'
                        WHEN 3 THEN 'HIGH'
                        WHEN 2 THEN 'MEDIUM'
                        ELSE 'LOW'
                    END AS peak_severity
                FROM (
                    SELECT
                        source_ip,
                        confidence,
                        CASE severity
                            WHEN 'CRITICAL' THEN 4
                            WHEN 'HIGH'     THEN 3
                            WHEN 'MEDIUM'   THEN 2
                            ELSE 1
                        END AS sev_rank
                    FROM verdicts
                )
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10;
                """
            )
            top_attackers = [dict(r) for r in cursor.fetchall()]

            return {
                "total_verdicts": total_verdicts,
                "total_decoy_hits": total_decoy_events,
                "total_flows_monitored": total_flows,
                "severity_breakdown": severity_counts,
                "attack_type_breakdown": attack_type_counts,
                "top_attackers": top_attackers,
            }

    def _row_to_verdict_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "verdict_id": row["verdict_id"],
            "timestamp": row["timestamp"],
            "source_ip": row["source_ip"],
            "target_service": row["target_service"],
            "attack_type": row["attack_type"],
            "severity": row["severity"],
            "confidence": float(row["confidence"]),
            "contributing_signals": json.loads(row["contributing_signals"])
            if row["contributing_signals"]
            else None,
            "raw_evidence": json.loads(row["raw_evidence"])
            if row["raw_evidence"]
            else {},
        }
