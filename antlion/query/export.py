"""
SIEM export formats for Antlion verdicts.

Three formats are supported:

* **CSV** — flattened, spreadsheet-friendly, for analysts and log pipelines.
* **JSON** — the native verdict dictionaries, for programmatic consumers.
* **STIX 2.1** — Threat Intelligence interoperability. Verdicts are emitted as
  ``indicator`` objects carrying the source IP as a pattern, so a SIEM or
  threat-intel platform can ingest them directly.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from antlion.core.types import SeverityLevel
from antlion.storage.database import AntlionDatabase

# Flattened column order for CSV export.
CSV_COLUMNS: List[str] = [
    "verdict_id",
    "timestamp",
    "source_ip",
    "target_service",
    "attack_type",
    "severity",
    "confidence",
    "heuristic_count",
    "evasion_detected",
    "commands",
    "http_path",
    "username",
]

STIX_VERSION = "2.1"


def _iso_or_empty(value: Optional[str]) -> str:
    """Normalises a stored timestamp to a STIX-valid RFC 3339 string."""
    if not value:
        return datetime.now(timezone.utc).isoformat()
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.isoformat()
    except (TypeError, ValueError):
        return value


def _to_csv_rows(verdicts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flattens verdict dictionaries into CSV-friendly rows."""
    rows = []

    for v in verdicts:
        evidence = v.get("raw_evidence") or {}
        signals = v.get("contributing_signals") or {}
        heuristic_signals = signals.get("heuristic_signals") or []

        commands = evidence.get("commands") or []
        if isinstance(commands, str):
            try:
                commands = json.loads(commands)
            except (TypeError, ValueError):
                commands = [commands]

        rows.append(
            {
                "verdict_id": v.get("verdict_id", ""),
                "timestamp": v.get("timestamp", ""),
                "source_ip": v.get("source_ip", ""),
                "target_service": v.get("target_service", ""),
                "attack_type": v.get("attack_type", ""),
                "severity": v.get("severity", ""),
                "confidence": v.get("confidence", 0.0),
                "heuristic_count": evidence.get(
                    "heuristic_count", len(heuristic_signals)
                ),
                "evasion_detected": evidence.get("evasion_detected", False),
                # Semicolon-joined so embedded commands cannot break the row.
                "commands": "; ".join(str(c) for c in commands),
                "http_path": evidence.get("http_path") or "",
                "username": evidence.get("username") or "",
            }
        )

    return rows


def to_csv(verdicts: List[Dict[str, Any]]) -> str:
    """Renders verdicts as CSV with a header row."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()

    for row in _to_csv_rows(verdicts):
        writer.writerow(row)

    return buffer.getvalue()


def to_json(verdicts: List[Dict[str, Any]]) -> str:
    """Renders verdicts as a pretty-printed JSON array."""
    return json.dumps(verdicts, indent=2, default=str)


def _severity_score(severity: str) -> int:
    """Maps severity to a 0-100 STIX confidence contribution."""
    return {
        SeverityLevel.CRITICAL.value: 95,
        SeverityLevel.HIGH.value: 75,
        SeverityLevel.MEDIUM.value: 50,
        SeverityLevel.LOW.value: 25,
    }.get(severity, 50)


def _pattern_for_ip(ip: str) -> str:
    """Builds a STIX pattern matching the source IP.

    IPv6 literals contain colons, which must be quoted in STIX patterns.
    """
    if ":" in ip:
        return f"[ipv6-addr:value = '{ip}']"
    return f"[ipv4-addr:value = '{ip}']"


def to_stix(verdicts: List[Dict[str, Any]]) -> str:
    """Renders verdicts as a STIX 2.1 Bundle of indicator objects."""
    now = datetime.now(timezone.utc).isoformat()
    objects: List[Dict[str, Any]] = []

    for v in verdicts:
        verdict_id = v.get("verdict_id") or str(uuid.uuid4())
        ip = v.get("source_ip", "")
        severity = v.get("severity", SeverityLevel.MEDIUM.value)
        confidence = float(v.get("confidence") or 0.0)
        evidence = v.get("raw_evidence") or {}

        indicator: Dict[str, Any] = {
            "type": "indicator",
            "spec_version": STIX_VERSION,
            "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, verdict_id)}",
            "created": _iso_or_empty(v.get("timestamp")),
            "modified": _iso_or_empty(v.get("timestamp")),
            "name": f"Antlion: {v.get('attack_type', 'Unknown Malicious')}",
            "description": (
                f"Honeypot interaction with {v.get('target_service', 'decoy')} "
                f"service classified as {v.get('attack_type', 'unknown')} "
                f"with {confidence:.0%} confidence."
            ),
            "indicator_types": ["malicious-activity"],
            "pattern": _pattern_for_ip(ip),
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": _iso_or_empty(v.get("timestamp")),
            "labels": [severity, v.get("attack_type", "unknown")],
            "confidence": int(min(100, max(0, confidence * 100))),
            "external_references": [
                {
                    "source_name": "antlion-verdict",
                    "external_id": verdict_id,
                }
            ],
        }

        # Preserve forensic context that has no native STIX equivalent.
        context = {
            k: evidence[k]
            for k in ("commands", "username", "http_path", "evasion_detected")
            if k in evidence
        }
        if context:
            indicator["x_antlion_context"] = context

        objects.append(indicator)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": STIX_VERSION,
        "objects": objects,
    }

    return json.dumps(bundle, indent=2, default=str)


def export_verdicts(
    db: AntlionDatabase,
    fmt: str = "csv",
    limit: int = 1000,
    source_ip: Optional[str] = None,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
) -> str:
    """Queries verdicts and renders them in the requested format.

    Raises ValueError for an unsupported format rather than silently returning
    the wrong shape to a downstream SIEM.
    """
    normalized = (fmt or "csv").lower()

    if normalized not in ("csv", "json", "stix"):
        raise ValueError(
            f"Unsupported export format: {fmt!r}. Use one of: csv, json, stix"
        )

    verdicts = db.query_verdicts(
        limit=limit,
        source_ip=source_ip,
        severity=severity,
        attack_type=attack_type,
    )

    if normalized == "csv":
        return to_csv(verdicts)
    if normalized == "json":
        return to_json(verdicts)
    return to_stix(verdicts)