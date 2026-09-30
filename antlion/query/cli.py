"""
Command-line query utilities to inspect Antlion verdicts, stats, and IP intelligence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from antlion.storage.database import AntlionDatabase


def handle_query_verdicts(
    db_path: Path,
    limit: int = 20,
    source_ip: Optional[str] = None,
    severity: Optional[str] = None,
    as_json: bool = False,
) -> None:
    """Displays formatted verdicts from the database."""
    db = AntlionDatabase(db_path)
    verdicts = db.query_verdicts(limit=limit, source_ip=source_ip, severity=severity)

    if as_json:
        print(json.dumps(verdicts, indent=2))
        return

    if not verdicts:
        print("No matching verdicts found.")
        return

    print("=" * 105)
    print(f"{'TIMESTAMP':<24} {'SOURCE IP':<18} {'SERVICE':<10} {'SEVERITY':<10} {'CONF':<6} {'ATTACK TYPE'}")
    print("=" * 105)

    for v in verdicts:
        ts = v["timestamp"][:19]
        ip = v["source_ip"]
        svc = v["target_service"]
        sev = v["severity"]
        conf = f"{v['confidence']:.2f}"
        cat = v["attack_type"]
        print(f"{ts:<24} {ip:<18} {svc:<10} {sev:<10} {conf:<6} {cat}")

    print("=" * 105)
    print(f"Total verdicts displayed: {len(verdicts)}")


def handle_query_intel(db_path: Path, source_ip: str, as_json: bool = False) -> None:
    """Displays forensic dossier and activity summary for a target IP."""
    db = AntlionDatabase(db_path)
    intel = db.get_ip_intel(source_ip)

    if as_json:
        print(json.dumps(intel, indent=2))
        return

    print("=" * 70)
    print(f"ANTLION THREAT DOSSIER: {source_ip}")
    print("=" * 70)
    print(f"Total Verdicts:          {intel['total_verdicts']}")
    print(f"Total Decoy Pit Hits:    {intel['total_decoy_hits']}")
    print(f"Highest Severity:        {intel['highest_severity']}")
    print(f"Observed Attack Types:   {', '.join(intel['observed_attack_types']) or 'None'}")
    print("-" * 70)
    print("Recent Decoy Interactions:")
    for hit in intel["recent_decoy_interactions"][:5]:
        ts = hit["timestamp"][:19]
        svc = hit["target_service"]
        depth = hit["depth"]
        extra = f"user={hit['username']}" if hit["username"] else (hit["http_path"] or "")
        print(f"  [{ts}] {svc:<8} depth={depth:<15} {extra}")
    print("=" * 70)


def handle_query_stats(db_path: Path, as_json: bool = False) -> None:
    """Displays platform analytics and threat category breakdown."""
    db = AntlionDatabase(db_path)
    stats = db.get_system_stats()

    if as_json:
        print(json.dumps(stats, indent=2))
        return

    print("=" * 60)
    print("ANTLION HONEYPOT PLATFORM STATISTICS")
    print("=" * 60)
    print(f"Total Threat Verdicts:      {stats['total_verdicts']}")
    print(f"Total Decoy Pit Hits:       {stats['total_decoy_hits']}")
    print(f"Total Flows Monitored:      {stats['total_flows_monitored']}")
    print("-" * 60)
    print("Severity Breakdown:")
    for sev, count in stats["severity_breakdown"].items():
        print(f"  {sev:<12} : {count}")
    print("-" * 60)
    print("Attack Family Breakdown:")
    for cat, count in stats["attack_type_breakdown"].items():
        print(f"  {cat:<32} : {count}")
    print("-" * 60)
    print("Top Attacker IPs:")
    for att in stats["top_attackers"][:5]:
        ip = att["source_ip"]
        count = att["count"]
        sev = att["peak_severity"]
        print(f"  {ip:<18} hits={count:<5} peak_severity={sev}")
    print("=" * 60)
