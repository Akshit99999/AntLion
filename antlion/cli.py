"""
Main command-line interface entry point for Antlion.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

import uvicorn

from antlion.classification.benchmark import train_and_persist_pipeline
from antlion.core.config import DEFAULT_CONFIG
from antlion.decoys.ssh_telnet.server import InteractiveDecoyServer
from antlion.decoys.web.server import WebDecoyServer
from antlion.query.api import create_query_api
from antlion.query.cli import handle_query_intel, handle_query_stats, handle_query_verdicts
from antlion.storage.database import AntlionDatabase
from antlion.storage.prune import RetentionManager, RetentionScheduler
from antlion.verdict.engine import VerdictEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antlion",
        description="Antlion: Honeypot-Based Intrusion Detection and Attack Classification System",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # Decoy subcommands
    decoy_parser = subparsers.add_parser("decoy", help="Run decoy pit services")
    decoy_subs = decoy_parser.add_subparsers(dest="decoy_service", help="Decoy type")

    web_parser = decoy_subs.add_parser("web", help="Start Web Admin honeypot portal")
    web_parser.add_argument("--host", default="0.0.0.0", help="Listen host")
    web_parser.add_argument("--port", type=int, default=8080, help="Listen port")

    ssh_parser = decoy_subs.add_parser("ssh", help="Start SSH/Telnet shell honeypot")
    ssh_parser.add_argument("--host", default="0.0.0.0", help="Listen host")
    ssh_parser.add_argument("--port", type=int, default=2222, help="Listen port")
    ssh_parser.add_argument("--hostname", default=None, help="Custom server hostname")

    # API subcommand
    api_parser = subparsers.add_parser("api", help="Start REST query API server")
    api_parser.add_argument("--host", default="127.0.0.1", help="Listen host")
    api_parser.add_argument("--port", type=int, default=8000, help="Listen port")

    # Query subcommand
    query_parser = subparsers.add_parser("query", help="Query stored verdicts and intelligence")
    query_subs = query_parser.add_subparsers(dest="query_action", help="Query action")

    q_verdicts = query_subs.add_parser("verdicts", help="List recent verdicts")
    q_verdicts.add_argument("--limit", type=int, default=20, help="Number of records to show")
    q_verdicts.add_argument("--ip", default=None, help="Filter by source IP")
    q_verdicts.add_argument("--severity", default=None, help="Filter by severity")
    q_verdicts.add_argument("--json", action="store_true", help="Output raw JSON")

    q_intel = query_subs.add_parser("intel", help="Investigate specific IP address")
    q_intel.add_argument("ip", help="Target source IP address")
    q_intel.add_argument("--json", action="store_true", help="Output raw JSON")

    q_stats = query_subs.add_parser("stats", help="Show system statistics and threat summary")
    q_stats.add_argument("--json", action="store_true", help="Output raw JSON")

    # Prune subcommand (retention management)
    prune_parser = subparsers.add_parser(
        "prune", help="Delete stored records older than the retention window"
    )
    prune_parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Retention window in days (overrides ANTLION_RETENTION_DAYS)",
    )
    prune_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be deleted without deleting anything",
    )

    # Export subcommand (SIEM interop)
    export_parser = subparsers.add_parser(
        "export", help="Export verdicts for SIEM integration"
    )
    export_parser.add_argument(
        "--format",
        choices=["csv", "json", "stix"],
        default="csv",
        help="Export format (default: csv)",
    )
    export_parser.add_argument("--limit", type=int, default=1000, help="Max records")
    export_parser.add_argument("--ip", default=None, help="Filter by source IP")
    export_parser.add_argument(
        "--output", default=None, help="Write to file instead of stdout"
    )

    # Train subcommand
    train_parser = subparsers.add_parser("train", help="Train and benchmark flow classifiers")
    train_parser.add_argument("--data", default=None, help="Path to labeled CSV dataset")
    train_parser.add_argument("--save-path", default=None, help="Path to save best model")

    # Info subcommand
    subparsers.add_parser("info", help="Display Antlion platform configuration")

    return parser


def _maybe_start_retention(config, db) -> Optional[RetentionScheduler]:
    """Starts the background retention scheduler when enabled.

    Any long-running command shares one database, so every service that writes
    verdicts needs its own sweeper; running several is safe because deletion
    is idempotent.
    """
    if not config.retention_autostart or config.retention_days <= 0:
        return None

    manager = RetentionManager(
        db=db,
        retention_days=config.retention_days,
        batch_size=config.retention_batch_size,
    )
    scheduler = RetentionScheduler(
        manager=manager, interval_seconds=config.retention_interval_sec
    )
    scheduler.start()
    return scheduler


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    # Rebuild config from the environment so ANTLION_* variables (DB path,
    # webhooks, alert severity, API key) take effect at runtime.
    config = DEFAULT_CONFIG.__class__.from_env()
    db_path = config.get_db_path()
    db = AntlionDatabase(db_path)
    engine = VerdictEngine(config=config, db=db)

    if args.subcommand == "info":
        print("Antlion v0.1.0 - Defensive Intrusion Detection Platform")
        print(f"Database Path:   {db_path}")
        print(f"Data Directory:  {config.data_dir}")
        print(f"Default Web:     {config.web_host}:{config.web_port}")
        print(f"Default SSH:     {config.ssh_host}:{config.ssh_port}")
        print(f"Alert Webhooks:  {len(config.webhook_urls)} configured")
        print(f"Min Severity:    {config.min_alert_severity}")
        print(f"Alert Dedup:     {'on' if config.alert_dedup_enabled else 'off'} "
              f"({config.alert_dedup_window_sec}s window)")
        print(f"Retention:       "
              f"{config.retention_days}d"
              f"{'' if config.retention_days > 0 else ' (disabled)'}")
        print(f"API Key:         {'configured' if config.api_key else 'NOT SET (unprotected)'}")
        return

    if args.subcommand == "decoy":
        _retention = _maybe_start_retention(config, db)
        if args.decoy_service == "web":
            server = WebDecoyServer(
                host=args.host, port=args.port, verdict_engine=engine, config=config
            )
            server.run()
        elif args.decoy_service == "ssh":
            ssh_server = InteractiveDecoyServer(
                host=args.host,
                port=args.port,
                hostname=args.hostname,
                verdict_engine=engine,
            )
            print(f"Starting Antlion SSH Decoy on {args.host}:{args.port}...")
            ssh_server.start(blocking=True)
        else:
            parser.parse_args(["decoy", "--help"])

    elif args.subcommand == "api":
        _retention = _maybe_start_retention(config, db)
        app = create_query_api(db=db, config=config)
        print(f"Starting Antlion REST API on http://{args.host}:{args.port} (Docs: http://{args.host}:{args.port}/docs)")
        uvicorn.run(app, host=args.host, port=args.port)

    elif args.subcommand == "query":
        if args.query_action == "verdicts":
            handle_query_verdicts(
                db_path,
                limit=args.limit,
                source_ip=args.ip,
                severity=args.severity,
                as_json=args.json,
            )
        elif args.query_action == "intel":
            handle_query_intel(db_path, source_ip=args.ip, as_json=args.json)
        elif args.query_action == "stats":
            handle_query_stats(db_path, as_json=args.json)
        else:
            parser.parse_args(["query", "--help"])

    elif args.subcommand == "prune":
        days = args.days if args.days is not None else config.retention_days
        manager = RetentionManager(
            db=db,
            retention_days=days,
            batch_size=config.retention_batch_size,
        )

        if not manager.enabled:
            print("Retention disabled (retention_days=%d). Nothing to prune." % days)
            return

        if args.dry_run:
            counts = manager.count_expired()
            total = sum(counts.values())
            print(f"Would delete {total} record(s) older than {manager.cutoff()}:")
            for table, count in counts.items():
                print(f"  {table:16} {count}")
            return

        result = manager.prune_once()
        print(
            f"Pruned {result.total_deleted} record(s) "
            f"older than {manager.cutoff()} "
            f"in {result.elapsed_seconds:.2f}s"
        )
        for table, count in result.deleted.items():
            print(f"  {table:16} {count}")

    elif args.subcommand == "export":
        from antlion.query.export import export_verdicts

        payload = export_verdicts(
            db=db,
            fmt=args.format,
            limit=args.limit,
            source_ip=args.ip,
        )
        if args.output:
            Path(args.output).write_text(payload, encoding="utf-8")
            print(f"Wrote {args.limit} record(s) as {args.format.upper()} to {args.output}")
        else:
            print(payload)

    elif args.subcommand == "train":
        save_path = args.save_path or config.get_model_path()
        import pandas as pd
        df = pd.read_csv(args.data) if args.data else None
        print("Starting classifier benchmark training...")
        benchmark, model_path = train_and_persist_pipeline(df=df, save_path=save_path)
        print(f"Benchmarking complete. Best model: {benchmark.best_model_name}")
        print(f"Persisted model bundle to: {model_path}")


if __name__ == "__main__":
    main()
