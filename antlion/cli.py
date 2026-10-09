"""
Main command-line interface entry point for Antlion.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import uvicorn

from antlion.classification.benchmark import train_and_persist_pipeline
from antlion.core.config import DEFAULT_CONFIG
from antlion.decoys.ssh_telnet.server import InteractiveDecoyServer
from antlion.decoys.web.server import WebDecoyServer
from antlion.query.api import create_query_api
from antlion.query.cli import handle_query_intel, handle_query_stats, handle_query_verdicts
from antlion.storage.database import AntlionDatabase
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

    # Train subcommand
    train_parser = subparsers.add_parser("train", help="Train and benchmark flow classifiers")
    train_parser.add_argument("--data", default=None, help="Path to labeled CSV dataset")
    train_parser.add_argument("--save-path", default=None, help="Path to save best model")

    # Info subcommand
    subparsers.add_parser("info", help="Display Antlion platform configuration")

    return parser


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
        print(f"API Key:         {'configured' if config.api_key else 'NOT SET (unprotected)'}")
        return

    if args.subcommand == "decoy":
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
