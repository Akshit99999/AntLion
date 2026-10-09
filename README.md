# Antlion

### Honeypot-Based Intrusion Detection and Multi-Signal Attack Classification System

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Architecture: Defensive IDS](https://img.shields.io/badge/Security-Passive%20Defensive-green.svg)](#concept--philosophy)

> **Antlion** is a defensive security research platform. Like the predatory insect larva that digs a conical sand pit to ambush prey, Antlion operates decoy services — **the "pit"** — where any inbound connection is inherently malicious ground truth. Captured traffic and application interactions are transformed into flow-level features, classified by machine learning, cross-evaluated against behavioral heuristics, and fused by a multi-signal **Verdict Engine**.

---

## Table of Contents

- [Concept & Philosophy](#concept--philosophy)
- [Architecture](#architecture)
- [Components](#components)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [CLI Reference](#cli-reference)
- [REST API](#rest-api)
- [Security Model](#security-model)
- [Development](#development)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)

---

## Concept & Philosophy

Traditional IDS suffer from high false-positive rates because they must separate legitimate production traffic from malicious activity.

**Antlion inverts this:**

- Decoys have **no production purpose** and **no legitimate users**.
- Any connection to an Antlion decoy is **inherently malicious ground truth** ($P(\text{malicious}) \approx 1.0$).
- Flow dynamics alone can be ambiguous and signatures can be bypassed, so Antlion merges **flow features (ML)**, **trap telemetry (ground truth)**, and **session behavior (heuristics)** into explainable verdicts.

---

## Architecture

```
                 [ Attacker / Internet Scanner ]
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       [ TCP/IP Network Flow ]         [ Decoy Services ]
               │                        (The "Pit")
       ┌───────┴───────┐               ┌───────┬───────┐
       ▼               ▼               ▼       ▼       ▼
 [ Rotating PCAP ] [ Raw Packets ] [ SSH ] [ Web ] [ Telnet ]
       │                               │       │       │
       ▼                               └───────┴───────┘
 [ Flow Feature Extractor ]                     │
 (CIC-IDS2017 format)                            ▼
       │                              [ Interactive Session &
       ▼                                Payload Logging ]
 [ ML Classifier ]                             │
 (RF / Baseline / XGB)                          ▼
       │                        [ Behavioral Heuristic Engine ]
       │                        (rate limits, bad creds, UA, commands)
       │                               │
       └───────────────┬───────────────┘
                       ▼
             ╔═════════════════════╗
             ║   VERDICT ENGINE    ║  Tri-signal fusion, interaction-depth
             ╚═════════════════════╝  scoring, congruence bonus
                       │
                       ▼
           [ SQLite Event Store ]
                       │
           ┌───────────┴───────────┐
           ▼                       ▼
    [ Antlion CLI ]        [ REST API + SOC Dashboard ]
                                     │
                                     ▼
                            [ Alert Dedup / Suppress ]
                                     │
                                     ▼
                            [ SIEM / Slack / Discord ]
```

---

## Components

### 1. Decoy Layer — the Pit

| Module | Purpose |
|---|---|
| `decoys/web/app.py` | FastAPI admin-portal honeypot. Captures full request metadata and serves deception traps (`.env`, `.git/config`, AWS IMDS, GraphQL). |
| `decoys/ssh_telnet/server.py` | Threaded interactive shell decoy simulating an Ubuntu host. |
| `decoys/ssh_telnet/filesystem.py` | In-memory Linux filesystem with realistic command emulation and payload fingerprinting (SHA-256). |
| `decoys/ssh_telnet/banner.py` | Plausible SSH banners and MOTD generation. |

### 2. Capture Layer

| Module | Purpose |
|---|---|
| `capture/flow_extractor.py` | Converts packets/PCAPs into CIC-IDS2017-style flow features. |
| `capture/live.py` | `LiveCapturePipeline` correlates sliding-window flows with decoy telemetry and runs ML inference. |

### 3. Classification Engine

| Module | Purpose |
|---|---|
| `classification/inference.py` | `FlowClassifier` — supervised prediction with a heuristic baseline fallback. |
| `classification/anomaly.py` | `FlowAnomalyDetector` — Isolation Forest for zero-day flow novelty. |
| `classification/dataset.py` | Dataset loading and preprocessing. |
| `classification/benchmark.py` | Trains and compares multiple models, persists the winner. |

### 4. Verdict Engine

| Module | Purpose |
|---|---|
| `verdict/scoring.py` | `MultiSignalScorer` — the Tri-Signal Fusion algorithm. |
| `verdict/heuristics.py` | `BehavioralHeuristicsEngine` — credential dictionaries, UA patterns, command/web signatures. |
| `verdict/engine.py` | Orchestrates telemetry → heuristics → fusion → persistence → alerting. |

### 6. Alert Suppression

A public-facing decoy receives constant scanning traffic. Without suppression a
single credential-stuffing host can emit thousands of identical `HIGH` alerts
and bury the real ones.

`alerts/dedup.py` collapses repeats by `(source_ip, attack_type)` within a
sliding window, then emits **one summary alert** carrying the occurrence count:

- Summaries retain the **peak severity** and **peak confidence** of the window,
  so a critical event is never downgraded by surrounding noise.
- Matured summaries are released even under continuous traffic.
- Webhook and CEF messages are annotated: `Suppressed 412 similar intrusions`.
- Thread-safe; stats exposed via `dedup.stats.to_dict()`.

```bash
ANTLION_ALERT_DEDUP_WINDOW_SEC=900   # aggregate for 15 minutes
ANTLION_ALERT_DEDUP_ENABLED=false    # send every alert verbatim
```

### 5. Data & Query Layer

| Module | Purpose |
|---|---|
| `storage/database.py` | Thread-safe SQLite persistence and aggregation. |
| `intel/enricher.py` | IP geolocation/ASN enrichment with offline fallback. |
| `query/api.py` | FastAPI REST interface (API-key protected). |
| `query/dashboard.py` | Self-contained SOC dashboard (charts, threat feed, IP dossier). |
| `alerts/dispatcher.py` | CEF logging plus Slack/Discord/generic webhook delivery. |

### Scoring, briefly

```
raw   = w_decoy·1.0 + w_ml·ml_conf + w_heur·heur_score
final = clamp(depth_multiplier · raw + congruence_bonus, 0.35, 1.0)
```

`heur_score` uses probabilistic saturation, `1 − Π(1 − scoreᵢ)`, so weak rules cannot sum to certainty. `congruence_bonus` rewards independently-derived signals that agree. When ML is absent, its weight is redistributed to the remaining signals.

---

## Quick Start

```bash
git clone https://github.com/Akshit99999/AntLion.git
cd AntLion

python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,full]"

# Optional: configure alerting and API auth
cp .env.example .env && $EDITOR .env

# Train a flow classifier (optional — a baseline ships in code)
antlion train --data /path/to/cicids2017.csv

# Run the pieces (separate terminals)
antlion decoy web --port 8080
antlion decoy ssh --port 2222
antlion api --port 8000
```

Open <http://localhost:8000> for the SOC dashboard.

---

## Configuration

Every setting is read from the environment via `AntlionConfig.from_env()`. Unset variables fall back to safe defaults, and malformed values are ignored rather than raising — a bad environment never prevents decoys from starting.

### Variables

| Variable | Default | Description |
|---|---|---|
| `ANTLION_HOME` | `~/.antlion` | Base directory for database, pcaps, and models. |
| `ANTLION_DB_PATH` | `<home>/antlion.db` | Explicit SQLite path. **Overrides** `ANTLION_HOME`. |
| `ANTLION_DISCORD_WEBHOOK` | — | Discord webhook URL. |
| `ANTLION_SLACK_WEBHOOK` | — | Slack incoming webhook URL. |
| `ANTLION_WEBHOOK_URLS` | — | Comma-separated additional targets. |
| `ANTLION_ALERT_SEVERITY` | `HIGH` | Minimum severity to dispatch (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`). |
| `ANTLION_ALERT_DEDUP_WINDOW_SEC` | `300` | Collapse repeats from the same IP + attack class within this window. `0` disables. |
| `ANTLION_ALERT_DEDUP_ENABLED` | `true` | Master switch for alert suppression. |
| `ANTLION_API_KEY` | — | Shared secret for `/api/v1`. **Unset = unauthenticated.** |
| `ANTLION_CORS_ORIGINS` | localhost origins | Comma-separated CORS allowlist. |
| `ANTLION_TRUST_PROXY` | `false` | Honour `X-Forwarded-For` for attribution. |
| `ANTLION_WEB_PORT` | `8080` | Web decoy port. |
| `ANTLION_SSH_PORT` | `2222` | SSH decoy port. |
| `ANTLION_TELNET_PORT` | `2323` | Telnet decoy port. |
| `ANTLION_API_PORT` | `8000` | Query API port. |

Inspect the effective configuration:

```bash
antlion info
```

### Programmatic use

```python
from antlion.core.config import AntlionConfig
from antlion.verdict.engine import VerdictEngine
from antlion.storage.database import AntlionDatabase

config = AntlionConfig.from_env()
engine = VerdictEngine(config=config, db=AntlionDatabase(config.get_db_path()))
```

---

## CLI Reference

```
antlion decoy web  [--host HOST] [--port PORT]
antlion decoy ssh  [--host HOST] [--port PORT] [--hostname NAME]
antlion api        [--host HOST] [--port PORT]
antlion query verdicts [--limit N] [--ip IP] [--severity S] [--json]
antlion query intel   <IP> [--json]
antlion query stats   [--json]
antlion train      [--data CSV] [--save-path PATH]
antlion info
```

---

## REST API

Data routes require `X-API-Key` (or `Authorization: Bearer …`) when `ANTLION_API_KEY` is set. `/api/v1/health` and the dashboard stay public.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/` `/dashboard` | No | SOC dashboard |
| `GET` | `/api/v1/health` | No | Health check |
| `GET` | `/api/v1/verdicts` | Yes | List verdicts (`limit`, `source_ip`, `severity`, `attack_type`) |
| `GET` | `/api/v1/verdicts/{id}` | Yes | Single verdict |
| `GET` | `/api/v1/intel/{ip}` | Yes | Forensic dossier and timeline |
| `GET` | `/api/v1/stats` | Yes | Aggregated statistics |
| `GET` | `/docs` | — | OpenAPI UI |

```bash
curl -H "X-API-Key: $ANTLION_API_KEY" http://localhost:8000/api/v1/stats
```

---

## Security Model

### What Antlion collects

Captured passwords and command history are stored **in plaintext**. This is deliberate — in a honeypot the credentials *are* the evidence, and hashing them would destroy their value as forensic artifacts. The consequence is that the query API must be treated as a secrets-bearing service:

- Always set `ANTLION_API_KEY`.
- Keep the API bound to `127.0.0.1` or behind a VPN unless the key is set.
- Never use a wildcard CORS origin.

### Deployment guidance

- Run decoys in an isolated VLAN or container network with no route to production.
- Decoys are **not** hardened services. Never place real credentials on the host.
- Canary tokens served by the web decoy (`.env`, AWS IMDS) are fake by design and are safe to expose.
- Capture requires elevated privileges (`tcpdump`/`AF_PACKET`). Prefer a dedicated network namespace or container with only the capture capability granted.

### Resource bounds

Because decoys face the open internet, every unbounded structure is capped:

| Bound | Default | Purpose |
|---|---|---|
| SSH decoy `max_connections` | 200 | Excess connections are refused rather than spawning threads. Slots are reclaimed when a session ends. |
| SSH decoy `idle_timeout` | 60s | Idle sessions cannot be held open indefinitely. |
| Live capture `max_tracked_flows` | 50000 | Enforced on ingest *and* on prune, so a burst between prunes cannot balloon memory. |
| Live capture pruner | 30s | Background thread; pruning runs automatically. |
| Alert dedup window | 300s | See [Alert Suppression](#6-alert-suppression). |

`LiveCapturePipeline` starts its pruner on construction; call `stop_pruner()` on shutdown.

### Known limitations

- The SSH/Telnet decoy emulates a plain protocol; it does not implement real SSH key exchange.
- The database grows unbounded without a retention job (see `ANTLION_RETENTION_DAYS`).

---

## Development

```bash
pip install -e ".[dev,full]"

python -m pytest tests/ -q            # 59 tests
python -m pytest tests/ -q -k hardening

ruff check antlion tests              # if available
```

### Layout

```
antlion/
  core/         types, enums, configuration
  decoys/       web + ssh/telnet honeypots
  capture/      flow extraction and live correlation
  classification/ ML inference, anomaly detection, benchmarking
  verdict/      scoring fusion, heuristics, orchestration
  intel/        IP enrichment
  alerts/       SIEM/webhook dispatch
  storage/      SQLite persistence
  query/        REST API, CLI query layer, dashboard
tests/
```

### Contributing

Branch per change, Conventional Commit messages, and open a PR. CI must be green before merge.

---

## Deployment

```bash
cp .env.example .env    # set ANTLION_API_KEY and webhooks
docker compose up -d
```

| Service | Port | Role |
|---|---|---|
| `antlion-api` | 8000 | REST API + dashboard |
| `antlion-web-decoy` | 8080 | Web honeypot |
| `antlion-ssh-decoy` | 2222 | SSH honeypot |

All three share the `antlion-data` volume holding the SQLite database.

---

## Troubleshooting

**No alerts are firing.** Check `antlion info` — `Alert Webhooks` must be non-zero. Webhooks are read from the environment; if you started Docker Compose without a populated `.env`, the variables resolve to empty strings.

**`/api/v1/*` returns 401.** Send `X-API-Key`, or unset `ANTLION_API_KEY` to disable auth (localhost only).

**Dashboard is empty.** Decoys write to the database at `ANTLION_DB_PATH`. Confirm the API and decoy containers share the same volume and that the path resolves identically in both.

**A legitimate scan is classified as exploitation.** Interaction-depth heuristics are tuned to be conservative. Adjust `ScoringWeights.depth_weights` in `core/config.py` and add a regression test.

---

## License

MIT — see [LICENSE](LICENSE).