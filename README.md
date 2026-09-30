# Antlion 🐜🦁
### Honeypot-Based Intrusion Detection and Multi-Signal Attack Classification System

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Architecture: Defensive IDS](https://img.shields.io/badge/Security-Passive%20Defensive-green.svg)](#concept--philosophy)

> **Antlion** is an original defensive security research platform. Like the predatory insect larva that digs a conical sand pit to ambush prey, Antlion operates decoy services—**the "pit"**—where any inbound connection represents inherently malicious ground truth. Captured network traffic and application interactions are transformed into flow-level features, classified by machine learning models, cross-evaluated against behavioral heuristics, and synthesized through a multi-signal **Verdict Engine**.

---

## Table of Contents
1. [Concept & Philosophy](#concept--philosophy)
2. [System Architecture](#system-architecture)
3. [Component Breakdown](#component-breakdown)
   - [Decoy Layer (The Pit)](#1-decoy-layer-the-pit)
   - [Capture Layer](#2-capture-layer)
   - [Classification Engine](#3-classification-engine)
   - [Verdict Engine](#4-verdict-engine)
   - [Data & Query Layer](#5-data--query-layer)
4. [Cloud Deployment & Isolation Guide (EC2 Setup)](#cloud-deployment--isolation-guide-ec2-setup)
5. [Safe Defensive Operating Instructions](#safe-defensive-operating-instructions)
6. [Getting Started & Installation](#getting-started--installation)
7. [API & CLI Query Interface](#api--cli-query-interface)

---

## Concept & Philosophy

Traditional Intrusion Detection Systems (IDS) suffer from high false-positive rates because they must differentiate between legitimate business traffic and malicious activity within production environments. 

**Antlion flips this paradigm:**
- Decoys have **no production purpose** and **no legitimate users**.
- Any connection to an Antlion decoy is **inherently malicious ground truth ($P(\text{malicious}) \approx 1.0$)**.
- Network flow dynamics alone can be ambiguous, and signature matching can be bypassed. However, by merging **network flow features (ML)**, **trap telemetry (Ground Truth)**, and **session behavior (Heuristics)**, Antlion produces high-fidelity, explainable verdicts without false alarms.

---

## System Architecture

```
                 [ Attacker / Internet Scanner ]
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       [ TCP/IP Network Flow ]         [ Decoy Services ]
       (libpcap / tcpdump)              (The "Pit")
               │                               │
       ┌───────┴───────┐               ┌───────┴───────┐
       ▼               ▼               ▼               ▼
 [ Rotating PCAP ] [ Raw Packets ] [ SSH Decoy ]  [ Web Decoy ]
       │                               │               │
       ▼                               │               │
 [ Flow Feature Extractor ]            │               │
 (CIC-IDS2017 Format)                  │               │
       │                               ▼               ▼
       ▼                     [ Interactive Session & Payload Logs ]
 [ ML Classifier Engine ]              │               │
 (RF / Baseline / XGB)                 │               │
       │                               ▼               ▼
       │                     [ Behavioral Heuristic Engine ]
       │                     (Rate limits, bad creds, UA, commands)
       │                               │
       └───────────────┬───────────────┘
                       ▼
             ╔═════════════════════╗
             ║   VERDICT ENGINE    ║  <-- Multi-signal confidence fusion,
             ╚═════════════════════╝      interaction-depth scoring & persistence
                       │
                       ▼
           [ SQLite / DB Event Store ]
                       │
           ┌───────────┴───────────┐
           ▼                       ▼
    [ Antlion CLI ]        [ REST API Seam ]
```

---

## Component Breakdown

### 1. Decoy Layer (The Pit)
- **SSH / Telnet Decoy**: Emulates a Linux server with custom realistic banners, randomized pseudo-filesystem, simulated shell command responses (`uname`, `id`, `cat /etc/passwd`, `ifconfig`, `ps`, `iptables`), and zero stock Cowrie fingerprints. Logs full credential pairs, typed keystrokes, and downloaded payload URLs.
- **Web Admin Decoy**: An internal-looking administration and management portal (`InfraOps Gateway`) exposing realistic, enticing endpoints (`/login`, `/api/v1/debug`, `/config/backup`, `/health`). Captures client IP, HTTP headers, User-Agent, traversal attempts, SQL injection probes, and payloads.

### 2. Capture Layer
- **Passive PCAP Rotation**: Runs a background `tcpdump` rotation service with capped ring-buffer sizes and automatic compression.
- **Flow Feature Extraction**: Pure-Python / Scapy-based network flow feature extractor emitting CIC-IDS2017 compliant statistics (Flow Duration, Fwd/Bwd Packet Counts, Flow Bytes/s, Flow Packets/s, Inter-Arrival Times [mean, std, min, max], Flag counts [SYN, FIN, RST, PSH, ACK, URG]).

### 3. Classification Engine
- **Preprocessing Pipeline**: Robust handling of zero-variance features, extreme outliers, missing values, and high class imbalances.
- **Model Benchmarking**: Trains and scores Random Forest, an interpretable baseline classifier, and gradient boosted models (with XGBoost or Scikit-learn GradientBoosting) on flow statistics.
- **Per-Class Metrics**: Precision, Recall, and F1 scoring with persistent serialized model artifacts.
- **Inference Pipeline**: Real-time flow feature consumption outputting predicted attack family and confidence distributions.

### 4. Verdict Engine
- **Original Multi-Signal Fusion Algorithm**: Merges:
  1. *Decoy Interaction Depth*: Handshake vs Auth Failure vs Shell Execution vs Exploit Payload.
  2. *ML Flow Prediction*: Flow-level behavioral fingerprint and class confidence.
  3. *Behavioral Heuristics*: Request burst rates, dictionary credential signatures (Mirai/CVEs), reconnaissance User-Agents, and suspicious command sequences.
- **Weighted Attitudinal Alignment**: Reinforces confidence when independent signals align, and flags evasion anomalies when an attacker operates stealthily on the wire but triggers deep decoy traps.
- **Structured Verdicts**: Stored with timestamp, attacker IP, attack category, composite confidence score, severity rating, and an auditable breakdown of contributing signals.

### 5. Data & Query Layer
- **Central Storage**: Persistent SQLite database storing flow records, decoy interactions, heuristic matches, and final verdicts.
- **REST API (`antlion.query.api`)**: Clean, OpenAPI-documented FastAPI endpoints for querying recent verdicts, IP intelligence, attack trends, and summary metrics.
- **CLI (`antlion query`)**: Terminal command-line tool for security analysts to inspect real-time alerts, search by IP, and export forensic JSON reports.

---

## Cloud Deployment & Isolation Guide (EC2 Setup)

When deploying Antlion in a public cloud provider such as AWS EC2, you must follow strict defensive isolation protocols to ensure the honeypot cannot be pivoted through or compromised:

### 1. Isolated VPC Architecture
- Deploy the honeypot instance inside a dedicated, isolated Virtual Private Cloud (VPC) with **no peering connections**, **no transit gateways**, and **no route to internal/corporate VPCs**.
- Use a dedicated Subnet with an Internet Gateway (IGW) solely for inbound honeypot traffic.

### 2. Locked-Down Security Group
- **Inbound Rules**:
  - `TCP 2222` (or public `22` redirected via iptables) -> `0.0.0.0/0` (Decoy SSH)
  - `TCP 8080` (or public `80`/`443`) -> `0.0.0.0/0` (Decoy Web Admin)
  - `TCP <custom-admin-port>` -> `<YOUR_OFFICE_OR_VPN_IP>/32` ONLY (Management access)
- **Outbound Rules (CRITICAL)**:
  - **Restrict or drop all outbound connections** except essential OS security updates and NTP.
  - Deny outbound traffic to private RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and AWS metadata service (`169.254.169.254`).
  - Block outbound SMTP (`TCP 25, 465, 587`) and DDoS amplification ports to ensure attackers cannot use the decoy as an offensive zombie.

### 3. Identity and Credential Isolation
- Attach **NO IAM Roles** or IAM instance profiles to the EC2 instance.
- Do NOT store cloud credentials, API tokens, production SSH private keys, or sensitive customer data on the machine.
- Decoy credentials presented in the fake filesystem are strictly honey-tokens that trigger alerts if used elsewhere.

---

## Safe Defensive Operating Instructions

1. **Strictly Passive Monitoring**:
   Antlion is engineered exclusively for observation and defensive intelligence gathering. It does not perform active vulnerability scanning, outbound exploitation, or counter-attacks.
2. **Containment & Sandboxing**:
   The interactive shell decoy operates within an in-memory virtual state machine. Keystrokes and downloaded malware URLs are recorded, but commands are never executed on the host operating system kernel.
3. **Log Sanitization**:
   Pay attention to log volume and rotate PCAP captures frequently to avoid disk exhaustion during denial-of-service probes.

---

## Getting Started & Installation

### Requirements
- Python 3.10+
- Linux (Ubuntu/Debian recommended for systemd capture) or macOS (development/testing)
- `tcpdump` / `libpcap` (for live packet capture)

### Installation
```bash
git clone https://github.com/Akshit99999/AntLion.git
cd AntLion
pip install -e .
```

### Running the Decoys
```bash
# Start Web Decoy (default port 8080)
antlion decoy web --port 8080

# Start SSH Decoy (default port 2222)
antlion decoy ssh --port 2222
```

### Starting the Query API & Interactive SOC Dashboard
```bash
antlion api --port 8000
# 🖥️ Interactive SOC Console Dashboard: http://localhost:8000/
# 📖 OpenAPI REST Documentation:       http://localhost:8000/docs
```

### Starting the Live Capture & Flow-Decoy Correlator
```bash
# Ingest live packets in sliding-window batches correlated directly to decoy events
python3 -c "
from antlion.capture.live import LiveCapturePipeline
from antlion.verdict.engine import VerdictEngine
pipeline = LiveCapturePipeline(verdict_engine=VerdictEngine())
print('Live Capture & Correlation Engine Ready.')
"
```

### Real-Time Alerts & Webhooks (Slack / Discord / CEF)
Antlion automatically formats and streams `CRITICAL` and `HIGH` severity verdicts to configured webhooks or SIEM collectors:
```python
from antlion.alerts.dispatcher import AlertDispatcher
from antlion.core.types import SeverityLevel

dispatcher = AlertDispatcher(
    webhook_urls=["https://discord.com/api/webhooks/..."],
    min_severity=SeverityLevel.HIGH
)
```

---

## License
MIT License. Developed for defensive cybersecurity research and threat intelligence.
