"""
Configuration management for Antlion decoys, classifiers, and verdict engine.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class ScoringWeights:
    """Weights and parameters for multi-signal verdict synthesis."""
    # Base signal weights (normalized to 1.0)
    w_decoy: float = 0.45
    w_ml: float = 0.25
    w_heuristics: float = 0.30

    # Interaction depth scale factor
    depth_weights: dict = field(
        default_factory=lambda: {
            "connection_probe": 0.55,
            "auth_attempt": 0.75,
            "web_endpoint_probe": 0.65,
            "web_exploit_payload": 0.90,
            "auth_success": 0.88,
            "interactive_commands": 0.96,
            "payload_delivery": 1.00,
        }
    )

    # Congruence synergy bonus when independent signals reinforce each other
    congruence_bonus: float = 0.12

    # High-confidence threshold
    high_confidence_cutoff: float = 0.82
    critical_confidence_cutoff: float = 0.92


@dataclass
class HeuristicConfig:
    """Thresholds for behavioral heuristics."""
    rate_window_seconds: int = 60
    burst_threshold_per_window: int = 8
    brute_force_failure_threshold: int = 3
    port_scan_unique_ports_threshold: int = 4


def _env_str(key: str, default: str = "") -> str:
    """Reads an environment variable, treating empty/whitespace as unset."""
    raw = os.environ.get(key)
    if raw is None:
        return default
    raw = raw.strip()
    return raw if raw else default


def _env_int(key: str, default: int) -> int:
    """Reads an integer environment variable, falling back on invalid input."""
    raw = _env_str(key)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    """Reads a boolean environment variable (1/true/yes/on are truthy)."""
    raw = _env_str(key).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _env_csv(key: str) -> List[str]:
    """Reads a comma-separated environment variable into a clean list."""
    raw = _env_str(key)
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass
class AntlionConfig:
    """Global configuration for Antlion deployment."""
    # Data directory
    data_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("ANTLION_HOME", Path.home() / ".antlion")
        )
    )
    db_filename: str = "antlion.db"

    # Explicit database path override (ANTLION_DB_PATH). When set, this wins
    # over data_dir/db_filename.
    db_path_override: Optional[Path] = None

    # Decoy Settings
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    ssh_host: str = "0.0.0.0"
    ssh_port: int = 2222
    telnet_host: str = "0.0.0.0"
    telnet_port: int = 2323

    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # Capture Settings
    pcap_dir: str = "pcaps"
    pcap_rotate_seconds: int = 300
    pcap_max_size_mb: int = 50

    # ML Classifier Settings
    model_path: str = "models/antlion_classifier.joblib"

    # ── Alert Dispatch ────────────────────────────────────────────
    # Webhook URLs for SIEM/chat delivery. Every entry receives an alert.
    webhook_urls: List[str] = field(default_factory=list)
    # Minimum severity that triggers an outbound alert.
    min_alert_severity: str = "HIGH"
    # Collapse repeated (source_ip, attack_type) alerts within this window.
    alert_dedup_window_sec: int = 300
    # Master switch for alert deduplication.
    alert_dedup_enabled: bool = True

    # ── Query API Security ───────────────────────────────────────
    # Shared secret required by /api/v1 data routes. None disables auth.
    api_key: Optional[str] = None
    # Explicit CORS allowlist. Never use a wildcard with credentials.
    cors_origins: List[str] = field(default_factory=list)
    # Honour X-Forwarded-For for client IP attribution (only behind a proxy).
    trust_proxy_headers: bool = False

    # Sub-configs
    scoring: ScoringWeights = field(default_factory=ScoringWeights)
    heuristics: HeuristicConfig = field(default_factory=HeuristicConfig)

    def get_db_path(self) -> Path:
        # ANTLION_DB_PATH takes precedence when explicitly configured.
        if self.db_path_override:
            self.db_path_override.parent.mkdir(parents=True, exist_ok=True)
            return self.db_path_override
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / self.db_filename

    def get_pcap_path(self) -> Path:
        pcap_path = self.data_dir / self.pcap_dir
        pcap_path.mkdir(parents=True, exist_ok=True)
        return pcap_path

    def get_model_path(self) -> Path:
        model_path = self.data_dir / self.model_path
        model_path.parent.mkdir(parents=True, exist_ok=True)
        return model_path

    @classmethod
    def from_env(cls) -> "AntlionConfig":
        """Builds a configuration from environment variables.

        Reads ANTLION_HOME, ANTLION_DB_PATH, webhook settings, alert severity,
        API key, CORS origins, and decoy ports. Invalid values fall back to
        safe defaults rather than raising, so a malformed environment never
        prevents the decoys from starting.
        """
        data_dir = Path(_env_str("ANTLION_HOME", str(Path.home() / ".antlion")))

        db_override_raw = _env_str("ANTLION_DB_PATH")
        db_override = Path(db_override_raw).expanduser() if db_override_raw else None

        # Collect webhook targets from both the dedicated Discord/Slack vars
        # and a generic comma-separated list.
        webhook_urls: List[str] = []
        for key in (
            "ANTLION_DISCORD_WEBHOOK",
            "ANTLION_SLACK_WEBHOOK",
            "ANTLION_WEBHOOK_URLS",
        ):
            webhook_urls.extend(_env_csv(key))

        severity = _env_str("ANTLION_ALERT_SEVERITY", "HIGH").upper()
        if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            severity = "HIGH"

        dedup_window = _env_int("ANTLION_ALERT_DEDUP_WINDOW_SEC", 300)
        dedup_enabled = _env_bool("ANTLION_ALERT_DEDUP_ENABLED", True)

        api_key = _env_str("ANTLION_API_KEY") or None

        cors_raw = _env_csv("ANTLION_CORS_ORIGINS")
        if not cors_raw:
            cors_raw = ["http://localhost:8000", "http://127.0.0.1:8000"]

        return cls(
            data_dir=data_dir,
            db_path_override=db_override,
            web_port=_env_int("ANTLION_WEB_PORT", 8080),
            ssh_port=_env_int("ANTLION_SSH_PORT", 2222),
            telnet_port=_env_int("ANTLION_TELNET_PORT", 2323),
            api_port=_env_int("ANTLION_API_PORT", 8000),
            webhook_urls=webhook_urls,
            min_alert_severity=severity,
            alert_dedup_window_sec=dedup_window,
            alert_dedup_enabled=dedup_enabled,
            api_key=api_key,
            cors_origins=cors_raw,
            trust_proxy_headers=_env_bool("ANTLION_TRUST_PROXY", False),
        )


# Global default configuration instance.
# Built from the environment when ANTLION_* variables are present, otherwise
# falls back to library defaults so tests and imports stay predictable.
DEFAULT_CONFIG = AntlionConfig.from_env()
