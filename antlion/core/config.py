"""
Configuration management for Antlion decoys, classifiers, and verdict engine.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


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

    # Decoy Settings
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    ssh_host: str = "0.0.0.0"
    ssh_port: int = 2222
    telnet_host: str = "0.0.0.0"
    telnet_port: int = 2323

    # Query API Settings
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # Capture Settings
    pcap_dir: str = "pcaps"
    pcap_rotate_seconds: int = 300
    pcap_max_size_mb: int = 50

    # ML Classifier Settings
    model_path: str = "models/antlion_classifier.joblib"

    # Sub-configs
    scoring: ScoringWeights = field(default_factory=ScoringWeights)
    heuristics: HeuristicConfig = field(default_factory=HeuristicConfig)

    def get_db_path(self) -> Path:
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


# Global default configuration instance
DEFAULT_CONFIG = AntlionConfig()
