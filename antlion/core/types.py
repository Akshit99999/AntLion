"""
Domain types, enumerations, and data classes for Antlion.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackCategory(str, Enum):
    RECON_SCAN = "Reconnaissance / PortScan"
    CREDENTIAL_BRUTE_FORCE = "Credential Brute-Force"
    WEB_EXPLOIT = "Web Application Attack"
    COMMAND_INJECTION = "Command Injection & Shell Tampering"
    MALWARE_DROPPER = "Malware Dropper / Payload Delivery"
    DENIAL_OF_SERVICE = "Denial of Service"
    BOTNET_PROBE = "Autonomous Botnet / Worm Probe"
    EVASIVE_INTRUSION = "Evasive Decoy Intrusion"
    UNKNOWN_MALICIOUS = "Unclassified Malicious Pit Interaction"


class InteractionDepth(str, Enum):
    CONNECTION_PROBE = "connection_probe"
    AUTHENTICATION_ATTEMPT = "auth_attempt"
    AUTHENTICATION_SUCCESS = "auth_success"
    INTERACTIVE_COMMANDS = "interactive_commands"
    PAYLOAD_DELIVERY = "payload_delivery"
    WEB_ENDPOINT_PROBE = "web_endpoint_probe"
    WEB_EXPLOIT_PAYLOAD = "web_exploit_payload"


class DecoyServiceType(str, Enum):
    SSH = "SSH"
    TELNET = "TELNET"
    WEB_ADMIN = "WEB_ADMIN"
    GENERIC = "GENERIC"


@dataclass
class DecoyEvent:
    """Telemetry captured directly from decoy pit services."""
    source_ip: str
    source_port: int
    target_service: DecoyServiceType
    depth: InteractionDepth
    event_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    commands: List[str] = field(default_factory=list)
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_headers: Dict[str, str] = field(default_factory=dict)
    http_payload: Optional[str] = None
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "target_service": self.target_service.value,
            "depth": self.depth.value,
            "event_timestamp": self.event_timestamp.isoformat(),
            "session_id": self.session_id,
            "username": self.username,
            "password": self.password,
            "commands": self.commands,
            "http_method": self.http_method,
            "http_path": self.http_path,
            "http_headers": self.http_headers,
            "http_payload": self.http_payload,
            "raw_metadata": self.raw_metadata,
        }


@dataclass
class FlowRecord:
    """Network flow metadata and extracted CIC-IDS2017 style features."""
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    features: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "timestamp": self.timestamp.isoformat(),
            "features": self.features,
        }


@dataclass
class MLPrediction:
    """Output from the trained flow classification engine."""
    model_name: str
    predicted_category: str
    confidence: float
    probabilities: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "predicted_category": self.predicted_category,
            "confidence": round(self.confidence, 4),
            "probabilities": {k: round(v, 4) for k, v in self.probabilities.items()},
        }


@dataclass
class HeuristicMatch:
    """Evaluation result from behavioral heuristics."""
    rule_id: str
    rule_name: str
    score: float  # Value between 0.0 and 1.0
    severity: SeverityLevel
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "score": round(self.score, 4),
            "severity": self.severity.value,
            "description": self.description,
            "metadata": self.metadata,
        }


@dataclass
class ContributingSignals:
    """Explainable diagnostic signals synthesizing the final verdict."""
    decoy_signal: Dict[str, Any]
    ml_signal: Optional[Dict[str, Any]]
    heuristic_signals: List[Dict[str, Any]]
    congruence_factor: float
    depth_multiplier: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decoy_signal": self.decoy_signal,
            "ml_signal": self.ml_signal,
            "heuristic_signals": self.heuristic_signals,
            "congruence_factor": round(self.congruence_factor, 4),
            "depth_multiplier": round(self.depth_multiplier, 4),
        }


@dataclass
class Verdict:
    """Unified intrusion classification and threat attribution verdict."""
    verdict_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str = ""
    target_service: str = ""
    attack_type: AttackCategory = AttackCategory.UNKNOWN_MALICIOUS
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence: float = 0.0
    contributing_signals: Optional[ContributingSignals] = None
    raw_evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict_id": self.verdict_id,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "target_service": self.target_service,
            "attack_type": self.attack_type.value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "contributing_signals": (
                self.contributing_signals.to_dict()
                if self.contributing_signals
                else None
            ),
            "raw_evidence": self.raw_evidence,
        }
