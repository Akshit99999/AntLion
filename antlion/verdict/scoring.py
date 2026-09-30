"""
Original Tri-Signal Fusion and Attribution Framework (TSFA).

Synthesizes three independent evidence vectors:
1. Decoy Pit Ground-Truth & Interaction Depth
2. ML Network Flow Classifier Confidence & Category
3. Behavioral Heuristics Accumulation & Rule Scoring
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

from antlion.core.config import ScoringWeights
from antlion.core.types import (
    AttackCategory,
    ContributingSignals,
    DecoyEvent,
    HeuristicMatch,
    InteractionDepth,
    MLPrediction,
    SeverityLevel,
    Verdict,
)


class MultiSignalScorer:
    """Core scoring algorithm synthesizing multi-source signals into attack verdicts."""

    def __init__(self, weights: Optional[ScoringWeights] = None):
        self.weights = weights or ScoringWeights()

    def evaluate(
        self,
        decoy_event: DecoyEvent,
        heuristic_matches: List[HeuristicMatch],
        ml_prediction: Optional[MLPrediction] = None,
    ) -> Verdict:
        """Computes composite intrusion confidence, attack classification, and severity."""
        # 1. Decoy interaction depth coefficient
        depth_multiplier = self._compute_depth_multiplier(decoy_event.depth)

        # 2. Behavioral heuristic evidence accumulation (diminishing returns)
        heur_score = self._accumulate_heuristics(heuristic_matches)

        # 3. ML prediction integration
        ml_conf = ml_prediction.confidence if ml_prediction else 0.0

        # Dynamic weight redistribution if ML is absent
        if ml_prediction is None:
            w_decoy = self.weights.w_decoy + (self.weights.w_ml * 0.6)
            w_heur = self.weights.w_heuristics + (self.weights.w_ml * 0.4)
            w_ml = 0.0
        else:
            w_decoy = self.weights.w_decoy
            w_heur = self.weights.w_heuristics
            w_ml = self.weights.w_ml

        # 4. Congruence and cross-signal alignment
        congruence_bonus, is_evasion_detected = self._evaluate_congruence(
            decoy_event, heuristic_matches, ml_prediction
        )

        # 5. Composite Confidence calculation
        raw_score = (w_decoy * 1.0) + (w_ml * ml_conf) + (w_heur * heur_score)
        scaled_score = depth_multiplier * raw_score + congruence_bonus

        # Bounded between 0.35 (pit entry baseline) and 1.0
        final_confidence = max(0.35, min(1.0, scaled_score))

        # 6. Attack Category Resolution
        attack_category = self._resolve_attack_category(
            decoy_event, heuristic_matches, ml_prediction, is_evasion_detected
        )

        # 7. Severity Rating
        severity = self._determine_severity(
            attack_category, decoy_event.depth, final_confidence, heuristic_matches
        )

        # 8. Explainable Contributing Signals
        contributing_signals = ContributingSignals(
            decoy_signal={
                "service": decoy_event.target_service.value,
                "depth": decoy_event.depth.value,
                "ground_truth_malicious": True,
                "commands_count": len(decoy_event.commands),
                "auth_provided": bool(decoy_event.username or decoy_event.password),
            },
            ml_signal=ml_prediction.to_dict() if ml_prediction else None,
            heuristic_signals=[h.to_dict() for h in heuristic_matches],
            congruence_factor=congruence_bonus,
            depth_multiplier=depth_multiplier,
        )

        # Evidence dictionary for forensics
        raw_evidence: Dict[str, Any] = {
            "source_ip": decoy_event.source_ip,
            "source_port": decoy_event.source_port,
            "username": decoy_event.username,
            "commands": decoy_event.commands,
            "http_path": decoy_event.http_path,
            "heuristic_count": len(heuristic_matches),
            "evasion_detected": is_evasion_detected,
        }

        return Verdict(
            source_ip=decoy_event.source_ip,
            target_service=decoy_event.target_service.value,
            attack_type=attack_category,
            severity=severity,
            confidence=final_confidence,
            contributing_signals=contributing_signals,
            raw_evidence=raw_evidence,
        )

    def _compute_depth_multiplier(self, depth: InteractionDepth) -> float:
        """Maps interaction depth to confidence multiplier."""
        return self.weights.depth_weights.get(depth.value, 0.60)

    def _accumulate_heuristics(self, matches: List[HeuristicMatch]) -> float:
        """Accumulates evidence scores with independent probabilistic saturation.

        Formula: 1 - prod(1 - score_i)
        """
        if not matches:
            return 0.0

        product = 1.0
        for match in matches:
            clamped = max(0.0, min(0.99, match.score))
            product *= 1.0 - clamped

        accumulated = 1.0 - product
        return round(min(1.0, accumulated), 4)

    def _evaluate_congruence(
        self,
        event: DecoyEvent,
        heuristics: List[HeuristicMatch],
        ml_prediction: Optional[MLPrediction],
    ) -> Tuple[float, bool]:
        """Calculates synergy bonus or identifies evasive stealth probes."""
        congruence = 0.0
        is_evasion = False

        if not ml_prediction:
            # If heuristics corroborate the specific decoy interaction
            if heuristics:
                if any("CRED" in h.rule_id for h in heuristics) and event.depth in (
                    InteractionDepth.AUTHENTICATION_ATTEMPT,
                    InteractionDepth.AUTHENTICATION_SUCCESS,
                ):
                    return 0.08, False
                if event.depth in (
                    InteractionDepth.INTERACTIVE_COMMANDS,
                    InteractionDepth.WEB_EXPLOIT_PAYLOAD,
                    InteractionDepth.PAYLOAD_DELIVERY,
                ):
                    return 0.08, False
            return 0.0, False

        ml_cat = (ml_prediction.predicted_category or "").lower()

        # Evasion check: ML says benign, but attacker entered commands or dropped payload
        if "benign" in ml_cat:
            if event.depth in (
                InteractionDepth.INTERACTIVE_COMMANDS,
                InteractionDepth.PAYLOAD_DELIVERY,
                InteractionDepth.WEB_EXPLOIT_PAYLOAD,
            ):
                is_evasion = True
                # Ground truth overrides ML blindness
                return 0.05, True

        # Congruence 1: Brute force agreement
        if "brute" in ml_cat and (
            event.depth == InteractionDepth.AUTHENTICATION_ATTEMPT
            or any("CRED" in h.rule_id for h in heuristics)
        ):
            congruence += self.weights.congruence_bonus

        # Congruence 2: Web attack agreement
        if "web" in ml_cat and (
            event.depth == InteractionDepth.WEB_EXPLOIT_PAYLOAD
            or any("WEB_" in h.rule_id for h in heuristics)
        ):
            congruence += self.weights.congruence_bonus

        # Congruence 3: Port scan / Recon agreement
        if "scan" in ml_cat or "port" in ml_cat:
            if event.depth == InteractionDepth.CONNECTION_PROBE or any(
                "SWEEP" in h.rule_id for h in heuristics
            ):
                congruence += self.weights.congruence_bonus

        # Congruence 4: Botnet agreement
        if "botnet" in ml_cat or "worm" in ml_cat:
            if any("BOTNET" in h.rule_id for h in heuristics):
                congruence += self.weights.congruence_bonus

        return min(0.18, congruence), is_evasion

    def _resolve_attack_category(
        self,
        event: DecoyEvent,
        heuristics: List[HeuristicMatch],
        ml_prediction: Optional[MLPrediction],
        is_evasion: bool,
    ) -> AttackCategory:
        """Determines final threat taxonomy based on hierarchical ground-truth evidence."""
        rule_ids = {h.rule_id for h in heuristics}

        # 1. Evasive override
        if is_evasion:
            return AttackCategory.EVASIVE_INTRUSION

        # 2. Malware dropper / payload delivery
        if (
            event.depth == InteractionDepth.PAYLOAD_DELIVERY
            or "CMD_DROPPER_DOWNLOAD" in rule_ids
        ):
            return AttackCategory.MALWARE_DROPPER

        # 3. Interactive command execution & reverse shells
        if "CMD_REVERSE_SHELL" in rule_ids or "CMD_PERSISTENCE" in rule_ids:
            return AttackCategory.COMMAND_INJECTION

        if event.depth == InteractionDepth.INTERACTIVE_COMMANDS:
            return AttackCategory.COMMAND_INJECTION

        # 4. Web Application Exploit
        if (
            event.depth == InteractionDepth.WEB_EXPLOIT_PAYLOAD
            or "WEB_SQL_INJECTION" in rule_ids
            or "WEB_PATH_TRAVERSAL" in rule_ids
            or "WEB_COMMAND_EXEC" in rule_ids
        ):
            return AttackCategory.WEB_EXPLOIT

        # 5. Known Botnet / Automated Worm Probe
        if (
            "RULE_KNOWN_BOTNET_CRED" in rule_ids
            or "RULE_SCANNER_UA" in rule_ids
            or (ml_prediction and "botnet" in ml_prediction.predicted_category.lower())
        ):
            return AttackCategory.BOTNET_PROBE

        # 6. Credential Brute-Force
        if (
            event.depth == InteractionDepth.AUTHENTICATION_ATTEMPT
            or "RULE_DICTIONARY_PASSWORD" in rule_ids
            or (ml_prediction and "brute" in ml_prediction.predicted_category.lower())
        ):
            return AttackCategory.CREDENTIAL_BRUTE_FORCE

        # 7. Denial of Service
        if ml_prediction and (
            "dos" in ml_prediction.predicted_category.lower()
            or "ddos" in ml_prediction.predicted_category.lower()
        ):
            return AttackCategory.DENIAL_OF_SERVICE

        # 8. Web probe
        if event.depth == InteractionDepth.WEB_ENDPOINT_PROBE:
            return AttackCategory.WEB_EXPLOIT

        # 9. Reconnaissance / PortScan
        if (
            event.depth == InteractionDepth.CONNECTION_PROBE
            or "RULE_PORT_SWEEP" in rule_ids
            or "RULE_RATE_BURST" in rule_ids
            or (ml_prediction and "scan" in ml_prediction.predicted_category.lower())
        ):
            return AttackCategory.RECON_SCAN

        return AttackCategory.UNKNOWN_MALICIOUS

    def _determine_severity(
        self,
        category: AttackCategory,
        depth: InteractionDepth,
        confidence: float,
        heuristics: List[HeuristicMatch],
    ) -> SeverityLevel:
        """Determines alert severity level."""
        # Check if any heuristic is critical or high
        has_critical_heur = any(h.severity == SeverityLevel.CRITICAL for h in heuristics)
        if has_critical_heur:
            return SeverityLevel.CRITICAL

        has_high_heur = any(h.severity == SeverityLevel.HIGH for h in heuristics)
        if has_high_heur and confidence >= 0.70:
            return SeverityLevel.HIGH

        # High-impact categories
        if category in (
            AttackCategory.MALWARE_DROPPER,
            AttackCategory.COMMAND_INJECTION,
            AttackCategory.EVASIVE_INTRUSION,
        ):
            return SeverityLevel.CRITICAL if confidence >= 0.85 else SeverityLevel.HIGH

        if category in (
            AttackCategory.WEB_EXPLOIT,
            AttackCategory.CREDENTIAL_BRUTE_FORCE,
            AttackCategory.BOTNET_PROBE,
            AttackCategory.DENIAL_OF_SERVICE,
        ):
            if confidence >= self.weights.critical_confidence_cutoff:
                return SeverityLevel.CRITICAL
            if confidence >= self.weights.high_confidence_cutoff:
                return SeverityLevel.HIGH
            return SeverityLevel.MEDIUM

        if depth == InteractionDepth.CONNECTION_PROBE and confidence < 0.70:
            return SeverityLevel.LOW

        return SeverityLevel.MEDIUM
