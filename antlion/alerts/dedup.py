"""
Alert deduplication and suppression for high-volume honeypot deployments.

A public-facing decoy receives constant scanning traffic. Without suppression,
a single host running a credential-stuffing loop can emit thousands of identical
HIGH/CRITICAL alerts and drown the SIEM, causing real incidents to be missed.

This module collapses repeats within a sliding window and emits one summary
alert per window per key, carrying the occurrence count.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from antlion.core.types import SeverityLevel, Verdict


@dataclass
class DedupStats:
    """Counters describing deduplication effectiveness."""

    emitted: int = 0
    suppressed: int = 0

    @property
    def total(self) -> int:
        return self.emitted + self.suppressed

    @property
    def suppression_ratio(self) -> float:
        """Fraction of alerts that were suppressed (0.0 - 1.0)."""
        if self.total == 0:
            return 0.0
        return self.suppressed / self.total

    def to_dict(self) -> Dict[str, float]:
        return {
            "emitted": self.emitted,
            "suppressed": self.suppressed,
            "total": self.total,
            "suppression_ratio": round(self.suppression_ratio, 4),
        }


@dataclass
class _PendingAlert:
    """A suppressed alert awaiting summary emission at the window boundary."""

    first_seen: float
    last_seen: float
    count: int
    peak_severity: SeverityLevel
    peak_confidence: float
    latest: Verdict = field(repr=False, default=None)  # type: ignore[assignment]


class AlertDeduplicator:
    """Collapses repeated alerts by (source_ip, attack_type) within a window.

    Thread-safe: the alert dispatcher is invoked from request-handling threads
    and background workers concurrently.
    """

    SEVERITY_ORDER: Dict[SeverityLevel, int] = {
        SeverityLevel.LOW: 1,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.HIGH: 3,
        SeverityLevel.CRITICAL: 4,
    }

    def __init__(
        self,
        window_seconds: float = 300.0,
        enabled: bool = True,
        time_source=None,
    ):
        self.window_seconds = window_seconds
        self.enabled = enabled
        self._now = time_source or time.monotonic
        self._lock = threading.Lock()
        self._pending: Dict[Tuple[str, str], _PendingAlert] = {}
        # Summaries matured inside check() awaiting collection by the caller.
        self._ready: List[Verdict] = []
        self.stats = DedupStats()

    @staticmethod
    def _key(verdict: Verdict) -> Tuple[str, str]:
        """Deduplication key: same attacker performing the same attack class."""
        return (verdict.source_ip, verdict.attack_type.value)

    def check(self, verdict: Verdict) -> Tuple[bool, int]:
        """Decides whether a verdict should be delivered now.

        Returns ``(should_emit, occurrence_count)``. When ``should_emit`` is
        False the verdict is folded into a pending summary that will be emitted
        once the window expires.
        """
        if not self.enabled or self.window_seconds <= 0:
            return True, 1

        key = self._key(verdict)
        now = self._now()

        with self._lock:
            # Emit any window that has elapsed before deciding on this one, so
            # summaries are never starved by continuous traffic. Matured
            # summaries are returned rather than dropped so the caller can
            # dispatch them.
            matured = self._flush_expired_locked(now)

            pending = self._pending.get(key)

            if pending is None:
                self._pending[key] = _PendingAlert(
                    first_seen=now,
                    last_seen=now,
                    count=1,
                    peak_severity=verdict.severity,
                    peak_confidence=verdict.confidence,
                    latest=verdict,
                )
                self.stats.emitted += 1
                self._ready.extend(matured)
                return True, 1

            pending.count += 1
            pending.last_seen = now
            # Retain whichever verdict carries the richer evidence so a
            # summary never loses signal detail present in an earlier alert.
            if (
                pending.latest.contributing_signals is None
                and verdict.contributing_signals is not None
            ):
                pending.latest = verdict

            rank = self.SEVERITY_ORDER.get(verdict.severity, 1)
            current_rank = self.SEVERITY_ORDER.get(pending.peak_severity, 1)
            if rank > current_rank:
                pending.peak_severity = verdict.severity
            pending.peak_confidence = max(
                pending.peak_confidence, verdict.confidence
            )

            self.stats.suppressed += 1
            self._ready.extend(matured)
            return False, pending.count

    def flush_expired(self) -> List[Verdict]:
        """Returns summary verdicts for windows that have elapsed.

        Includes summaries matured during an earlier ``check()`` call so nothing
        is lost when a caller only polls periodically.
        """
        with self._lock:
            matured = self._flush_expired_locked(self._now())
            ready = self._ready + matured
            self._ready = []
            return ready

    def _flush_expired_locked(self, now: float) -> List[Verdict]:
        """Emits summaries for elapsed windows. Caller must hold the lock."""
        summaries: List[Verdict] = []

        for key, pending in list(self._pending.items()):
            if now - pending.first_seen < self.window_seconds:
                continue

            del self._pending[key]
            summary = self._build_summary(pending)
            summaries.append(summary)
            self.stats.emitted += 1

        return summaries

    def _build_summary(self, pending: _PendingAlert) -> Verdict:
        """Builds a summary verdict representing a collapsed window."""
        base = pending.latest
        count = pending.count

        summary = Verdict(
            source_ip=base.source_ip,
            target_service=base.target_service,
            attack_type=base.attack_type,
            severity=pending.peak_severity,
            confidence=pending.peak_confidence,
        )

        signals = base.contributing_signals
        if signals is not None:
            from antlion.core.types import ContributingSignals

            summary.contributing_signals = ContributingSignals(
                decoy_signal={
                    **signals.decoy_signal,
                    "suppressed_count": count,
                    "summary_alert": True,
                },
                ml_signal=signals.ml_signal,
                heuristic_signals=signals.heuristic_signals,
                congruence_factor=signals.congruence_factor,
                depth_multiplier=signals.depth_multiplier,
            )

        summary.raw_evidence = {
            **base.raw_evidence,
            "suppressed_count": count,
            "summary_alert": True,
            "window_seconds": self.window_seconds,
        }

        return summary

    def pending_count(self) -> int:
        """Number of alerts currently held in open windows."""
        with self._lock:
            return len(self._pending)

    def reset(self) -> None:
        """Clears all pending state and counters."""
        with self._lock:
            self._pending.clear()
            self._ready.clear()
            self.stats = DedupStats()