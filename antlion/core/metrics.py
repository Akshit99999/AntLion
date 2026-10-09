"""
Lightweight Prometheus-compatible metrics registry for Antlion.

Emits the Prometheus text exposition format directly, avoiding a hard
dependency on ``prometheus_client`` for what is a small, fixed set of
counters and gauges.

Two metric sources are combined:

* **Process counters** — incremented in-process as verdicts are produced
  (severity, attack class, service, decoy depth, alert delivery results).
* **Database gauges** — read at scrape time, since they reflect persisted
  state rather than lifetime deltas (total verdicts, distinct attackers,
  flow count, dedup suppression ratio).
"""

from __future__ import annotations

import threading
from typing import Dict, Iterable, List, Optional, Tuple

from antlion.core.types import SeverityLevel


def _escape_label(value: str) -> str:
    """Escapes a Prometheus label value per the exposition format spec."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def _format_float(value: float) -> str:
    """Renders a float without a trailing '.0' for whole numbers."""
    if value == int(value):
        return str(int(value))
    return repr(round(float(value), 6))


class MetricsRegistry:
    """Thread-safe counters and gauges exposed in Prometheus text format."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # metric name -> list of (labels tuple, value)
        self._counters: Dict[str, List[Tuple[Tuple[str, str], float]]] = {}
        # metric name -> (help text, type)
        self._help: Dict[str, str] = {}
        self._types: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, name: str, help_text: str, metric_type: str = "counter") -> None:
        """Declares a metric so it appears in the output even at zero."""
        with self._lock:
            self._help[name] = help_text
            self._types[name] = metric_type
            self._counters.setdefault(name, [])

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        """Increments a counter, optionally with labels."""
        if not name:
            return
        key = tuple(sorted(labels.items()))
        with self._lock:
            series = self._counters.setdefault(name, [])
            for existing_key, existing_val in series:
                if existing_key == key:
                    series[series.index((existing_key, existing_val))] = (
                        existing_key,
                        existing_val + value,
                    )
                    return
            series.append((key, value))

    def set(self, name: str, value: float, **labels: str) -> None:
        """Sets a gauge to an absolute value."""
        key = tuple(sorted(labels.items()))
        with self._lock:
            series = self._counters.setdefault(name, [])
            for i, (existing_key, _) in enumerate(series):
                if existing_key == key:
                    series[i] = (existing_key, value)
                    return
            series.append((key, value))

    def get(self, name: str, **labels: str) -> float:
        """Reads a single series value (0.0 when absent)."""
        key = tuple(sorted(labels.items()))
        with self._lock:
            for existing_key, existing_val in self._counters.get(name, []):
                if existing_key == key:
                    return existing_val
        return 0.0

    def value(self, name: str, **labels: str) -> Optional[float]:
        """Alias of get() kept for readability at call sites."""
        return self.get(name, **labels)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def render(self) -> str:
        """Renders the registry in Prometheus text exposition format."""
        lines: List[str] = []

        with self._lock:
            snapshot = {
                name: list(series) for name, series in self._counters.items()
            }
            help_map = dict(self._help)
            type_map = dict(self._types)

        for name in sorted(snapshot):
            series = snapshot[name]

            if name in help_map:
                lines.append(f"# HELP {name} {help_map[name]}")
            if name in type_map:
                lines.append(f"# TYPE {name} {type_map[name]}")

            if not series:
                continue

            for labels, value in sorted(series, key=lambda item: item[0]):
                if labels:
                    rendered = ",".join(
                        f'{k}="{_escape_label(v)}"' for k, v in labels
                    )
                    lines.append(f"{name}{{{rendered}}} {_format_float(value)}")
                else:
                    lines.append(f"{name} {_format_float(value)}")

            lines.append("")

        return "\n".join(lines) + "\n"


# Global registry shared by the verdict engine and query API.
REGISTRY = MetricsRegistry()


def register_default_metrics(registry: MetricsRegistry = REGISTRY) -> MetricsRegistry:
    """Declares the standard Antlion metric set."""
    registry.register(
        "antlion_verdicts_total", "Verdicts produced, by severity and attack class",
        "counter",
    )
    registry.register(
        "antlion_decoy_events_total", "Raw decoy events captured, by service and depth",
        "counter",
    )
    registry.register(
        "antlion_decoy_connections_active", "Currently open decoy sessions", "gauge",
    )
    registry.register(
        "antlion_decoy_connections_rejected_total",
        "Decoy connections refused because the connection cap was reached",
        "counter",
    )
    registry.register(
        "antlion_alerts_delivered_total", "Alert webhook deliveries, by result", "counter",
    )
    registry.register(
        "antlion_alerts_suppressed_total", "Alerts collapsed by deduplication", "gauge",
    )
    registry.register(
        "antlion_alerts_emitted_total", "Alerts actually dispatched", "gauge",
    )
    registry.register(
        "antlion_verdict_confidence", "Most recent verdict confidence, by attack class",
        "gauge",
    )
    registry.register(
        "antlion_flows_tracked", "Flow accumulators currently retained in memory", "gauge",
    )
    registry.register(
        "antlion_ip_flow_cache_entries",
        "Per-IP correlation cache entries currently retained",
        "gauge",
    )
    registry.register(
        "antlion_verdicts_stored", "Verdicts persisted in the event store", "gauge",
    )
    registry.register(
        "antlion_distinct_attackers", "Distinct source IPs with recorded verdicts", "gauge",
    )
    registry.register(
        "antlion_decoy_events_stored", "Decoy events persisted in the event store", "gauge",
    )
    registry.register(
        "antlion_flow_records_stored", "Network flow records persisted", "gauge",
    )
    return registry


register_default_metrics()


def record_verdict(
    severity: SeverityLevel,
    attack_type: str,
    confidence: float,
    registry: MetricsRegistry = REGISTRY,
) -> None:
    """Records a produced verdict as a counter increment plus a confidence gauge."""
    registry.inc(
        "antlion_verdicts_total",
        severity=severity.value,
        attack_type=attack_type,
    )
    registry.set(
        "antlion_verdict_confidence", confidence, attack_type=attack_type
    )


def record_decoy_event(
    service: str,
    depth: str,
    registry: MetricsRegistry = REGISTRY,
) -> None:
    """Records a captured decoy event."""
    registry.inc(
        "antlion_decoy_events_total", service=service, depth=depth
    )


def record_alert_delivery(
    result: str, registry: MetricsRegistry = REGISTRY
) -> None:
    """Records a webhook delivery attempt as 'success' or 'failure'."""
    registry.inc("antlion_alerts_delivered_total", result=result)


def record_alert_suppression(
    registry: MetricsRegistry = REGISTRY,
) -> None:
    """Records that one alert was collapsed by deduplication."""
    registry.inc("antlion_alerts_suppressed_total")


def refresh_suppression_gauge(
    emitted: int, suppressed: int, registry: MetricsRegistry = REGISTRY
) -> None:
    """Publishes cumulative dedup counters as gauges.

    Counters are aggregated rather than incremented per call because the
    deduplicator owns the authoritative totals; mirroring them keeps a single
    source of truth instead of double-counting across scrapes.
    """
    registry.set("antlion_alerts_emitted_total", emitted)
    registry.set("antlion_alerts_suppressed_total", suppressed)


def set_database_gauges(
    registry: MetricsRegistry,
    total_verdicts: int,
    distinct_attackers: int,
    decoy_events: int,
    flow_records: int,
) -> None:
    """Refreshes gauges derived from persisted state at scrape time."""
    registry.set("antlion_verdicts_stored", total_verdicts)
    registry.set("antlion_distinct_attackers", distinct_attackers)
    registry.set("antlion_decoy_events_stored", decoy_events)
    registry.set("antlion_flow_records_stored", flow_records)