"""
Live packet capture and real-time flow-to-decoy correlation pipeline.
Monitors network packets in sliding windows and correlates with decoy pit interactions.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional

from antlion.capture.flow_extractor import FlowFeatureExtractor, PacketMetadata
from antlion.classification.anomaly import FlowAnomalyDetector
from antlion.classification.inference import FlowClassifier
from antlion.core.metrics import REGISTRY
from antlion.core.types import DecoyEvent, FlowRecord, MLPrediction, Verdict
from antlion.verdict.engine import VerdictEngine

logger = logging.getLogger("antlion.capture.live")


class LiveCapturePipeline:
    """Coordinates packet sniffing, flow feature extraction, and decoy session correlation."""

    def __init__(
        self,
        verdict_engine: VerdictEngine,
        classifier: Optional[FlowClassifier] = None,
        anomaly_detector: Optional[FlowAnomalyDetector] = None,
        correlation_window_sec: float = 30.0,
        max_tracked_flows: int = 50000,
        prune_interval_sec: float = 30.0,
        autostart_pruner: bool = True,
        correlation_max_age_sec: float = 300.0,
    ):
        self.verdict_engine = verdict_engine
        self.classifier = classifier or FlowClassifier()
        self.anomaly_detector = anomaly_detector or FlowAnomalyDetector()
        self.correlation_window_sec = correlation_window_sec

        # Upper bound on retained flow state. A public-facing capture sees
        # unbounded distinct 5-tuples, so without a cap the extractor and the
        # per-IP cache grow until the process is OOM-killed.
        self.max_tracked_flows = max_tracked_flows
        # Age bound for per-IP correlation entries, independent of the flow
        # sliding window.
        self._cache_max_age_sec = correlation_max_age_sec

        self.extractor = FlowFeatureExtractor()
        # Maps src_ip -> latest FlowRecord
        self._ip_flow_cache: Dict[str, FlowRecord] = {}
        self._lock = threading.Lock()
        self._is_running = False

        self._prune_interval_sec = prune_interval_sec
        self._stop_event = threading.Event()
        self._pruner_thread: Optional[threading.Thread] = None

        if autostart_pruner:
            self.start_pruner()

    def start_pruner(self) -> None:
        """Starts the background flow-pruning thread.

        Previously prune_stale_flows() had no caller, so a long-running capture
        leaked flow state indefinitely.
        """
        if self._pruner_thread and self._pruner_thread.is_alive():
            return

        self._stop_event.clear()

        def _loop() -> None:
            while not self._stop_event.wait(self._prune_interval_sec):
                try:
                    self.prune_stale_flows()
                except Exception as e:  # never let pruning kill the pipeline
                    logger.warning("Flow pruning failed: %s", e)

        self._pruner_thread = threading.Thread(
            target=_loop, daemon=True, name="AntlionFlowPruner"
        )
        self._pruner_thread.start()
        logger.info(
            "Flow pruner started (interval=%.0fs window=%.0fs max_flows=%d)",
            self._prune_interval_sec,
            self.correlation_window_sec,
            self.max_tracked_flows,
        )

    def stop_pruner(self) -> None:
        """Signals the pruning thread to exit."""
        self._stop_event.set()
        if self._pruner_thread and self._pruner_thread.is_alive():
            self._pruner_thread.join(timeout=5.0)
        self._pruner_thread = None

    def ingest_packet(self, pkt: PacketMetadata) -> None:
        """Ingests a packet, updates flow accumulator, and refreshes IP cache."""
        with self._lock:
            self.extractor.process_packet(pkt)
            fwd_key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
            flow_acc = self.extractor.flows.get(fwd_key)
            if flow_acc:
                features = flow_acc.compute_features()
                rec = FlowRecord(
                    flow_id=f"{pkt.src_ip}:{pkt.src_port}->{pkt.dst_ip}:{pkt.dst_port}/{pkt.protocol}",
                    src_ip=pkt.src_ip,
                    src_port=pkt.src_port,
                    dst_ip=pkt.dst_ip,
                    dst_port=pkt.dst_port,
                    protocol=pkt.protocol,
                    features=features,
                )
                self._ip_flow_cache[pkt.src_ip] = rec

                # Enforce the cap on ingest, not only on the prune timer.
                # A burst between prunes must not be able to balloon memory.
                overflow = len(self.extractor.flows) - self.max_tracked_flows
                if overflow > 0:
                    ordered = sorted(
                        self.extractor.flows.items(),
                        key=lambda kv: kv[1].last_time or 0.0,
                    )
                    for k, _ in ordered[:overflow]:
                        del self.extractor.flows[k]

                self._publish_flow_metrics()

    def _publish_flow_metrics(self) -> None:
        """Publishes tracked-flow gauges. Caller must hold the lock."""
        try:
            REGISTRY.set("antlion_flows_tracked", len(self.extractor.flows))
            REGISTRY.set(
                "antlion_ip_flow_cache_entries", len(self._ip_flow_cache)
            )
        except Exception as e:  # pragma: no cover - defensive
            logger.debug("Flow metric publication skipped: %s", e)

    def correlate_and_process_decoy(self, event: DecoyEvent) -> Verdict:
        """Correlates an incoming decoy interaction with concurrent network flow features."""
        with self._lock:
            matched_flow = self._ip_flow_cache.get(event.source_ip)

        ml_pred: Optional[MLPrediction] = None
        if matched_flow:
            try:
                # 1. Supervised flow prediction
                ml_pred = self.classifier.predict_flow(matched_flow.features)

                # 2. Unsupervised flow anomaly scoring
                is_anomaly, anomaly_score = self.anomaly_detector.score_flow(matched_flow.features)
                if is_anomaly:
                    matched_flow.features["anomaly_score"] = anomaly_score
                    if ml_pred and ml_pred.confidence < 0.70:
                        ml_pred.predicted_category = "Zero-Day Flow Anomaly"
                        ml_pred.confidence = max(ml_pred.confidence, anomaly_score)
            except Exception as e:
                logger.warning("Error running ML inference on correlated flow: %s", e)

        # Dispatch fully fused event to VerdictEngine
        return self.verdict_engine.process_decoy_event(
            event=event,
            flow_record=matched_flow,
            ml_prediction=ml_pred,
        )

    def prune_stale_flows(self) -> int:
        """Removes flows outside the sliding window and enforces the size cap.

        Prunes both the extractor's flow accumulators and the per-IP
        correlation cache. Returns the number of entries removed.
        """
        removed = 0

        with self._lock:
            now = time.time()
            cutoff = now - self.correlation_window_sec

            stale = [
                k
                for k, flow in self.extractor.flows.items()
                if flow.last_time and flow.last_time < cutoff
            ]
            for k in stale:
                del self.extractor.flows[k]
                removed += 1

            # Evict per-IP entries whose backing flow is gone, otherwise the
            # cache outlives the flows it references.
            live_ips = {
                (flow.fwd_src_ip, flow.fwd_dst_ip)
                for flow in self.extractor.flows.values()
            }
            stale_ips = [
                ip
                for ip in self._ip_flow_cache
                if (ip, self._ip_flow_cache[ip].dst_ip) not in live_ips
            ]
            for ip in stale_ips:
                del self._ip_flow_cache[ip]
                removed += 1

            # Belt-and-braces: evict cache entries older than a generous bound
            # even if a matching accumulator still lingers. Correlation against
            # a many-minute-old flow produces misleading verdicts anyway.
            cache_cutoff = now - max(self.correlation_window_sec, self._cache_max_age_sec)
            aged = [
                ip
                for ip, rec in self._ip_flow_cache.items()
                if rec.timestamp and rec.timestamp.timestamp() < cache_cutoff
            ]
            for ip in aged:
                del self._ip_flow_cache[ip]
                removed += 1

            # Hard cap: evict the oldest flows if still over budget. Without
            # this a high-cardinality scan (unique src/dst/port per packet)
            # grows unbounded regardless of the sliding window.
            overflow = len(self.extractor.flows) - self.max_tracked_flows
            if overflow > 0:
                ordered = sorted(
                    self.extractor.flows.items(),
                    key=lambda kv: kv[1].last_time or 0.0,
                )
                for k, _ in ordered[:overflow]:
                    del self.extractor.flows[k]
                    removed += 1

            self._publish_flow_metrics()

        if removed:
            logger.info("Pruned %d stale flow entries", removed)
        return removed

    def tracked_state_size(self) -> Tuple[int, int]:
        """Returns (flow accumulators, per-IP cache entries)."""
        with self._lock:
            return len(self.extractor.flows), len(self._ip_flow_cache)
