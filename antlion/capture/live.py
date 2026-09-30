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
    ):
        self.verdict_engine = verdict_engine
        self.classifier = classifier or FlowClassifier()
        self.anomaly_detector = anomaly_detector or FlowAnomalyDetector()
        self.correlation_window_sec = correlation_window_sec

        self.extractor = FlowFeatureExtractor()
        # Maps src_ip -> latest FlowRecord
        self._ip_flow_cache: Dict[str, FlowRecord] = {}
        self._lock = threading.Lock()
        self._is_running = False

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

    def prune_stale_flows(self) -> None:
        """Removes expired flows beyond the sliding window."""
        with self._lock:
            now = time.time()
            cutoff = now - self.correlation_window_sec
            to_remove = []
            for k, flow in self.extractor.flows.items():
                if flow.last_time and flow.last_time < cutoff:
                    to_remove.append(k)

            for k in to_remove:
                del self.extractor.flows[k]
