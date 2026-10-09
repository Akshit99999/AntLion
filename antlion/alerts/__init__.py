"""
Antlion Alerting and SIEM / Webhook Dispatcher module.
"""

from antlion.alerts.dedup import AlertDeduplicator, DedupStats
from antlion.alerts.dispatcher import AlertDispatcher

__all__ = ["AlertDispatcher", "AlertDeduplicator", "DedupStats"]
