"""
Data retention and automatic pruning for the Antlion event store.

The SQLite event store grows without bound: a public decoy under sustained
scanning produces verdicts and decoy events continuously, and PCAP rotation is
configured but the database itself is never trimmed. This module deletes
records older than a retention window and can run as a background task.

Deletion is done in bounded batches so a large backlog does not hold a write
lock long enough to stall verdict persistence.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from antlion.storage.database import AntlionDatabase

logger = logging.getLogger("antlion.storage.prune")

# Tables eligible for retention pruning, with their timestamp column.
PRUNABLE_TABLES: Dict[str, str] = {
    "verdicts": "timestamp",
    "decoy_events": "timestamp",
    "flow_records": "timestamp",
}


@dataclass
class PruneResult:
    """Outcome of a pruning pass."""

    deleted: Dict[str, int]
    elapsed_seconds: float = 0.0

    @property
    def total_deleted(self) -> int:
        return sum(self.deleted.values())

    def to_dict(self) -> Dict[str, object]:
        return {
            "deleted": dict(self.deleted),
            "total_deleted": self.total_deleted,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


class RetentionManager:
    """Deletes event-store records older than the configured retention window."""

    def __init__(
        self,
        db: AntlionDatabase,
        retention_days: int = 30,
        batch_size: int = 5000,
    ):
        self.db = db
        self.retention_days = retention_days
        self.batch_size = batch_size

    @property
    def enabled(self) -> bool:
        """Retention is disabled when the window is non-positive."""
        return self.retention_days > 0

    def cutoff(self, now: Optional[datetime] = None) -> str:
        """Returns the ISO timestamp cutoff for deletion."""
        reference = now or datetime.now(timezone.utc)
        return (reference - timedelta(days=self.retention_days)).isoformat()

    def prune_once(self, now: Optional[datetime] = None) -> PruneResult:
        """Deletes expired records in bounded batches.

        Returns per-table deletion counts. Safe to call concurrently with
        verdict persistence: each batch is its own short transaction.
        """
        import time as _time

        started = _time.monotonic()
        cutoff = self.cutoff(now)
        deleted: Dict[str, int] = {}

        if not self.enabled:
            logger.debug("Retention disabled (retention_days=%d)", self.retention_days)
            return PruneResult(deleted=deleted, elapsed_seconds=0.0)

        for table, ts_column in PRUNABLE_TABLES.items():
            deleted[table] = self._prune_table(table, ts_column, cutoff)

        result = PruneResult(
            deleted=deleted, elapsed_seconds=_time.monotonic() - started
        )

        if result.total_deleted:
            logger.info(
                "Retention prune removed %d records older than %s: %s",
                result.total_deleted,
                cutoff,
                deleted,
            )
        else:
            logger.debug("Retention prune removed nothing (cutoff=%s)", cutoff)

        return result

    def _prune_table(self, table: str, ts_column: str, cutoff: str) -> int:
        """Deletes rows older than cutoff in batches. Returns the count."""
        total = 0

        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            try:
                while True:
                    # LIMIT inside DELETE keeps the write lock short. SQLite
                    # supports RETURNING, but the rowid approach works on
                    # older builds and avoids depending on it.
                    cursor.execute(
                        f"""
                        DELETE FROM {table}
                        WHERE rowid IN (
                            SELECT rowid FROM {table}
                            WHERE {ts_column} < ?
                            LIMIT ?
                        );
                        """,
                        (cutoff, self.batch_size),
                    )
                    batch_deleted = cursor.rowcount or 0
                    conn.commit()

                    total += batch_deleted
                    if batch_deleted < self.batch_size:
                        break
            except Exception as e:
                conn.rollback()
                logger.warning("Retention prune failed on %s: %s", table, e)
                return total

        return total

    def count_expired(self, now: Optional[datetime] = None) -> Dict[str, int]:
        """Counts records that the next prune would delete, without deleting."""
        cutoff = self.cutoff(now)
        counts: Dict[str, int] = {}

        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            for table, ts_column in PRUNABLE_TABLES.items():
                try:
                    cursor.execute(
                        f"SELECT COUNT(*) AS n FROM {table} WHERE {ts_column} < ?;",
                        (cutoff,),
                    )
                    row = cursor.fetchone()
                    counts[table] = int(row["n"]) if row else 0
                except Exception as e:
                    logger.debug("Count expired failed on %s: %s", table, e)
                    counts[table] = 0

        return counts


class RetentionScheduler:
    """Runs RetentionManager on a fixed interval in a background thread."""

    def __init__(
        self,
        manager: RetentionManager,
        interval_seconds: float = 3600.0,
    ):
        self.manager = manager
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.last_result: Optional[PruneResult] = None
        self.run_count = 0

    def start(self) -> None:
        """Starts the background pruning loop."""
        if not self.manager.enabled:
            logger.info(
                "Retention scheduler not started (retention_days=%d)",
                self.manager.retention_days,
            )
            return

        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()

            def _loop() -> None:
                while not self._stop_event.wait(self.interval_seconds):
                    try:
                        result = self.manager.prune_once()
                        self.last_result = result
                        self.run_count += 1
                    except Exception as e:
                        # Never let a prune failure kill the loop.
                        logger.warning("Scheduled retention prune failed: %s", e)

            self._thread = threading.Thread(
                target=_loop, daemon=True, name="AntlionRetention"
            )
            self._thread.start()

        logger.info(
            "Retention scheduler started (every %.0fs, %d day window)",
            self.interval_seconds,
            self.manager.retention_days,
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Signals the loop to exit and waits briefly for it."""
        self._stop_event.set()
        with self._lock:
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=timeout)
            self._thread = None

    @property
    def running(self) -> bool:
        with self._lock:
            return bool(self._thread and self._thread.is_alive())