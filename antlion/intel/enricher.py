"""
IP threat intelligence and geolocation/ASN enrichment.

Design constraint: this module runs on the decoy request path, where latency is
attacker-controlled. A decoy has no legitimate users, so source IPs are
adversarial and overwhelmingly unique, which defeats caching entirely. A
blocking provider lookup would therefore add the provider's full timeout to
every single interaction -- turning the decoy into a slow service that one
attacker can pin with one request per spoofed source address.

Accordingly:

* ``enrich()`` never performs network I/O. It returns a cached profile, a
  locally-computed one (private ranges), or a neutral placeholder, and
  schedules resolution on a background worker.
* A **bounded** LRU cache with TTL replaces the previous unbounded dict, which
  was a slow leak keyed by attacker-controlled input.
* A **circuit breaker** stops scheduling lookups after repeated failures, so an
  unreachable provider degrades enrichment instead of stalling every verdict.
* Duplicate concurrent lookups for the same address are collapsed.

``resolve_now()`` remains available for CLI tools and tests that genuinely
want to block.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from queue import Empty, Full, Queue
from typing import Callable, Dict, Optional, Tuple

logger = logging.getLogger("antlion.intel.enricher")


@dataclass
class IPProfile:
    """Enriched threat profile for an attacking source IP."""

    ip: str
    country: str = "Unknown"
    country_code: str = "XX"
    city: str = "Unknown"
    asn: str = "AS0"
    isp: str = "Unknown"
    org: str = "Unknown"
    is_private: bool = False
    is_hosting: bool = False
    is_tor_proxy: bool = False
    risk_score: float = 0.0
    lookup_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "asn": self.asn,
            "isp": self.isp,
            "org": self.org,
            "is_private": self.is_private,
            "is_hosting": self.is_hosting,
            "is_tor_proxy": self.is_tor_proxy,
            "risk_score": round(self.risk_score, 2),
            "lookup_timestamp": self.lookup_timestamp.isoformat(),
            "resolved": self.resolved,
        }


class IntelCache:
    """Bounded LRU cache with per-entry TTL.

    Replaces the previous unbounded dict. Attackers control the key space, so an
    unbounded cache is a memory leak with attacker-selected lifetime.
    """

    def __init__(self, max_size: int = 10000, ttl_seconds: float = 86400.0):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._data: "OrderedDict[str, Tuple[IPProfile, float]]" = OrderedDict()
        self._lock = threading.Lock()
        self.evictions = 0

    def get(self, key: str, now: float) -> Optional[IPProfile]:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None

            profile, expires_at = entry
            if expires_at <= now:
                del self._data[key]
                return None

            self._data.move_to_end(key)
            return profile

    def put(self, key: str, profile: IPProfile, now: float) -> None:
        with self._lock:
            self._data[key] = (profile, now + self.ttl_seconds)
            self._data.move_to_end(key)

            while len(self._data) > self.max_size:
                self._data.popitem(last=False)
                self.evictions += 1

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


class IPThreatEnricher:
    """Caches and resolves IP intelligence with a non-blocking request path."""

    # Curated known bulletproof / high-abuse hosting keywords
    HIGH_ABUSE_PROVIDERS = [
        "digitalocean", "ovh", "linode", "vultr", "hetzner", "choopa",
        "m247", "scaleway", "cogent", "bulletproof", "leaseweb", "tor-exit",
    ]

    def __init__(
        self,
        enable_live_lookup: bool = True,
        cache_max_size: int = 10000,
        cache_ttl_seconds: float = 86400.0,
        lookup_timeout: float = 1.5,
        failure_threshold: int = 3,
        circuit_cooldown_seconds: float = 300.0,
        max_queue_size: int = 2000,
        autostart_worker: bool = True,
        time_source: Optional[Callable[[], float]] = None,
    ):
        self.enable_live_lookup = enable_live_lookup
        self.lookup_timeout = lookup_timeout
        self.failure_threshold = failure_threshold
        self.circuit_cooldown_seconds = circuit_cooldown_seconds

        self._cache = IntelCache(max_size=cache_max_size, ttl_seconds=cache_ttl_seconds)
        self._now = time_source or time.monotonic

        # Single worker: lookups are I/O bound but rate-limited providers punish
        # concurrency, and one thread keeps ordering predictable.
        self._queue: "Queue[Optional[str]]" = Queue(maxsize=max_queue_size)
        self._inflight: set = set()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker: Optional[threading.Thread] = None

        self._consecutive_failures = 0
        self._circuit_open_until = 0.0

        self.stats: Dict[str, int] = {
            "hits": 0,
            "misses": 0,
            "scheduled": 0,
            "resolved": 0,
            "failures": 0,
            "dropped": 0,
            "circuit_trips": 0,
        }

        if enable_live_lookup and autostart_worker:
            self.start_worker()

    # ------------------------------------------------------------------
    # Worker lifecycle
    # ------------------------------------------------------------------

    def start_worker(self) -> None:
        """Starts the background resolution thread."""
        if self._worker and self._worker.is_alive():
            return
        self._stop_event.clear()
        self._worker = threading.Thread(
            target=self._worker_loop, daemon=True, name="AntlionIntelResolver"
        )
        self._worker.start()

    def stop_worker(self, timeout: float = 2.0) -> None:
        """Stops the background worker."""
        self._stop_event.set()
        try:
            self._queue.put_nowait(None)
        except Full:
            pass
        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=timeout)
        self._worker = None

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                ip = self._queue.get(timeout=0.5)
            except Empty:
                continue

            if ip is None:
                self._queue.task_done()
                break

            try:
                self._resolve_and_store(ip)
            except Exception as e:  # never let the worker die
                self._bump("failures")
                logger.debug("Background intel resolution failed for %s: %s", ip, e)
            finally:
                with self._lock:
                    self._inflight.discard(ip)
                self._queue.task_done()

    def _resolve_and_store(self, ip_str: str) -> None:
        """Performs a blocking lookup on the worker thread and caches it."""
        if self.circuit_open:
            return

        profile = self._resolve_public_ip(ip_str)
        # Only successful lookups are cached. Caching a failure for the full TTL
        # would let one transient provider blip blind enrichment for a day;
        # provider health is the circuit breaker's job, not the cache's.
        if profile.resolved:
            self._cache.put(ip_str, profile, self._now())
        self._bump("resolved")

    # ------------------------------------------------------------------
    # Circuit breaker
    # ------------------------------------------------------------------

    @property
    def circuit_open(self) -> bool:
        """True while lookups are suspended after repeated failures."""
        return self._now() < self._circuit_open_until

    def _record_success(self) -> None:
        self._consecutive_failures = 0

    def _record_failure(self) -> None:
        self._bump("failures")
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.failure_threshold:
            self._circuit_open_until = self._now() + self.circuit_cooldown_seconds
            self._consecutive_failures = 0
            self._bump("circuit_trips")
            logger.warning(
                "IP enrichment circuit opened after %d consecutive failures; "
                "suspending lookups for %.0fs",
                self.failure_threshold,
                self.circuit_cooldown_seconds,
            )

    def _bump(self, key: str) -> None:
        with self._lock:
            self.stats[key] = self.stats.get(key, 0) + 1

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich(self, ip_str: str) -> IPProfile:
        """Returns an intelligence profile without blocking on the network.

        Returns a cached profile when fresh, a locally-computed profile for
        private/reserved ranges, or a neutral placeholder while a background
        lookup is scheduled. Enrichment is supplementary context, so it must
        never add provider latency to a verdict.
        """
        cached = self._cache.get(ip_str, self._now())
        if cached is not None:
            self._bump("hits")
            return cached

        local = self._local_profile(ip_str)
        if local is not None:
            self._bump("hits")
            self._cache.put(ip_str, local, self._now())
            return local

        self._bump("misses")
        self._schedule(ip_str)
        return self._neutral_profile(ip_str)

    def resolve_now(self, ip_str: str) -> IPProfile:
        """Blocking resolution, for CLI tooling and tests.

        Prefer ``enrich()`` on any request path.
        """
        cached = self._cache.get(ip_str, self._now())
        if cached is not None:
            return cached

        local = self._local_profile(ip_str)
        if local is not None:
            self._cache.put(ip_str, local, self._now())
            return local

        if self.circuit_open:
            return self._neutral_profile(ip_str)

        profile = self._resolve_public_ip(ip_str)
        # Failures are deliberately not cached; see _resolve_and_store.
        if profile.resolved:
            self._cache.put(ip_str, profile, self._now())
        return profile

    def _schedule(self, ip_str: str) -> None:
        """Queues a background lookup, collapsing duplicates."""
        if not self.enable_live_lookup or self.circuit_open:
            return

        with self._lock:
            if ip_str in self._inflight:
                return
            self._inflight.add(ip_str)

        try:
            self._queue.put_nowait(ip_str)
            self._bump("scheduled")
        except Full:
            # Queue saturated: drop this address. It will be retried on a later
            # interaction, and blocking here would defeat the whole design.
            with self._lock:
                self._inflight.discard(ip_str)
            self._bump("dropped")

    def warm(self, ip_str: str) -> None:
        """Schedules a background lookup without needing a returned profile."""
        self._schedule(ip_str)

    def _local_profile(self, ip_str: str) -> Optional[IPProfile]:
        """Computes a profile without network access, or None if unknown."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
            return None

        return IPProfile(
            ip=ip_str,
            country="Private Network",
            country_code="LAN",
            city="Internal / Localhost",
            asn="AS0",
            isp="RFC1918 Private Range",
            org="Internal / Localhost",
            is_private=True,
            risk_score=0.10,
            resolved=True,
        )

    def _neutral_profile(self, ip_str: str) -> IPProfile:
        """Placeholder returned while intelligence is unresolved."""
        return IPProfile(
            ip=ip_str,
            country="Unresolved",
            country_code="XX",
            city="Unresolved",
            asn="AS-Unknown",
            isp="Unresolved",
            org="Unresolved",
            risk_score=0.50,
            resolved=False,
        )

    def _resolve_public_ip(self, ip_str: str) -> IPProfile:
        """Performs the provider lookup. Runs on the worker thread only."""
        if not self.enable_live_lookup:
            return IPProfile(ip=ip_str, country="External Internet", risk_score=0.50)

        try:
            # HTTPS only: plaintext would leak attacker IPs and let a MITM
            # poison ASN/risk enrichment.
            url = (
                f"https://ip-api.com/json/{ip_str}"
                "?fields=status,message,country,countryCode,city,isp,org,as,hosting,proxy"
            )
            req = urllib.request.Request(
                url, headers={"User-Agent": "Antlion-Threat-Intel/0.1.0"}
            )
            with urllib.request.urlopen(req, timeout=self.lookup_timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if data.get("status") == "success":
                isp = data.get("isp", "Unknown")
                org = data.get("org", "Unknown")
                asn = data.get("as", "AS0")
                is_hosting = bool(data.get("hosting", False))
                is_proxy = bool(data.get("proxy", False))

                # Compute baseline infrastructure risk score
                risk = 0.50
                corp_str = f"{isp} {org} {asn}".lower()
                if any(bad in corp_str for bad in self.HIGH_ABUSE_PROVIDERS):
                    is_hosting = True
                    risk += 0.25

                if is_proxy:
                    risk += 0.20

                self._record_success()
                return IPProfile(
                    ip=ip_str,
                    country=data.get("country", "Unknown"),
                    country_code=data.get("countryCode", "XX"),
                    city=data.get("city", "Unknown"),
                    asn=asn,
                    isp=isp,
                    org=org,
                    is_hosting=is_hosting,
                    is_tor_proxy=is_proxy,
                    risk_score=min(1.0, risk),
                    resolved=True,
                )

            self._record_failure()
        except Exception as e:
            logger.debug("Live IP enrichment skipped for %s: %s", ip_str, e)
            self._record_failure()

        # Graceful fallback for offline environments or timeout
        return IPProfile(
            ip=ip_str,
            country="External Internet",
            country_code="NET",
            city="Global",
            asn="AS-Unknown",
            isp="Public ISP",
            org="Public Subnet",
            risk_score=0.50,
            resolved=False,
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    @property
    def cache_max_size(self) -> int:
        return self._cache.max_size

    def cache_stats(self) -> Dict[str, float]:
        """Cache and resolution counters for observability."""
        total = self.stats["hits"] + self.stats["misses"]
        return {
            **self.stats,
            "cache_size": self.cache_size,
            "cache_max_size": self.cache_max_size,
            "cache_evictions": self._cache.evictions,
            "hit_rate": round(self.stats["hits"] / total, 4) if total else 0.0,
            "circuit_open": self.circuit_open,
            "queue_depth": self._queue.qsize(),
        }