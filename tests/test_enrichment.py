"""
Tests for non-blocking IP enrichment.

The defect: enrichment ran a blocking provider lookup on the decoy request
path. Source IPs are attacker-controlled and near-unique, so the cache almost
never hit and every interaction paid the full provider timeout.
"""

import tempfile
import threading
import time
from pathlib import Path

import pytest

import antlion.intel.enricher as enricher_mod
from antlion.core.config import AntlionConfig
from antlion.core.types import (
    DecoyEvent,
    DecoyServiceType,
    InteractionDepth,
    SeverityLevel,
)
from antlion.intel.enricher import IntelCache, IPProfile, IPThreatEnricher
from antlion.verdict.heuristics import BehavioralHeuristicsEngine


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture(autouse=True)
def restore_resolver():
    original = enricher_mod.IPThreatEnricher._resolve_public_ip
    yield
    enricher_mod.IPThreatEnricher._resolve_public_ip = original


def install_resolver(latency=0.0, fail=False, profile=None):
    """Replaces the live resolver with a controllable fake."""
    calls = {"n": 0}

    def _resolve(self, ip_str):
        calls["n"] += 1
        if latency:
            time.sleep(latency)
        if fail:
            self._record_failure()
            return IPProfile(
                ip=ip_str, country="External Internet", risk_score=0.50, resolved=False
            )
        self._record_success()
        return profile or IPProfile(
            ip=ip_str,
            country="Netherlands",
            country_code="NL",
            asn="AS24940",
            isp="Hetzner Online",
            is_hosting=True,
            risk_score=0.75,
            resolved=True,
        )

    enricher_mod.IPThreatEnricher._resolve_public_ip = _resolve
    return calls


def drain(enricher, timeout=5.0):
    """Waits for the background worker to finish queued work."""
    deadline = time.time() + timeout
    while time.time() < deadline and not enricher._queue.empty():
        time.sleep(0.01)
    time.sleep(0.05)


# ---------------------------------------------------------------------------
# Core requirement: enrich() must not block
# ---------------------------------------------------------------------------


def test_enrich_does_not_block_on_network():
    """The regression this whole change exists to prevent."""
    install_resolver(latency=1.5)
    e = IPThreatEnricher()
    try:
        start = time.perf_counter()
        for i in range(50):
            e.enrich(f"45.1.{i}.1")
        elapsed = time.perf_counter() - start

        # 50 lookups at 1.5s each would be 75s serially.
        assert elapsed < 0.5, f"enrich() blocked: {elapsed:.2f}s for 50 IPs"
    finally:
        e.stop_worker()


def test_enrich_returns_immediately_for_unique_ips():
    install_resolver(latency=0.5)
    e = IPThreatEnricher()
    try:
        start = time.perf_counter()
        profile = e.enrich("45.9.9.9")
        elapsed = time.perf_counter() - start

        assert elapsed < 0.05
        assert profile.resolved is False
        assert profile.risk_score == 0.50
    finally:
        e.stop_worker()


def test_resolve_now_still_blocks_when_asked():
    """CLI tooling keeps a blocking path available."""
    install_resolver(latency=0.2)
    e = IPThreatEnricher()
    try:
        start = time.perf_counter()
        profile = e.resolve_now("45.8.8.8")
        assert time.perf_counter() - start >= 0.2
        assert profile.resolved is True
    finally:
        e.stop_worker()


# ---------------------------------------------------------------------------
# Cache bounding
# ---------------------------------------------------------------------------


def test_cache_is_bounded():
    install_resolver()
    e = IPThreatEnricher(cache_max_size=25)
    try:
        for i in range(200):
            e.enrich(f"45.2.{i // 256}.{i % 256}")
            e.resolve_now(f"45.2.{i // 256}.{i % 256}")

        assert e.cache_size <= 25
        assert e.cache_stats()["cache_evictions"] > 0
    finally:
        e.stop_worker()


def test_cache_evicts_least_recently_used():
    cache = IntelCache(max_size=3, ttl_seconds=1000)
    now = 100.0
    for k in ("a", "b", "c"):
        cache.put(k, IPProfile(ip=k), now)

    cache.get("a", now)  # 'a' becomes most recently used
    cache.put("d", IPProfile(ip="d"), now)

    assert cache.get("a", now) is not None  # survived
    assert cache.get("b", now) is None  # evicted as LRU
    assert len(cache) == 3
    cache.clear()


def test_cache_ttl_expiry():
    clock = FakeClock()
    cache = IntelCache(max_size=10, ttl_seconds=60)
    cache.put("x", IPProfile(ip="x"), clock())

    assert cache.get("x", clock()) is not None
    clock.advance(61)
    assert cache.get("x", clock()) is None
    cache.clear()


def test_cache_ttl_triggers_revalidation():
    calls = install_resolver()
    clock = FakeClock()
    e = IPThreatEnricher(cache_ttl_seconds=60, time_source=clock)
    try:
        e.resolve_now("45.7.7.7")
        assert calls["n"] == 1

        e.enrich("45.7.7.7")  # fresh
        assert calls["n"] == 1

        clock.advance(61)
        e.resolve_now("45.7.7.7")  # expired
        assert calls["n"] == 2
    finally:
        e.stop_worker()


def test_private_ip_is_resolved_without_network():
    calls = install_resolver()
    e = IPThreatEnricher()
    try:
        for ip in ("192.168.1.10", "10.0.0.5", "127.0.0.1"):
            profile = e.enrich(ip)
            assert profile.is_private is True
            assert profile.resolved is True

        assert calls["n"] == 0, "private ranges must not hit the network"
    finally:
        e.stop_worker()


# ---------------------------------------------------------------------------
# Background resolution and stampede protection
# ---------------------------------------------------------------------------


def test_background_worker_resolves_queued_ip():
    install_resolver()
    e = IPThreatEnricher()
    try:
        assert e.enrich("45.6.6.6").resolved is False

        drain(e)

        assert e.enrich("45.6.6.6").resolved is True
    finally:
        e.stop_worker()


def test_duplicate_lookups_are_collapsed():
    """Concurrent requests for one IP must not fan out to N lookups."""
    install_resolver(latency=0.15)
    e = IPThreatEnricher()
    try:
        threads = [
            threading.Thread(target=lambda: [e.enrich("45.5.5.5") for _ in range(10)])
            for _ in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        drain(e)
        assert e.cache_stats()["scheduled"] == 1
    finally:
        e.stop_worker()


def test_queue_full_drops_rather_than_blocking():
    install_resolver(latency=0.5)
    e = IPThreatEnricher(max_queue_size=5, autostart_worker=False)
    try:
        for i in range(100):
            e.enrich(f"45.3.{i // 256}.{i % 256}")

        assert e.cache_stats()["dropped"] > 0, "saturated queue must drop, not block"
    finally:
        e.stop_worker()


def test_disabled_lookup_never_schedules():
    install_resolver()
    e = IPThreatEnricher(enable_live_lookup=False, autostart_worker=False)
    try:
        profile = e.enrich("45.4.4.4")
        assert profile.resolved is False
        assert e.cache_stats()["scheduled"] == 0
        assert e.cache_stats()["misses"] == 1
    finally:
        e.stop_worker()


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


def test_circuit_opens_after_repeated_failures():
    install_resolver(fail=True)
    e = IPThreatEnricher(
        failure_threshold=3, circuit_cooldown_seconds=60, autostart_worker=False
    )
    try:
        for _ in range(3):
            e.resolve_now("45.1.1.1")

        assert e.circuit_open is True
        assert e.cache_stats()["circuit_trips"] == 1
    finally:
        e.stop_worker()


def test_circuit_suppresses_further_lookups():
    install_resolver(fail=True)
    clock = FakeClock()
    e = IPThreatEnricher(
        failure_threshold=2,
        circuit_cooldown_seconds=60,
        time_source=clock,
        autostart_worker=False,
    )
    try:
        calls_before = None
        for _ in range(2):
            e.resolve_now("45.1.1.1")
        calls_before = e.cache_stats()["resolved"]

        start = time.perf_counter()
        profile = e.resolve_now("45.2.2.2")
        elapsed = time.perf_counter() - start

        assert elapsed < 0.05, "open circuit must not attempt a lookup"
        assert profile.resolved is False
        assert e.cache_stats()["resolved"] == calls_before
    finally:
        e.stop_worker()


def test_failed_lookups_are_not_cached():
    """A transient provider blip must not blind enrichment for the full TTL."""
    install_resolver(fail=True)
    e = IPThreatEnricher(failure_threshold=99, cache_ttl_seconds=86400, autostart_worker=False)
    try:
        e.resolve_now("45.1.1.1")
        assert e.cache_size == 0, "failure must not be cached"
    finally:
        e.stop_worker()


def test_failed_lookup_is_retried_and_can_recover():
    state = {"fail": True}

    def _resolve(self, ip_str):
        if state["fail"]:
            self._record_failure()
            return IPProfile(ip=ip_str, risk_score=0.5, resolved=False)
        self._record_success()
        return IPProfile(ip=ip_str, risk_score=0.7, resolved=True)

    enricher_mod.IPThreatEnricher._resolve_public_ip = _resolve

    e = IPThreatEnricher(failure_threshold=99, autostart_worker=False)
    try:
        assert e.resolve_now("45.1.1.1").resolved is False

        state["fail"] = False
        recovered = e.resolve_now("45.1.1.1")

        assert recovered.resolved is True
        assert e.enrich("45.1.1.1").resolved is True
    finally:
        e.stop_worker()


def test_circuit_closes_after_cooldown():
    install_resolver(fail=True)
    clock = FakeClock()
    e = IPThreatEnricher(
        failure_threshold=1,
        circuit_cooldown_seconds=30,
        time_source=clock,
        autostart_worker=False,
    )
    try:
        e.resolve_now("45.1.1.1")
        assert e.circuit_open is True

        clock.advance(31)
        assert e.circuit_open is False
    finally:
        e.stop_worker()


def test_success_resets_failure_run():
    state = {"fail": True}

    def _resolve(self, ip_str):
        if state["fail"]:
            self._record_failure()
            return IPProfile(ip=ip_str, risk_score=0.5, resolved=False)
        self._record_success()
        return IPProfile(ip=ip_str, risk_score=0.7, resolved=True)

    enricher_mod.IPThreatEnricher._resolve_public_ip = _resolve

    e = IPThreatEnricher(failure_threshold=3, autostart_worker=False)
    try:
        e.resolve_now("45.1.1.1")
        e.resolve_now("45.1.2.1")
        assert e._consecutive_failures == 2

        state["fail"] = False
        e.resolve_now("45.1.3.1")
        assert e._consecutive_failures == 0
        assert e.circuit_open is False
    finally:
        e.stop_worker()


def test_enrich_does_not_schedule_while_circuit_open():
    install_resolver(fail=True)
    e = IPThreatEnricher(failure_threshold=1, autostart_worker=False)
    try:
        e.resolve_now("45.1.1.1")
        assert e.circuit_open is True

        before = e.cache_stats()["scheduled"]
        e.enrich("45.9.9.9")
        assert e.cache_stats()["scheduled"] == before
    finally:
        e.stop_worker()


# ---------------------------------------------------------------------------
# Worker lifecycle
# ---------------------------------------------------------------------------


def test_worker_survives_resolver_exception():
    def _boom(self, ip_str):
        raise RuntimeError("resolver exploded")

    enricher_mod.IPThreatEnricher._resolve_public_ip = _boom

    e = IPThreatEnricher()
    try:
        e.enrich("45.1.1.1")
        drain(e)

        assert e._worker is None or e._worker.is_alive(), "worker died"
        assert e.enrich("45.1.1.1") is not None
    finally:
        e.stop_worker()


def test_worker_start_is_not_duplicated():
    e = IPThreatEnricher()
    try:
        first = e._worker
        e.start_worker()
        assert e._worker is first
    finally:
        e.stop_worker()


def test_stop_worker_is_idempotent():
    e = IPThreatEnricher()
    e.stop_worker()
    e.stop_worker()  # must not raise


# ---------------------------------------------------------------------------
# Heuristic integration
# ---------------------------------------------------------------------------


def _auth_event(ip):
    return DecoyEvent(
        source_ip=ip,
        source_port=1234,
        target_service=DecoyServiceType.SSH,
        depth=InteractionDepth.AUTHENTICATION_ATTEMPT,
        username="root",
        password="admin",
    )


def test_hosting_heuristic_fires_once_resolved():
    install_resolver()
    e = IPThreatEnricher()
    engine = BehavioralHeuristicsEngine(enricher=e)
    try:
        # First evaluation: unresolved, so no intel rule.
        rules = {m.rule_id for m in engine.evaluate_event(_auth_event("45.1.1.1"))}
        assert "RULE_HOSTING_ABUSE_INFRA" not in rules

        drain(e)

        rules = {m.rule_id for m in engine.evaluate_event(_auth_event("45.1.1.1"))}
        assert "RULE_HOSTING_ABUSE_INFRA" in rules
    finally:
        e.stop_worker()


def test_unresolved_profile_produces_no_intel_rule():
    install_resolver()
    e = IPThreatEnricher(enable_live_lookup=False, autostart_worker=False)
    engine = BehavioralHeuristicsEngine(enricher=e)
    rules = {m.rule_id for m in engine.evaluate_event(_auth_event("45.1.1.1"))}
    assert "RULE_HOSTING_ABUSE_INFRA" not in rules
    assert "RULE_TOR_PROXY_INTRUSION" not in rules


def test_heuristic_evaluation_is_fast_under_load():
    """End-to-end guard on the original defect."""
    install_resolver(latency=1.5)
    e = IPThreatEnricher()
    engine = BehavioralHeuristicsEngine(enricher=e)
    try:
        start = time.perf_counter()
        for i in range(50):
            engine.evaluate_event(_auth_event(f"45.4.{i // 256}.{i % 256}"))
        elapsed = time.perf_counter() - start

        assert elapsed < 0.5, f"heuristics blocked on enrichment: {elapsed:.2f}s"
    finally:
        e.stop_worker()


def test_private_ip_heuristics_still_fire():
    calls = install_resolver()
    e = IPThreatEnricher()
    engine = BehavioralHeuristicsEngine(enricher=e)
    try:
        engine.evaluate_event(_auth_event("192.168.1.50"))
        assert calls["n"] == 0
    finally:
        e.stop_worker()


def test_missing_enricher_is_tolerated():
    engine = BehavioralHeuristicsEngine(enricher=IPThreatEnricher(enable_live_lookup=False))
    engine.enricher = None
    matches = engine.evaluate_event(_auth_event("45.1.1.1"))
    assert isinstance(matches, list)


# ---------------------------------------------------------------------------
# Config wiring
# ---------------------------------------------------------------------------


def test_engine_builds_enricher_from_config(monkeypatch):
    from antlion.storage.database import AntlionDatabase
    from antlion.verdict.engine import VerdictEngine

    monkeypatch.setenv("ANTLION_IP_CACHE_MAX_SIZE", "1234")
    monkeypatch.setenv("ANTLION_IP_LOOKUP_TIMEOUT", "0.25")
    monkeypatch.setenv("ANTLION_IP_FAILURE_THRESHOLD", "7")
    monkeypatch.setenv("ANTLION_IP_ENRICHMENT", "false")

    cfg = AntlionConfig(data_dir=Path(tempfile.mkdtemp()))
    cfg = AntlionConfig.from_env()
    cfg.data_dir = Path(tempfile.mkdtemp())

    engine = VerdictEngine(config=cfg, db=AntlionDatabase(cfg.get_db_path()))
    enricher = engine.heuristics.enricher

    assert enricher.cache_max_size == 1234
    assert enricher.lookup_timeout == 0.25
    assert enricher.failure_threshold == 7
    assert enricher.enable_live_lookup is False


def test_invalid_enrichment_env_falls_back(monkeypatch):
    monkeypatch.setenv("ANTLION_IP_LOOKUP_TIMEOUT", "not-a-float")
    monkeypatch.setenv("ANTLION_IP_CACHE_MAX_SIZE", "abc")

    cfg = AntlionConfig.from_env()
    assert cfg.ip_lookup_timeout == 1.5
    assert cfg.ip_cache_max_size == 10000


def test_cache_stats_shape():
    e = IPThreatEnricher(autostart_worker=False)
    try:
        stats = e.cache_stats()
        for key in (
            "hits",
            "misses",
            "scheduled",
            "resolved",
            "failures",
            "dropped",
            "circuit_trips",
            "cache_size",
            "cache_max_size",
            "cache_evictions",
            "hit_rate",
            "circuit_open",
        ):
            assert key in stats
    finally:
        e.stop_worker()