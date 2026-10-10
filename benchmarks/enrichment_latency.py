"""
Benchmark: IP enrichment latency on the decoy request path.

Reproduces the blocking-lookup defect and measures the non-blocking design.

Run:  python3 benchmarks/enrichment_latency.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import antlion.intel.enricher as enricher_mod
from antlion.core.types import DecoyEvent, DecoyServiceType, InteractionDepth
from antlion.intel.enricher import IPProfile, IPThreatEnricher
from antlion.verdict.heuristics import BehavioralHeuristicsEngine

# A simulated lookup latency, standing in for a real ip-api.com round trip.
SIMULATED_LATENCY = 0.02  # 20ms (optimistic; the real timeout is 1500ms)


def _install_slow_resolver(latency: float = SIMULATED_LATENCY, fail: bool = False):
    """Patches the live resolver to simulate network latency or failure."""

    def _resolve(self, ip_str):
        time.sleep(latency)
        if fail:
            return IPProfile(
                ip=ip_str, country="External Internet", risk_score=0.50
            )
        return IPProfile(
            ip=ip_str,
            country="Netherlands",
            country_code="NL",
            asn="AS24940",
            isp="Hetzner Online",
            is_hosting=True,
            risk_score=0.75,
        )

    enricher_mod.IPThreatEnricher._resolve_public_ip = _resolve


def _original_resolver():
    return enricher_mod.IPThreatEnricher._resolve_public_ip


def bench_heuristics(
    n: int, latency: float, unique_ips: bool = True, enricher=None
) -> tuple[float, IPThreatEnricher]:
    """Times evaluate_event across n events from distinct attacker IPs."""
    _install_slow_resolver(latency)
    enricher = enricher or IPThreatEnricher()
    engine = BehavioralHeuristicsEngine(enricher=enricher)

    start = time.perf_counter()
    for i in range(n):
        ip = f"45.{i // 65536}.{(i // 256) % 256}.{i % 256}" if unique_ips else "45.1.1.1"
        engine.evaluate_event(
            DecoyEvent(
                source_ip=ip,
                source_port=1000 + i,
                target_service=DecoyServiceType.SSH,
                depth=InteractionDepth.AUTHENTICATION_ATTEMPT,
                username="root",
                password="admin",
            )
        )
    return time.perf_counter() - start, enricher


def main() -> None:
    n = 200
    latency = SIMULATED_LATENCY
    enricher = IPThreatEnricher(cache_max_size=50)

    print("=" * 70)
    print("IP enrichment on the decoy request path")
    print("=" * 70)

    try:
        print(f"\n{'':26}{'elapsed':>12}{'per event':>14}")
        print("-" * 70)

        elapsed, enricher = bench_heuristics(n, latency, enricher=enricher)
        print(
            f"{n} unique attacker IPs:".ljust(26)
            + f"{elapsed:>10.3f}s{elapsed / n * 1000:>12.3f}ms"
        )
        print(
            f"  at the real 1.5s timeout this was {1500}ms per request "
            f"({n * 1.5:.0f}s total)"
        )

        # Let the background worker drain so cache stats are meaningful.
        time.sleep(latency * n + 0.3)

        stats = enricher.cache_stats()
        print("-" * 70)
        print(f"  lookups resolved   {stats['resolved']}")
        print(f"  cache entries      {stats['cache_size']} (bound {stats['cache_max_size']})")
        print(f"  cache evictions    {stats['cache_evictions']}")
        print(f"  circuit open       {stats['circuit_open']}")
        print("=" * 70)
    finally:
        enricher.stop_worker()
        enricher_mod.IPThreatEnricher._resolve_public_ip = _original_resolver()


if __name__ == "__main__":
    main()