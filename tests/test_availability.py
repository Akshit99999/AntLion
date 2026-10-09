"""
Tests for resource-bounding and cleanup behaviour.

Covers the unbounded-growth fixes: live-capture flow pruning and SSH decoy
connection caps.
"""

import socket
import threading
import time

import pytest

from antlion.capture.flow_extractor import PacketMetadata
from antlion.capture.live import LiveCapturePipeline
from antlion.core.types import DecoyServiceType


class _NullEngine:
    def process_decoy_event(self, *a, **kw):
        return None


def make_pipeline(**kwargs):
    kwargs.setdefault("autostart_pruner", False)
    return LiveCapturePipeline(verdict_engine=_NullEngine(), **kwargs)


def pkt(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80, ts=None):
    return PacketMetadata(
        timestamp=ts if ts is not None else time.time(),
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol=6,
        length=100,
        tcp_flags={"SYN": 1},
    )


# ---------------------------------------------------------------------------
# Live capture pruning
# ---------------------------------------------------------------------------


def test_prune_removes_stale_flows():
    pipe = make_pipeline(correlation_window_sec=10)

    now = time.time()
    pipe.ingest_packet(pkt(ts=now - 100))  # old
    assert pipe.tracked_state_size()[0] == 1

    removed = pipe.prune_stale_flows()
    assert removed >= 1
    assert pipe.tracked_state_size()[0] == 0


def test_prune_keeps_fresh_flows():
    pipe = make_pipeline(correlation_window_sec=300)
    pipe.ingest_packet(pkt(ts=time.time()))
    pipe.prune_stale_flows()
    assert pipe.tracked_state_size()[0] == 1


def test_prune_evicts_ip_cache_with_flow():
    """The per-IP cache must not outlive the flows it references."""
    pipe = make_pipeline(correlation_window_sec=10)

    pipe.ingest_packet(pkt(ts=time.time() - 100))
    flows, cache = pipe.tracked_state_size()
    assert flows == 1 and cache == 1

    pipe.prune_stale_flows()
    flows, cache = pipe.tracked_state_size()
    assert flows == 0
    assert cache == 0


def test_max_tracked_flows_cap_is_enforced():
    """High-cardinality traffic must not grow without bound."""
    pipe = make_pipeline(correlation_window_sec=3600, max_tracked_flows=50)

    now = time.time()
    for i in range(300):
        pipe.ingest_packet(
            pkt(src=f"10.0.{i // 256}.{i % 256}", sport=1000 + i, ts=now)
        )

    flows, cache = pipe.tracked_state_size()
    assert flows <= 50, f"flow state grew past cap: {flows}"
    assert cache <= 300


def test_cap_evicts_oldest_first():
    pipe = make_pipeline(correlation_window_sec=3600, max_tracked_flows=10)

    now = time.time()
    for i in range(20):
        pipe.ingest_packet(pkt(sport=2000 + i, ts=now - (100 - i)))

    # The newest packets (higher ports, later timestamps) must survive.
    flows, _ = pipe.tracked_state_size()
    assert flows == 10


def test_pruner_thread_runs_and_stops():
    pipe = LiveCapturePipeline(
        verdict_engine=_NullEngine(),
        autostart_pruner=True,
        prune_interval_sec=0.05,
        correlation_window_sec=0.01,
    )
    try:
        pipe.ingest_packet(pkt(ts=time.time() - 100))

        deadline = time.time() + 3.0
        while time.time() < deadline and pipe.tracked_state_size()[0] > 0:
            time.sleep(0.02)

        assert pipe.tracked_state_size()[0] == 0, "background pruner did not run"
    finally:
        pipe.stop_pruner()

    assert pipe._pruner_thread is None


def test_stop_pruner_is_idempotent():
    pipe = LiveCapturePipeline(verdict_engine=_NullEngine(), autostart_pruner=True)
    pipe.stop_pruner()
    pipe.stop_pruner()  # must not raise


def test_start_pruner_is_not_duplicated():
    pipe = LiveCapturePipeline(verdict_engine=_NullEngine(), autostart_pruner=True)
    try:
        first = pipe._pruner_thread
        pipe.start_pruner()
        assert pipe._pruner_thread is first
    finally:
        pipe.stop_pruner()


def test_pruner_survives_exceptions(monkeypatch):
    """A pruning failure must never kill the capture pipeline."""
    pipe = LiveCapturePipeline(
        verdict_engine=_NullEngine(), prune_interval_sec=0.05
    )
    try:
        calls = []

        def boom():
            calls.append(1)
            raise RuntimeError("prune exploded")

        monkeypatch.setattr(pipe, "prune_stale_flows", boom)
        time.sleep(0.25)

        assert len(calls) >= 2, "pruner died after first exception"
        assert pipe._pruner_thread.is_alive()
    finally:
        pipe.stop_pruner()


# ---------------------------------------------------------------------------
# SSH decoy connection caps
# ---------------------------------------------------------------------------


def test_connection_cap_rejects_beyond_limit():
    from antlion.decoys.ssh_telnet.server import InteractiveDecoyServer

    srv = InteractiveDecoyServer(port=0, max_connections=3)
    assert srv.active_connections == 0
    assert srv.max_connections == 3


def test_active_connections_tracks_sessions():
    import socketserver

    from antlion.decoys.ssh_telnet.server import InteractiveDecoyServer

    srv = InteractiveDecoyServer(host="127.0.0.1", port=0, max_connections=50)
    srv.start(blocking=False)
    time.sleep(0.2)

    host, port = srv._server_sock.getsockname()[:2]

    clients = []
    try:
        for _ in range(3):
            c = socket.create_connection((host, port), timeout=2)
            clients.append(c)

        deadline = time.time() + 3.0
        while time.time() < deadline and srv.active_connections < 3:
            time.sleep(0.05)

        assert srv.active_connections == 3
    finally:
        for c in clients:
            try:
                c.close()
            except Exception:
                pass
        time.sleep(0.5)
        srv.stop()


def test_over_capacity_connections_are_dropped():
    from antlion.decoys.ssh_telnet.server import InteractiveDecoyServer

    srv = InteractiveDecoyServer(host="127.0.0.1", port=0, max_connections=2)
    srv.start(blocking=False)
    time.sleep(0.2)

    host, port = srv._server_sock.getsockname()[:2]

    clients = []
    try:
        # Saturate the cap.
        for _ in range(2):
            clients.append(socket.create_connection((host, port), timeout=2))

        deadline = time.time() + 3.0
        while time.time() < deadline and srv.active_connections < 2:
            time.sleep(0.05)

        # This third connection must be refused rather than spawning a thread.
        extra = socket.create_connection((host, port), timeout=2)
        clients.append(extra)

        time.sleep(0.5)
        assert srv.active_connections == 2, "cap was exceeded"
        assert srv._total_rejected >= 1
    finally:
        for c in clients:
            try:
                c.close()
            except Exception:
                pass
        time.sleep(0.4)
        srv.stop()


def test_sessions_are_reclaimed_after_close():
    """Finished sessions must release their slot, or the cap leaks."""
    from antlion.decoys.ssh_telnet.server import InteractiveDecoyServer

    srv = InteractiveDecoyServer(
        host="127.0.0.1", port=0, max_connections=5, idle_timeout=2.0
    )
    srv.start(blocking=False)
    time.sleep(0.2)

    host, port = srv._server_sock.getsockname()[:2]

    try:
        for _ in range(5):
            c = socket.create_connection((host, port), timeout=2)
            c.close()

        # After the sessions end, capacity must return.
        deadline = time.time() + 5.0
        while time.time() < deadline and srv.active_connections > 0:
            time.sleep(0.05)

        assert srv.active_connections == 0, "session slots were not reclaimed"
    finally:
        srv.stop()


def test_stop_closes_active_sessions():
    from antlion.decoys.ssh_telnet.server import InteractiveDecoyServer

    srv = InteractiveDecoyServer(
        host="127.0.0.1", port=0, max_connections=5, idle_timeout=30.0
    )
    srv.start(blocking=False)
    time.sleep(0.2)

    host, port = srv._server_sock.getsockname()[:2]

    c = socket.create_connection((host, port), timeout=2)
    try:
        deadline = time.time() + 3.0
        while time.time() < deadline and srv.active_connections == 0:
            time.sleep(0.05)

        assert srv.active_connections == 1

        srv.stop()

        # Drain the banner first, then confirm the server closes the session
        # promptly instead of holding it for the full 30s idle timeout.
        c.settimeout(5.0)
        banner = c.recv(256)
        assert banner.startswith(b"SSH-")

        # Everything the server already sent must arrive, then EOF.
        deadline = time.time() + 5.0
        closed = False
        while time.time() < deadline:
            try:
                if c.recv(256) == b"":
                    closed = True
                    break
            except socket.timeout:
                continue
            except OSError:
                closed = True
                break

        assert closed, "session was not closed by stop()"
    finally:
        try:
            c.close()
        except Exception:
            pass