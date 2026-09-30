"""
Tests for Antlion Decoy Layer (SSH/Telnet and Web Decoys).
"""

import socket
import tempfile
import time

import pytest
from fastapi.testclient import TestClient

from antlion.core.config import AntlionConfig
from antlion.core.types import AttackCategory, DecoyServiceType, SeverityLevel
from antlion.decoys.ssh_telnet.banner import CustomBannerGenerator
from antlion.decoys.ssh_telnet.filesystem import FakeFilesystem
from antlion.decoys.ssh_telnet.server import InteractiveDecoyServer
from antlion.decoys.web.app import create_web_decoy_app
from antlion.storage.database import AntlionDatabase
from antlion.verdict.engine import VerdictEngine


@pytest.fixture
def test_engine():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        db = AntlionDatabase(tmp.name)
        config = AntlionConfig()
        yield VerdictEngine(config=config, db=db)


def test_banner_and_motd_generation():
    banner = CustomBannerGenerator.get_ssh_banner()
    assert "OpenSSH" in banner
    assert "Cowrie" not in banner

    hostname = CustomBannerGenerator.get_hostname()
    assert len(hostname) > 0

    motd = CustomBannerGenerator.get_motd(hostname)
    assert hostname in motd or "Ubuntu" in motd
    assert "NOTICE: Authorized access only" in motd

    cowrie_cfg = CustomBannerGenerator.export_cowrie_overrides(hostname)
    assert f"hostname = {hostname}" in cowrie_cfg


def test_fake_filesystem_commands():
    fs = FakeFilesystem(hostname="test-host")

    out, code = fs.execute_command("uname -a")
    assert code == 0
    assert "test-host" in out
    assert "Linux" in out

    out, code = fs.execute_command("whoami")
    assert code == 0
    assert out.strip() == "root"

    out, code = fs.execute_command("id")
    assert code == 0
    assert "uid=0(root)" in out

    out, code = fs.execute_command("cat /etc/passwd")
    assert code == 0
    assert "root:x:0:0" in out
    assert "deploy:x:1000:1000" in out

    out, code = fs.execute_command("cat /proc/version")
    assert code == 0
    assert "Linux version" in out

    out, code = fs.execute_command("cd /var/log")
    assert code == 0
    assert fs.cwd == "/var/log"

    out, code = fs.execute_command("ls -la")
    assert code == 0
    assert "total" in out

    out, code = fs.execute_command("invalid_unknown_tool")
    assert code == 127
    assert "command not found" in out


def test_web_decoy_endpoints_and_telemetry(test_engine):
    app = create_web_decoy_app(verdict_engine=test_engine)
    client = TestClient(app)

    # 1. Probe login page
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "InfraOps Cluster Console" in resp.text

    # 2. Authentication probe with known botnet credentials
    post_resp = client.post(
        "/login",
        data={"username": "root", "password": "password"},
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    )
    assert post_resp.status_code == 401
    assert post_resp.json()["code"] == "INVALID_CORPORATE_SSO_CREDENTIALS"

    # Verify verdict generated
    verdicts = test_engine.get_recent_verdicts()
    assert len(verdicts) >= 1
    recent = verdicts[0]
    assert recent["target_service"] == DecoyServiceType.WEB_ADMIN.value

    # 3. Path traversal exploit probe
    exploit_resp = client.get(
        "/config/backup?file=../../../../etc/passwd",
        headers={"User-Agent": "sqlmap/1.6"},
    )
    assert exploit_resp.status_code == 200
    assert "root:x:0:0:root" in exploit_resp.text

    # Check that high severity web exploit verdict was triggered
    all_verdicts = test_engine.get_recent_verdicts(limit=10)
    exploit_verdicts = [
        v for v in all_verdicts if v["attack_type"] == AttackCategory.WEB_EXPLOIT.value
    ]
    assert len(exploit_verdicts) >= 1
    assert exploit_verdicts[0]["severity"] in (
        SeverityLevel.HIGH.value,
        SeverityLevel.CRITICAL.value,
    )


def test_interactive_decoy_server_socket(test_engine):
    # Find free port for test
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        test_port = s.getsockname()[1]

    server = InteractiveDecoyServer(
        host="127.0.0.1",
        port=test_port,
        service_type=DecoyServiceType.SSH,
        hostname="test-node-01",
        verdict_engine=test_engine,
    )
    server.start(blocking=False)
    time.sleep(0.1)

    try:
        # Connect client socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(5.0)
            client.connect(("127.0.0.1", test_port))

            # Read banner & login prompt
            data = b""
            while b"login: " not in data:
                chunk = client.recv(1024)
                if not chunk:
                    break
                data += chunk

            assert b"OpenSSH" in data
            assert b"login: " in data

            # Send username
            client.sendall(b"root\n")

            # Read password prompt
            data = client.recv(1024)
            assert b"Password: " in data

            # Send password
            client.sendall(b"vizkey\n")

            # Read prompt
            time.sleep(0.2)
            motd_and_prompt = client.recv(4096)
            assert b"Ubuntu" in motd_and_prompt

            # Send command
            client.sendall(b"id\n")
            time.sleep(0.1)
            cmd_out = client.recv(1024)
            assert b"uid=0(root)" in cmd_out

            client.sendall(b"exit\n")

        time.sleep(0.2)
        # Verify that verdict engine recorded events
        verdicts = test_engine.get_recent_verdicts()
        assert len(verdicts) >= 2
        categories = [v["attack_type"] for v in verdicts]
        assert any("Botnet" in c or "Credential" in c or "Command" in c for c in categories)

    finally:
        server.stop()
