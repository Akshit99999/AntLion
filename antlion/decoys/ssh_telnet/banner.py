"""
Custom anti-fingerprinting banners, MOTD, and host identity generator for SSH and Telnet decoys.
"""

from __future__ import annotations

import random
from typing import Dict, List


class CustomBannerGenerator:
    """Generates realistic server banners and configurations avoiding stock honeypot fingerprints."""

    REALISTIC_SSH_BANNERS: List[str] = [
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
        "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
        "SSH-2.0-OpenSSH_8.7p1-38.el9_4.x86_64",
    ]

    REALISTIC_HOSTNAMES: List[str] = [
        "prod-api-gw-01",
        "core-infra-node-02",
        "app-cluster-worker-03",
        "bastion-internal-vpc",
        "edge-proxy-lon-01",
    ]

    @classmethod
    def get_ssh_banner(cls, seed: int | None = None) -> str:
        """Returns an authentic OpenSSH banner string."""
        rng = random.Random(seed)
        return rng.choice(cls.REALISTIC_SSH_BANNERS)

    @classmethod
    def get_hostname(cls, seed: int | None = None) -> str:
        """Returns a plausible enterprise hostname."""
        rng = random.Random(seed)
        return rng.choice(cls.REALISTIC_HOSTNAMES)

    @classmethod
    def get_motd(cls, hostname: str = "prod-api-gw-01") -> str:
        """Generates an authentic Ubuntu 22.04 LTS terminal MOTD."""
        return (
            f"\r\n"
            f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n"
            f" * Documentation:  https://help.ubuntu.com\r\n"
            f" * Management:     https://landscape.canonical.com\r\n"
            f" * Support:        https://ubuntu.com/pro\r\n\r\n"
            f" System information as of Wed Sep 30 19:42:01 UTC 2026\r\n\r\n"
            f"  System load:  0.18               Processes:             142\r\n"
            f"  Usage of /:   34.2% of 48.29GB   Users logged in:       1\r\n"
            f"  Memory usage: 28%                IPv4 address for eth0: 10.0.1.14\r\n"
            f"  Swap usage:   0%\r\n\r\n"
            f"========================================================================\r\n"
            f" NOTICE: Authorized access only. All activities are actively logged and\r\n"
            f" monitored under corporate security compliance policy (SOC2 / ISO27001).\r\n"
            f"========================================================================\r\n\r\n"
            f"Last login: Tue Sep 29 14:18:02 2026 from 10.0.1.2\r\n"
        )

    @classmethod
    def export_cowrie_overrides(cls, hostname: str = "core-infra-01") -> str:
        """Emits Cowrie configuration file overrides stripping default fingerprints."""
        ssh_banner = cls.get_ssh_banner()
        return (
            f"# Auto-generated Antlion Cowrie Anti-Fingerprint Profile\n"
            f"[honeypot]\n"
            f"hostname = {hostname}\n"
            f"ssh_version_string = {ssh_banner}\n"
            f"reported_ssh_port = 22\n"
            f"fake_addr = 10.0.1.14\n"
            f"timezone = UTC\n"
            f"\n"
            f"[ssh]\n"
            f"enabled = true\n"
            f"version = {ssh_banner}\n"
            f"listen_endpoints = tcp:2222:interface=0.0.0.0\n"
            f"\n"
            f"[telnet]\n"
            f"enabled = true\n"
            f"listen_endpoints = tcp:2323:interface=0.0.0.0\n"
        )
