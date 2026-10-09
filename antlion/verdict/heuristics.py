"""
Behavioral heuristics engine for Antlion.

Analyzes connection rates, credential dictionaries, user-agents, command
sequences, and web attack signatures.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Tuple

from antlion.core.types import DecoyEvent, HeuristicMatch, SeverityLevel
from antlion.intel.enricher import IPThreatEnricher


class BehavioralHeuristicsEngine:
    """Evaluates incoming decoy events against behavioral heuristic rules."""

    # Curated dictionary of known botnet, IoT, and default SSH/Telnet credentials
    KNOWN_BAD_CREDENTIALS: set[Tuple[str, str]] = {
        ("root", "vizkey"),
        ("root", "xc3511"),
        ("root", "root"),
        ("root", "admin"),
        ("root", "123456"),
        ("root", "default"),
        ("root", "toor"),
        ("root", "password"),
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", "123456"),
        ("support", "support"),
        ("guest", "guest"),
        ("user", "user"),
        ("pi", "raspberry"),
        ("ubnt", "ubnt"),
        ("default", "default"),
        ("test", "test"),
        ("oracle", "oracle"),
        ("service", "service"),
    }

    KNOWN_BAD_PASSWORDS: set[str] = {
        "admin", "root", "123456", "password", "12345678", "qwerty",
        "1234", "default", "vizkey", "xc3511", "toor", "raspberry",
    }

    # Reconnaissance scanners, automated exploit tool User-Agents
    SUSPICIOUS_UA_PATTERNS = [
        re.compile(r"sqlmap", re.IGNORECASE),
        re.compile(r"nikto", re.IGNORECASE),
        re.compile(r"masscan", re.IGNORECASE),
        re.compile(r"nmap", re.IGNORECASE),
        re.compile(r"zgrab", re.IGNORECASE),
        re.compile(r"gobuster", re.IGNORECASE),
        re.compile(r"dirbuster", re.IGNORECASE),
        re.compile(r"ffuf", re.IGNORECASE),
        re.compile(r"hydra", re.IGNORECASE),
        re.compile(r"metasploit", re.IGNORECASE),
        re.compile(r"python-requests", re.IGNORECASE),
        re.compile(r"go-http-client", re.IGNORECASE),
        re.compile(r"curl/", re.IGNORECASE),
        re.compile(r"wget/", re.IGNORECASE),
        re.compile(r"shodan", re.IGNORECASE),
        re.compile(r"censys", re.IGNORECASE),
    ]

    # Command sequence regex patterns categorized by attack lifecycle
    CMD_PATTERNS = [
        (
            "CMD_REVERSE_SHELL",
            re.compile(r"(bash\s+-i\s+>&|/dev/tcp/|nc\s+-e|mkfifo\s+/tmp/|python.*socket.*pty)", re.IGNORECASE),
            0.95,
            SeverityLevel.CRITICAL,
            "Interactive reverse shell invocation attempt",
        ),
        (
            "CMD_DROPPER_DOWNLOAD",
            re.compile(r"(curl\s+-[fsSLkO].*\|\s*(sh|bash)|wget\s+.*-O\s+/tmp/|tftp\s+-g|fetch\s+http)", re.IGNORECASE),
            0.92,
            SeverityLevel.CRITICAL,
            "Malicious secondary payload / dropper retrieval",
        ),
        (
            "CMD_PERSISTENCE",
            re.compile(r"(crontab\s+-e|/etc/cron|/etc/rc\.local|systemctl\s+enable|\.bashrc)", re.IGNORECASE),
            0.85,
            SeverityLevel.HIGH,
            "Host persistence mechanism installation attempt",
        ),
        (
            "CMD_CRED_RECON",
            re.compile(r"(cat\s+/etc/shadow|cat\s+/etc/passwd|cat\s+~?/\.ssh/id_rsa|cat\s+/root/\.ssh/)", re.IGNORECASE),
            0.78,
            SeverityLevel.HIGH,
            "Credential store and SSH key reconnaissance",
        ),
        (
            "CMD_SYSTEM_RECON",
            # 'id' is anchored on word boundaries: without this the bare
            # alternative matches inside innocent words like 'vid' or 'gridctl'.
            re.compile(
                r"(uname\s+-[amrv]|cat\s+/proc/cpuinfo|ifconfig|ip\s+addr|whoami"
                r"|(?<![a-z0-9_-])id(?![a-z0-9_-])|uptime|lscpu)",
                re.IGNORECASE,
            ),
            0.60,
            SeverityLevel.MEDIUM,
            "Host environment, architecture, and network discovery",
        ),
        (
            "CMD_DEFENSE_EVASION",
            re.compile(r"(history\s+-c|rm\s+-[rf].*log|touch\s+-t|unset\s+HISTFILE)", re.IGNORECASE),
            0.88,
            SeverityLevel.HIGH,
            "Log wiping and defense evasion command sequence",
        ),
    ]

    # Web payload attack signatures
    WEB_PATTERNS = [
        (
            "WEB_SQL_INJECTION",
            re.compile(r"('|\%27)\s*(or|and)\s*('|\d+)=\1|union\s+select|sleep\(\d+\)|information_schema", re.IGNORECASE),
            0.90,
            SeverityLevel.CRITICAL,
            "SQL injection exploit attempt in path or body",
        ),
        (
            "WEB_PATH_TRAVERSAL",
            re.compile(r"(\.\./|\.\.\\|\%2e\%2e\%2f|/etc/passwd|win\.ini|boot\.ini)", re.IGNORECASE),
            0.85,
            SeverityLevel.HIGH,
            "Local file inclusion / path traversal attempt",
        ),
        (
            "WEB_COMMAND_EXEC",
            re.compile(r"(;\s*(id|whoami|cat|ls|uname)|`.*`|\$\(.*\)|php://|data://|\$\{jndi:)", re.IGNORECASE),
            0.95,
            SeverityLevel.CRITICAL,
            "Remote command execution or JNDI injection payload",
        ),
        (
            "WEB_SENSITIVE_PROBE",
            re.compile(r"(/\.env|/\.git/HEAD|/wp-config\.php|/actuator/health|/phpmyadmin|/console/login)", re.IGNORECASE),
            0.75,
            SeverityLevel.MEDIUM,
            "Probe targeting sensitive configuration files or admin endpoints",
        ),
    ]

    def __init__(
        self,
        rate_window_seconds: int = 60,
        burst_threshold: int = 8,
        enricher: Optional[IPThreatEnricher] = None,
    ):
        self.rate_window_seconds = rate_window_seconds
        self.burst_threshold = burst_threshold
        self.enricher = enricher or IPThreatEnricher()
        # Sliding history per IP: deque of timestamps
        self._ip_history: Dict[str, Deque[float]] = defaultdict(deque)
        # Port targeting history per IP: deque of (timestamp, port)
        self._ip_port_history: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)

    def evaluate_event(self, event: DecoyEvent) -> List[HeuristicMatch]:
        """Runs all applicable behavioral heuristic rules against a decoy event."""
        matches: List[HeuristicMatch] = []

        # 1. Connection rate & burst evaluation
        rate_matches = self._check_rate_heuristics(
            event.source_ip, event.source_port, event.event_timestamp
        )
        matches.extend(rate_matches)

        # 2. Credential heuristics (for SSH / Telnet / Web Auth)
        if event.username or event.password:
            cred_match = self._check_credentials(event.username, event.password)
            if cred_match:
                matches.append(cred_match)

        # 3. User-Agent analysis (for Web Decoy)
        if event.http_headers:
            ua_match = self._check_user_agent(event.http_headers)
            if ua_match:
                matches.append(ua_match)

        # 4. Command sequence analysis (for SSH / Telnet decoy shell)
        if event.commands:
            cmd_matches = self._check_command_sequences(event.commands)
            matches.extend(cmd_matches)

        # 5. Web payload and path inspection
        if event.http_path or event.http_payload:
            web_matches = self._check_web_signatures(event.http_path, event.http_payload)
            matches.extend(web_matches)

        # 6. ASN, Hosting, & Tor threat intelligence evaluation
        intel_match = self._check_ip_threat_intel(event.source_ip)
        if intel_match:
            matches.append(intel_match)

        return matches

    def _check_ip_threat_intel(self, ip_str: str) -> Optional[HeuristicMatch]:
        """Evaluates whether attacker IP belongs to an anonymous proxy or abuse hosting provider."""
        if not self.enricher:
            return None
        profile = self.enricher.enrich(ip_str)
        if profile.is_tor_proxy:
            return HeuristicMatch(
                rule_id="RULE_TOR_PROXY_INTRUSION",
                rule_name="Anonymized Tor Exit Node Probe",
                score=0.88,
                severity=SeverityLevel.HIGH,
                description=f"Inbound traffic originates from verified Tor relay / anonymous proxy ({profile.country})",
                metadata=profile.to_dict(),
            )
        if profile.is_hosting:
            return HeuristicMatch(
                rule_id="RULE_HOSTING_ABUSE_INFRA",
                rule_name="Commercial Cloud / Bulletproof Host Scanner",
                score=0.78,
                severity=SeverityLevel.MEDIUM,
                description=f"Traffic originated from commercial datacenter/hosting ASN ({profile.isp}, {profile.country})",
                metadata=profile.to_dict(),
            )
        return None

    def _check_rate_heuristics(
        self, ip: str, port: int, event_time: datetime
    ) -> List[HeuristicMatch]:
        matches: List[HeuristicMatch] = []
        now_ts = event_time.timestamp()
        cutoff = now_ts - self.rate_window_seconds

        # Clean old timestamps
        history = self._ip_history[ip]
        while history and history[0] < cutoff:
            history.popleft()
        history.append(now_ts)

        # Burst rate check
        recent_count = len(history)
        if recent_count >= self.burst_threshold:
            score = min(1.0, 0.60 + 0.05 * (recent_count - self.burst_threshold))
            severity = SeverityLevel.HIGH if recent_count >= self.burst_threshold * 2 else SeverityLevel.MEDIUM
            matches.append(
                HeuristicMatch(
                    rule_id="RULE_RATE_BURST",
                    rule_name="Connection Burst Anomaly",
                    score=score,
                    severity=severity,
                    description=(
                        f"IP executed {recent_count} requests in "
                        f"{self.rate_window_seconds}s (threshold: {self.burst_threshold})"
                    ),
                    metadata={"request_count": recent_count, "window_seconds": self.rate_window_seconds},
                )
            )

        # Port sweep check
        port_history = self._ip_port_history[ip]
        while port_history and port_history[0][0] < cutoff:
            port_history.popleft()
        port_history.append((now_ts, port))

        unique_ports = {p for _, p in port_history}
        if len(unique_ports) >= 4:
            matches.append(
                HeuristicMatch(
                    rule_id="RULE_PORT_SWEEP",
                    rule_name="Multi-Port Sweep Reconnaissance",
                    score=0.82,
                    severity=SeverityLevel.HIGH,
                    description=f"IP connected across {len(unique_ports)} distinct ports within window",
                    metadata={"unique_ports": list(unique_ports)},
                )
            )

        return matches

    def _check_credentials(
        self, username: Optional[str], password: Optional[str]
    ) -> Optional[HeuristicMatch]:
        u = (username or "").strip().lower()
        p = (password or "").strip()

        # Check known dictionary pairs
        if (u, p) in self.KNOWN_BAD_CREDENTIALS:
            return HeuristicMatch(
                rule_id="RULE_KNOWN_BOTNET_CRED",
                rule_name="Known Botnet/Mirai Credential Pair",
                score=0.94,
                severity=SeverityLevel.HIGH,
                description=f"Exact match for known botnet default credential pair ({u}:***)",
                metadata={"username": u, "credential_type": "botnet_dictionary"},
            )

        # Check common password
        if p in self.KNOWN_BAD_PASSWORDS:
            return HeuristicMatch(
                rule_id="RULE_DICTIONARY_PASSWORD",
                rule_name="Common Default Password Attempt",
                score=0.80,
                severity=SeverityLevel.MEDIUM,
                description=f"Supplied password '{p}' is a high-frequency dictionary attack item",
                metadata={"username": u, "password_length": len(p)},
            )

        return None

    def _check_user_agent(self, headers: Dict[str, str]) -> Optional[HeuristicMatch]:
        # Normalize header keys to lowercase
        norm_headers = {k.lower(): v for k, v in headers.items()}
        ua = norm_headers.get("user-agent", "").strip()

        if not ua:
            return HeuristicMatch(
                rule_id="RULE_MISSING_UA",
                rule_name="Omitted/Empty User-Agent Header",
                score=0.65,
                severity=SeverityLevel.LOW,
                description="Client sent HTTP request with missing or empty User-Agent",
                metadata={"user_agent": ""},
            )

        for pattern in self.SUSPICIOUS_UA_PATTERNS:
            if pattern.search(ua):
                return HeuristicMatch(
                    rule_id="RULE_SCANNER_UA",
                    rule_name="Offensive Scanner / Tool User-Agent",
                    score=0.89,
                    severity=SeverityLevel.HIGH,
                    description=f"User-Agent matched automated penetration/recon tool signature: '{ua}'",
                    metadata={"user_agent": ua, "matched_pattern": pattern.pattern},
                )

        return None

    def _check_command_sequences(self, commands: List[str]) -> List[HeuristicMatch]:
        matches: List[HeuristicMatch] = []
        joined_commands = " \n ".join(commands)

        for rule_id, pattern, score, severity, desc in self.CMD_PATTERNS:
            found = pattern.findall(joined_commands)
            if found:
                matches.append(
                    HeuristicMatch(
                        rule_id=rule_id,
                        rule_name=rule_id.replace("_", " ").title(),
                        score=score,
                        severity=severity,
                        description=desc,
                        metadata={"commands_matched": len(found), "sample_matches": [str(m) for m in found[:3]]},
                    )
                )

        return matches

    def _check_web_signatures(
        self, path: Optional[str], payload: Optional[str]
    ) -> List[HeuristicMatch]:
        matches: List[HeuristicMatch] = []
        target_corpus = f"{path or ''} {payload or ''}"

        for rule_id, pattern, score, severity, desc in self.WEB_PATTERNS:
            match = pattern.search(target_corpus)
            if match:
                matches.append(
                    HeuristicMatch(
                        rule_id=rule_id,
                        rule_name=rule_id.replace("_", " ").title(),
                        score=score,
                        severity=severity,
                        description=desc,
                        metadata={"matched_substring": match.group(0)},
                    )
                )

        return matches
