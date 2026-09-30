"""
Alerting & SIEM Webhook Dispatcher for Antlion threat verdicts.
Supports Slack, Discord, Generic JSON webhooks, and Common Event Format (CEF) logging.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.request
from typing import Any, Dict, List, Optional

from antlion.core.types import SeverityLevel, Verdict

logger = logging.getLogger("antlion.alerts.dispatcher")


class AlertDispatcher:
    """Dispatches high-severity intrusion alerts to configured SIEMs and chat webhooks."""

    def __init__(
        self,
        webhook_urls: Optional[List[str]] = None,
        min_severity: SeverityLevel = SeverityLevel.HIGH,
    ):
        self.webhook_urls: List[str] = webhook_urls or []
        self.min_severity = min_severity

    def notify(self, verdict: Verdict) -> None:
        """Asynchronously dispatches alerts if verdict severity meets threshold."""
        severity_order = {
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }

        verdict_rank = severity_order.get(verdict.severity, 1)
        thresh_rank = severity_order.get(self.min_severity, 3)

        if verdict_rank < thresh_rank:
            return

        # Format Common Event Format log entry
        cef_entry = self.format_cef(verdict)
        logger.warning("[SIEM-CEF] %s", cef_entry)

        if not self.webhook_urls:
            return

        # Spawn asynchronous non-blocking worker thread
        t = threading.Thread(
            target=self._send_webhooks, args=(verdict,), daemon=True
        )
        t.start()

    def format_cef(self, v: Verdict) -> str:
        """Formats verdict into industry standard Common Event Format (CEF)."""
        severity_num = 10 if v.severity == SeverityLevel.CRITICAL else (8 if v.severity == SeverityLevel.HIGH else 5)
        attack_clean = v.attack_type.value.replace("|", "/")
        return (
            f"CEF:0|Antlion|Honeypot-IDS|0.1.0|{attack_clean}|{attack_clean}|{severity_num}|"
            f"src={v.source_ip} dproc={v.target_service} "
            f"cn1={round(v.confidence, 2)} cn1Label=Confidence "
            f"msg=Intrusion captured in decoy pit"
        )

    def _send_webhooks(self, verdict: Verdict) -> None:
        for url in self.webhook_urls:
            try:
                # Detect Discord vs Slack vs Generic Webhook
                if "discord.com" in url:
                    payload = self._build_discord_payload(verdict)
                elif "slack.com" in url:
                    payload = self._build_slack_payload(verdict)
                else:
                    payload = {"event": "antlion_intrusion_alert", "verdict": verdict.to_dict()}

                req_data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    url,
                    data=req_data,
                    headers={"Content-Type": "application/json", "User-Agent": "Antlion-Alerts/0.1.0"},
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    pass
            except Exception as e:
                logger.debug("Failed delivering webhook to %s: %s", url, e)

    def _build_discord_payload(self, v: Verdict) -> Dict[str, Any]:
        color = 0xDC2626 if v.severity == SeverityLevel.CRITICAL else 0xF59E0B
        return {
            "embeds": [
                {
                    "title": f"🚨 Antlion Alert: {v.attack_type.value}",
                    "color": color,
                    "fields": [
                        {"name": "Source IP", "value": f"`{v.source_ip}`", "inline": True},
                        {"name": "Severity", "value": f"**{v.severity.value}**", "inline": True},
                        {"name": "Confidence", "value": f"`{v.confidence:.2f}`", "inline": True},
                        {"name": "Decoy Target", "value": f"`{v.target_service}`", "inline": True},
                        {"name": "Timestamp", "value": v.timestamp.isoformat(), "inline": False},
                    ],
                    "footer": {"text": "Antlion Defensive Threat Intelligence"},
                }
            ]
        }

    def _build_slack_payload(self, v: Verdict) -> Dict[str, Any]:
        return {
            "text": (
                f"*🚨 [Antlion Alert]* *{v.severity.value}* - {v.attack_type.value}\n"
                f"• *Attacker IP*: `{v.source_ip}`\n"
                f"• *Target Decoy*: `{v.target_service}`\n"
                f"• *Confidence*: `{v.confidence:.2f}`"
            )
        }
