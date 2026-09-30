"""
IP Threat Intelligence & Geolocation/ASN Enrichment Engine.
Identifies host provider, Tor exit relays, bulletproof hosters, and country origins.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

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

    def to_dict(self) -> Dict[str, Any]:
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
        }


class IPThreatEnricher:
    """Caches and resolves IP intelligence metadata with offline heuristics fallback."""

    # Curated known bulletproof / high-abuse hosting keywords
    HIGH_ABUSE_PROVIDERS = [
        "digitalocean", "ovh", "linode", "vultr", "hetzner", "choopa",
        "m247", "scaleway", "cogent", "bulletproof", "leaseweb", "tor-exit",
    ]

    def __init__(self, enable_live_lookup: bool = True):
        self.enable_live_lookup = enable_live_lookup
        # In-memory cache to prevent redundant queries
        self._cache: Dict[str, IPProfile] = {}

    def enrich(self, ip_str: str) -> IPProfile:
        """Enriches an IP with geolocation, ASN, and hosting risk scoring."""
        if ip_str in self._cache:
            return self._cache[ip_str]

        # 1. Check for private/loopback/RFC1918 addresses
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                profile = IPProfile(
                    ip=ip_str,
                    country="Private Network",
                    country_code="LAN",
                    city="Internal / Localhost",
                    asn="AS0",
                    isp="RFC1918 Private Range",
                    org="Internal / Localhost",
                    is_private=True,
                    risk_score=0.10,
                )
                self._cache[ip_str] = profile
                return profile
        except ValueError:
            pass

        # 2. Query public endpoint with strict 1.5s timeout
        profile = self._resolve_public_ip(ip_str)
        self._cache[ip_str] = profile
        return profile

    def _resolve_public_ip(self, ip_str: str) -> IPProfile:
        """Attempts live resolution or produces a structured offline fallback."""
        if not self.enable_live_lookup:
            return IPProfile(ip=ip_str, country="External Internet", risk_score=0.50)

        try:
            url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,city,isp,org,as,hosting,proxy"
            req = urllib.request.Request(
                url, headers={"User-Agent": "Antlion-Threat-Intel/0.1.0"}
            )
            with urllib.request.urlopen(req, timeout=1.5) as resp:
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
                )
        except Exception as e:
            logger.debug("Live IP enrichment skipped for %s: %s", ip_str, e)

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
        )
