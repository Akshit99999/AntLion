"""
REST API Query Layer providing a clean integration seam for frontends and SIEM systems.
"""

from __future__ import annotations

import hmac
import logging
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse

from antlion.core.config import DEFAULT_CONFIG, AntlionConfig
from antlion.core.metrics import REGISTRY, publish_intel_gauges, set_database_gauges
from antlion.query.dashboard import DASHBOARD_HTML
from antlion.query.export import export_verdicts
from antlion.storage.database import AntlionDatabase
from antlion.storage.prune import RetentionManager

logger = logging.getLogger("antlion.query.api")


def refresh_database_gauges(database: AntlionDatabase, enricher=None) -> None:
    """Updates scrape-time gauges from persisted state.

    Failures are swallowed: a metrics scrape must never take down the API or
    surface a database error to a monitoring system as a 500.
    """
    try:
        stats = database.get_system_stats()
        set_database_gauges(
            registry=REGISTRY,
            total_verdicts=int(stats.get("total_verdicts", 0)),
            distinct_attackers=int(stats.get("distinct_attackers", 0)),
            decoy_events=int(stats.get("total_decoy_hits", 0)),
            flow_records=int(stats.get("total_flows_monitored", 0)),
        )
    except Exception as e:
        logger.debug("Database gauge refresh failed: %s", e)

    if enricher is not None:
        try:
            publish_intel_gauges(enricher.cache_stats())
        except Exception as e:
            logger.debug("Intel gauge refresh failed: %s", e)


def create_query_api(
    db: Optional[AntlionDatabase] = None,
    config: Optional[AntlionConfig] = None,
    enricher=None,
) -> FastAPI:
    """Creates the FastAPI REST query interface.

    Data routes under /api/v1 are protected by a shared API key when
    ANTLION_API_KEY is configured. This API exposes attacker dossiers
    including captured credentials, so it fails closed when a key is set
    and warns loudly when it is not.
    """
    database = db or AntlionDatabase()
    config = config or DEFAULT_CONFIG
    api_key = config.api_key

    if not api_key:
        logger.warning(
            "ANTLION_API_KEY is not set — /api/v1 data routes are UNPROTECTED "
            "and expose captured credentials. Set ANTLION_API_KEY before "
            "exposing this service beyond localhost."
        )

    app = FastAPI(
        title="Antlion Threat Intelligence & Verdict API",
        description=(
            "Query and integration seam for Antlion honeypot verdicts, "
            "attacker forensic timelines, and platform analytics."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Explicit allowlist only. A wildcard origin combined with credentials would
    # let any website read threat intelligence from a SOC operator's browser.
    origins = list(config.cors_origins) or ["http://localhost:8000"]
    if "*" in origins:
        logger.warning(
            "ANTLION_CORS_ORIGINS contains '*'. Wildcard origins with "
            "credentials are unsafe; falling back to localhost."
        )
        origins = ["http://localhost:8000", "http://127.0.0.1:8000"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key", "Authorization"],
    )

    def require_api_key(
        x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
        authorization: Optional[str] = Header(None),
    ) -> None:
        """Validates the shared API key on protected data routes."""
        if not api_key:
            # No key configured: allow, but the warning above already fired.
            return

        supplied = x_api_key
        if not supplied and authorization:
            parts = authorization.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == "bearer":
                supplied = parts[1].strip()

        if not supplied or not hmac.compare_digest(supplied, api_key):
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing API key. Provide X-API-Key or a Bearer token.",
            )

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
    async def dashboard_view():
        """Serves the interactive cybersecurity SOC threat console."""
        return HTMLResponse(content=DASHBOARD_HTML, status_code=200)

    @app.get("/api/v1/health", tags=["System"])
    async def health() -> Dict[str, str]:
        """Health check endpoint."""
        return {"status": "healthy", "service": "antlion-query-api"}

    @app.get("/api/v1/verdicts", tags=["Verdicts"])
    async def list_verdicts(
        _auth: None = Depends(require_api_key),
        limit: int = Query(50, ge=1, le=500, description="Max verdicts to retrieve"),
        source_ip: Optional[str] = Query(None, description="Filter by source IP address"),
        severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
        attack_type: Optional[str] = Query(None, description="Filter by attack category"),
    ) -> List[Dict[str, Any]]:
        """Retrieves paginated verdicts filtered by IP, severity, or attack family."""
        return database.query_verdicts(
            limit=limit,
            source_ip=source_ip,
            severity=severity,
            attack_type=attack_type,
        )

    @app.get("/api/v1/verdicts/{verdict_id}", tags=["Verdicts"])
    async def get_verdict(
        verdict_id: str, _auth: None = Depends(require_api_key)
    ) -> Dict[str, Any]:
        """Retrieves a single threat verdict by its UUID."""
        verdict = database.get_verdict(verdict_id)
        if not verdict:
            raise HTTPException(status_code=404, detail="Verdict not found")
        return verdict

    @app.get("/api/v1/intel/{source_ip}", tags=["Threat Intelligence"])
    async def get_ip_intelligence(
        source_ip: str, _auth: None = Depends(require_api_key)
    ) -> Dict[str, Any]:
        """Retrieves comprehensive forensic dossier and interaction timeline for a given IP."""
        return database.get_ip_intel(source_ip)

    @app.get(
        "/api/v1/export/verdicts.csv",
        tags=["Export"],
        response_class=PlainTextResponse,
    )
    async def export_verdicts_csv(
        limit: int = Query(1000, ge=1, le=10000),
        source_ip: Optional[str] = Query(None),
        severity: Optional[str] = Query(None),
        _auth: None = Depends(require_api_key),
    ) -> str:
        """Exports verdicts as flattened CSV for analyst and pipeline use."""
        return export_verdicts(
            db=database, fmt="csv", limit=limit, source_ip=source_ip, severity=severity
        )

    @app.get(
        "/api/v1/export/verdicts.json",
        tags=["Export"],
        response_class=PlainTextResponse,
    )
    async def export_verdicts_json(
        limit: int = Query(1000, ge=1, le=10000),
        source_ip: Optional[str] = Query(None),
        _auth: None = Depends(require_api_key),
    ) -> str:
        """Exports verdicts as JSON."""
        return export_verdicts(
            db=database, fmt="json", limit=limit, source_ip=source_ip
        )

    @app.get(
        "/api/v1/export/stix",
        tags=["Export"],
        response_class=PlainTextResponse,
    )
    async def export_verdicts_stix(
        limit: int = Query(1000, ge=1, le=10000),
        source_ip: Optional[str] = Query(None),
        _auth: None = Depends(require_api_key),
    ) -> str:
        """Exports verdicts as a STIX 2.1 bundle for threat-intel platforms."""
        return export_verdicts(
            db=database, fmt="stix", limit=limit, source_ip=source_ip
        )

    @app.get(
        "/api/v1/retention/status",
        tags=["Maintenance"],
    )
    async def retention_status(
        _auth: None = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """Reports how many records the next retention sweep would delete."""
        manager = RetentionManager(
            db=database, retention_days=config.retention_days
        )
        return {
            "retention_days": manager.retention_days,
            "enabled": manager.enabled,
            "cutoff": manager.cutoff() if manager.enabled else None,
            "expired_counts": manager.count_expired() if manager.enabled else {},
        }

    @app.post(
        "/api/v1/retention/prune",
        tags=["Maintenance"],
    )
    async def retention_prune_now(
        _auth: None = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """Triggers an immediate retention sweep."""
        manager = RetentionManager(
            db=database, retention_days=config.retention_days
        )
        if not manager.enabled:
            return {"enabled": False, "detail": "Retention is disabled."}
        result = manager.prune_once()
        return {"enabled": True, **result.to_dict()}

    @app.get(
        "/metrics",
        response_class=PlainTextResponse,
        tags=["Observability"],
        include_in_schema=False,
    )
    async def prometheus_metrics() -> str:
        """Exposes Prometheus metrics in the text exposition format.

        Deliberately unauthenticated: Prometheus scrapers conventionally reach
        the endpoint over an internal network, and the payload contains only
        aggregate counters and gauges — no captured credentials, no attacker
        IPs, no verdict detail.
        """
        refresh_database_gauges(database, enricher)
        return REGISTRY.render()

    @app.get("/api/v1/stats", tags=["Analytics"])
    async def get_system_stats(
        _auth: None = Depends(require_api_key)
    ) -> Dict[str, Any]:
        """Aggregates platform statistics, threat category breakdown, and top attacker rankings."""
        return database.get_system_stats()

    return app
