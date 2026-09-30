"""
REST API Query Layer providing a clean integration seam for frontends and SIEM systems.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from antlion.storage.database import AntlionDatabase

logger = logging.getLogger("antlion.query.api")


def create_query_api(db: Optional[AntlionDatabase] = None) -> FastAPI:
    """Creates the FastAPI REST query interface."""
    database = db or AntlionDatabase()

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

    # Enable CORS for frontend integrations
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/v1/health", tags=["System"])
    async def health() -> Dict[str, str]:
        """Health check endpoint."""
        return {"status": "healthy", "service": "antlion-query-api"}

    @app.get("/api/v1/verdicts", tags=["Verdicts"])
    async def list_verdicts(
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
    async def get_verdict(verdict_id: str) -> Dict[str, Any]:
        """Retrieves a single threat verdict by its UUID."""
        verdict = database.get_verdict(verdict_id)
        if not verdict:
            raise HTTPException(status_code=404, detail="Verdict not found")
        return verdict

    @app.get("/api/v1/intel/{source_ip}", tags=["Threat Intelligence"])
    async def get_ip_intelligence(source_ip: str) -> Dict[str, Any]:
        """Retrieves comprehensive forensic dossier and interaction timeline for a given IP."""
        return database.get_ip_intel(source_ip)

    @app.get("/api/v1/stats", tags=["Analytics"])
    async def get_system_stats() -> Dict[str, Any]:
        """Aggregates platform statistics, threat category breakdown, and top attacker rankings."""
        return database.get_system_stats()

    return app
