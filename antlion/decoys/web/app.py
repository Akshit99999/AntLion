"""
From-scratch FastAPI Web Decoy mimicking an internal infrastructure administration portal.
Captures full request metadata: client IP, headers, User-Agent, path, payload, and timestamp.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from antlion.core.types import (
    DecoyEvent,
    DecoyServiceType,
    InteractionDepth,
)
from antlion.verdict.engine import VerdictEngine

logger = logging.getLogger("antlion.decoy.web")


LOGIN_HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>InfraOps Gateway | Corporate SSO Authentication</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { background: #1e293b; padding: 2.5rem; border-radius: 8px; width: 380px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }
        .badge { background: #0369a1; color: #e0f2fe; padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }
        h2 { margin: 1rem 0 0.5rem 0; font-size: 1.4rem; }
        p { color: #94a3b8; font-size: 0.85rem; margin-bottom: 1.5rem; }
        label { display: block; font-size: 0.8rem; color: #cbd5e1; margin-bottom: 0.3rem; }
        input { width: 100%; box-sizing: border-box; padding: 0.6rem; border-radius: 4px; border: 1px solid #475569; background: #0f172a; color: white; margin-bottom: 1rem; }
        input:focus { border-color: #38bdf8; outline: none; }
        button { width: 100%; padding: 0.7rem; background: #0284c7; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
        button:hover { background: #0369a1; }
        .footer { margin-top: 1.5rem; font-size: 0.75rem; color: #64748b; text-align: center; }
    </style>
</head>
<body>
    <div class="card">
        <span class="badge">Internal Network Only</span>
        <h2>InfraOps Cluster Console</h2>
        <p>Enterprise Infrastructure Gateway &bull; v4.2.1-prod</p>
        <form method="POST" action="/login">
            <label for="username">Corporate Identity / LDAP</label>
            <input type="text" id="username" name="username" placeholder="user@corp.internal" required>
            <label for="password">Password &amp; Hardware Token</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Sign In with Corporate SSO</button>
        </form>
        <div class="footer">
            Protected by CorpSec Zero-Trust Proxy. Unauthorized access is actively logged.
        </div>
    </div>
</body>
</html>
"""


def create_web_decoy_app(verdict_engine: Optional[VerdictEngine] = None) -> FastAPI:
    """Builds FastAPI web honeypot application with full request telemetry capture."""
    app = FastAPI(
        title="InfraOps Internal Admin Console",
        description="Internal cluster node management gateway",
        version="4.2.1",
        docs_url=None,  # Suppress default OpenAPI docs on decoy port to look like proprietary admin tool
        redoc_url=None,
    )

    @app.middleware("http")
    async def capture_request_metadata(request: Request, call_next):
        """Intercepts every incoming HTTP request, logs metadata, and evaluates verdict."""
        # 1. Extract client IP (respecting proxy headers)
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "127.0.0.1"

        client_port = request.client.port if request.client else 0
        path = request.url.path
        method = request.method
        headers = dict(request.headers)

        # 2. Read request payload
        body_bytes = await request.body()
        payload_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else None

        # Re-attach body for downstream endpoint handlers
        async def receive():
            return {"type": "http.request", "body": body_bytes}

        request._receive = receive

        # 3. Determine interaction depth
        query_str = str(request.url.query)
        full_path = f"{path}?{query_str}" if query_str else path
        is_exploit = any(
            x in full_path.lower() or (payload_str and x in payload_str.lower())
            for x in ["union", "select", "../", "..\\", "sleep(", "whoami", "id", "/.env", "eval"]
        )

        depth = (
            InteractionDepth.WEB_EXPLOIT_PAYLOAD
            if is_exploit
            else InteractionDepth.WEB_ENDPOINT_PROBE
        )

        # 4. Dispatch telemetry to VerdictEngine
        if verdict_engine:
            event = DecoyEvent(
                source_ip=client_ip,
                source_port=client_port,
                target_service=DecoyServiceType.WEB_ADMIN,
                depth=depth,
                event_timestamp=datetime.now(timezone.utc),
                http_method=method,
                http_path=full_path,
                http_headers=headers,
                http_payload=payload_str,
                raw_metadata={
                    "query_string": query_str,
                    "url": str(request.url),
                },
            )
            verdict_engine.process_decoy_event(event)

        # 5. Proceed to endpoint execution
        response = await call_next(request)
        # Custom realistic server header
        response.headers["Server"] = "InfraOps-Gateway/4.2.1 (Unix)"
        return response

    # ------------------ Decoy Endpoints ------------------

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return HTMLResponse(content=LOGIN_HTML_PAGE, status_code=200)

    @app.get("/login", response_class=HTMLResponse)
    async def get_login():
        return HTMLResponse(content=LOGIN_HTML_PAGE, status_code=200)

    @app.post("/login")
    async def post_login(request: Request):
        form_data = await request.form()
        username = form_data.get("username", "")
        password = form_data.get("password", "")

        client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "127.0.0.1")
        )
        client_port = request.client.port if request.client else 0

        # Create specific authentication attempt event
        if verdict_engine:
            auth_event = DecoyEvent(
                source_ip=client_ip,
                source_port=client_port,
                target_service=DecoyServiceType.WEB_ADMIN,
                depth=InteractionDepth.AUTHENTICATION_ATTEMPT,
                username=username,
                password=password,
                http_method="POST",
                http_path="/login",
                http_headers=dict(request.headers),
            )
            verdict_engine.process_decoy_event(auth_event)

        # Plausible realistic auth failure
        return JSONResponse(
            status_code=401,
            content={
                "error": "Authentication failed",
                "code": "INVALID_CORPORATE_SSO_CREDENTIALS",
                "message": "Supplied LDAP identity or hardware token is invalid.",
                "attempt_id": "auth-ref-88129a",
            },
        )

    @app.get("/api/v1/cluster/status")
    async def cluster_status():
        return {
            "cluster_name": "prod-infra-us-east-1",
            "status": "HEALTHY",
            "nodes_total": 12,
            "nodes_ready": 12,
            "region": "us-east-1",
            "vpc_id": "vpc-0bf19c289ad9821aa",
            "control_plane": "active",
        }

    @app.get("/api/v1/nodes")
    async def list_nodes():
        return {
            "nodes": [
                {"id": "node-01", "role": "controller", "ip": "10.0.1.10", "status": "Ready"},
                {"id": "node-02", "role": "worker", "ip": "10.0.1.11", "status": "Ready"},
                {"id": "node-03", "role": "worker", "ip": "10.0.1.12", "status": "Ready"},
                {"id": "db-primary", "role": "database", "ip": "10.0.2.20", "status": "Ready"},
            ]
        }

    @app.get("/config/backup")
    async def config_backup(file: Optional[str] = None):
        """Vulnerable-looking endpoint tempting attackers to perform LFI / Path Traversal."""
        if file and ("../" in file or "..\\" in file or "passwd" in file or "shadow" in file):
            # Deceptive honey response
            return Response(
                content="root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n",
                media_type="text/plain",
                status_code=200,
            )
        return {
            "status": "error",
            "message": "Backup configuration bundle must specify valid archive parameter.",
        }

    @app.post("/api/v1/debug/eval")
    async def debug_eval(request: Request):
        """Vulnerable-looking debug API endpoint tempting RCE / command injection."""
        body = await request.body()
        return JSONResponse(
            status_code=403,
            content={
                "error": "Execution Forbidden",
                "message": "Remote debug evaluation requires elevated ClusterAdmin scope.",
                "received_length": len(body),
            },
        )

    @app.get("/.env")
    async def trap_env_file():
        """Honey environment file trap leaking fake canary tokens."""
        return Response(
            content=(
                "# Enterprise Infrastructure Environment Variables\n"
                "ENVIRONMENT=production\n"
                "DATABASE_URL=postgres://infra_admin:canary_db_token_9918@10.0.2.20:5432/infra_prod\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7CANARY1\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYCANARY01\n"
                "JWT_SECRET=canary_sec_key_alpha_9981290\n"
            ),
            media_type="text/plain",
            status_code=200,
        )

    @app.get("/.git/config")
    async def trap_git_config():
        """Honey git config exposure trap."""
        return Response(
            content=(
                "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
                "[remote \"origin\"]\n\turl = git@github.corp.internal:infra/cluster-ops.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            ),
            media_type="text/plain",
            status_code=200,
        )

    @app.get("/.git/HEAD")
    async def trap_git_head():
        return Response(content="ref: refs/heads/main\n", media_type="text/plain", status_code=200)

    @app.get("/latest/meta-data/")
    async def trap_aws_metadata_root():
        """AWS IMDSv1 SSRF honeypot trap."""
        return Response(content="ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\n", media_type="text/plain")

    @app.get("/latest/meta-data/iam/security-credentials/")
    async def trap_aws_iam_list():
        return Response(content="InfraOpsClusterAdminRole\n", media_type="text/plain")

    @app.get("/latest/meta-data/iam/security-credentials/{role}")
    async def trap_aws_iam_role(role: str):
        """Emits traceable canary AWS credentials."""
        return {
            "Code": "Success",
            "LastUpdated": "2026-09-30T19:40:00Z",
            "Type": "AWS-HMAC",
            "AccessKeyId": "ASIA99CANARYHONEYTOKEN1",
            "SecretAccessKey": "canary99secret_key_access_antlion_trap_token_x99",
            "Token": "canary_session_token_trap_active_monitoring_991823",
            "Expiration": "2026-10-01T04:00:00Z",
        }

    @app.get("/graphql")
    @app.post("/graphql")
    async def trap_graphql():
        """GraphQL introspection trap."""
        return {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "Query", "kind": "OBJECT"},
                        {"name": "User", "kind": "OBJECT"},
                        {"name": "AdminSecret", "kind": "OBJECT"},
                    ]
                }
            }
        }

    @app.get("/healthz")
    async def health():
        return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

    return app
