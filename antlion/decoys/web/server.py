"""
Web decoy server runner utilizing uvicorn.
"""

from __future__ import annotations

import logging
from typing import Optional

import uvicorn

from antlion.core.config import AntlionConfig
from antlion.decoys.web.app import create_web_decoy_app
from antlion.verdict.engine import VerdictEngine

logger = logging.getLogger("antlion.decoy.web")


class WebDecoyServer:
    """Runner wrapper for FastAPI web decoy."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        verdict_engine: Optional[VerdictEngine] = None,
        config: Optional[AntlionConfig] = None,
    ):
        self.host = host
        self.port = port
        self.verdict_engine = verdict_engine
        self.app = create_web_decoy_app(
            verdict_engine=self.verdict_engine, config=config
        )

    def run(self) -> None:
        """Starts the uvicorn server (blocking)."""
        logger.info("Starting Antlion Web Decoy on %s:%d", self.host, self.port)
        uvicorn.run(self.app, host=self.host, port=self.port, log_level="warning")
