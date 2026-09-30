"""
Native interactive SSH/Telnet decoy server simulating a Linux shell and logging sessions.
"""

from __future__ import annotations

import logging
import socket
import threading
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from antlion.core.types import (
    DecoyEvent,
    DecoyServiceType,
    InteractionDepth,
)
from antlion.decoys.ssh_telnet.banner import CustomBannerGenerator
from antlion.decoys.ssh_telnet.filesystem import FakeFilesystem
from antlion.verdict.engine import VerdictEngine

logger = logging.getLogger("antlion.decoy.ssh_telnet")


class InteractiveDecoyServer:
    """Multi-threaded interactive decoy honeypot simulating shell access."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2222,
        service_type: DecoyServiceType = DecoyServiceType.SSH,
        hostname: Optional[str] = None,
        verdict_engine: Optional[VerdictEngine] = None,
    ):
        self.host = host
        self.port = port
        self.service_type = service_type
        self.hostname = hostname or CustomBannerGenerator.get_hostname()
        self.verdict_engine = verdict_engine
        self._server_sock: Optional[socket.socket] = None
        self._is_running = False
        self._threads: List[threading.Thread] = []

    def start(self, blocking: bool = False) -> None:
        """Starts the decoy listener."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(128)
        self._is_running = True

        logger.info(
            "Antlion %s decoy listening on %s:%d (hostname: %s)",
            self.service_type.value,
            self.host,
            self.port,
            self.hostname,
        )

        if blocking:
            self._accept_loop()
        else:
            accept_thread = threading.Thread(
                target=self._accept_loop, daemon=True, name="DecoyAcceptLoop"
            )
            accept_thread.start()
            self._threads.append(accept_thread)

    def stop(self) -> None:
        """Stops the listener and closes active sockets."""
        self._is_running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass

    def _accept_loop(self) -> None:
        while self._is_running:
            try:
                client_sock, client_addr = self._server_sock.accept()
                client_ip, client_port = client_addr[0], client_addr[1]

                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_ip, client_port),
                    daemon=True,
                )
                client_thread.start()
                self._threads.append(client_thread)
            except Exception:
                if not self._is_running:
                    break

    def _handle_client(
        self, sock: socket.socket, client_ip: str, client_port: int
    ) -> None:
        sock.settimeout(60.0)
        session_id = str(uuid.uuid4())
        fs = FakeFilesystem(hostname=self.hostname)
        entered_commands: List[str] = []

        try:
            # 1. Connection probe event
            if self.verdict_engine:
                probe_event = DecoyEvent(
                    source_ip=client_ip,
                    source_port=client_port,
                    target_service=self.service_type,
                    depth=InteractionDepth.CONNECTION_PROBE,
                    session_id=session_id,
                )
                self.verdict_engine.process_decoy_event(probe_event)

            # Send service banner
            banner = CustomBannerGenerator.get_ssh_banner()
            sock.sendall(f"{banner}\r\n".encode("utf-8"))

            # Telnet/SSH interactive prompt emulation
            sock.sendall(f"{self.hostname} login: ".encode("utf-8"))
            username = self._read_line(sock)
            if username is None:
                return

            sock.sendall(b"Password: ")
            password = self._read_line(sock)
            if password is None:
                return

            # 2. Authentication event
            if self.verdict_engine:
                auth_event = DecoyEvent(
                    source_ip=client_ip,
                    source_port=client_port,
                    target_service=self.service_type,
                    depth=InteractionDepth.AUTHENTICATION_ATTEMPT,
                    session_id=session_id,
                    username=username,
                    password=password,
                )
                self.verdict_engine.process_decoy_event(auth_event)

            # Display Ubuntu MOTD
            motd = CustomBannerGenerator.get_motd(self.hostname)
            sock.sendall(motd.encode("utf-8"))

            # Interactive Shell Loop
            while self._is_running:
                prompt = f"root@{self.hostname}:{fs.cwd}# "
                sock.sendall(prompt.encode("utf-8"))

                cmd = self._read_line(sock)
                if cmd is None:
                    break

                cmd = cmd.strip()
                if not cmd:
                    continue

                entered_commands.append(cmd)

                # Determine interaction depth
                is_payload = any(p in cmd for p in ["curl", "wget", "tftp", "fetch"])
                depth = (
                    InteractionDepth.PAYLOAD_DELIVERY
                    if is_payload
                    else InteractionDepth.INTERACTIVE_COMMANDS
                )

                # 3. Interactive command event
                if self.verdict_engine:
                    cmd_event = DecoyEvent(
                        source_ip=client_ip,
                        source_port=client_port,
                        target_service=self.service_type,
                        depth=depth,
                        session_id=session_id,
                        username=username,
                        password=password,
                        commands=list(entered_commands),
                    )
                    self.verdict_engine.process_decoy_event(cmd_event)

                # Execute inside simulated filesystem
                out, code = fs.execute_command(cmd)
                if out:
                    # Normalize linebreaks to CRLF for terminal
                    crlf_out = out.replace("\r\n", "\n").replace("\n", "\r\n")
                    sock.sendall(crlf_out.encode("utf-8"))

                if cmd == "exit" or cmd == "logout":
                    break

        except (socket.timeout, socket.error):
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _read_line(self, sock: socket.socket) -> Optional[str]:
        """Reads characters until newline from socket."""
        buf = bytearray()
        while True:
            try:
                chunk = sock.recv(1)
                if not chunk:
                    return None
                if chunk in (b"\n", b"\r"):
                    # Consume following \n if \r\n
                    return buf.decode("utf-8", errors="replace").strip()
                buf.extend(chunk)
                if len(buf) > 1024:
                    return buf.decode("utf-8", errors="replace").strip()
            except Exception:
                return None
