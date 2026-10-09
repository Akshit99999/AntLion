"""
Deceptive Linux virtual filesystem and simulated shell command handler.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple


class FakeFilesystem:
    """Emulates a realistic Linux root filesystem in memory with command emulation."""

    def __init__(self, hostname: str = "prod-api-gw-01"):
        self.hostname = hostname
        self.current_user = "root"
        self.cwd = "/root"
        self.captured_payloads: List[Dict[str, Any]] = []

        # Virtual files and contents
        self.files: Dict[str, str] = {
            "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n",
            "/etc/hostname": f"{self.hostname}\n",
            "/etc/os-release": (
                'NAME="Ubuntu"\n'
                'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
                'ID=ubuntu\n'
                'ID_LIKE=debian\n'
                'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
                'VERSION_ID="22.04"\n'
            ),
            "/etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                "sync:x:4:65534:sync:/bin:/bin/sync\n"
                "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
                "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
                "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
                "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
                "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
                "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
                "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
                "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
                "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n"
                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
                "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
                "sshd:x:106:65534::/run/sshd:/usr/sbin/nologin\n"
                "deploy:x:1000:1000:Deployer,,,:/home/deploy:/bin/bash\n"
                "ubuntu:x:1001:1001:Ubuntu User,,,:/home/ubuntu:/bin/bash\n"
            ),
            "/etc/shadow": (
                "root:$6$v1zK3y$8h8n9W2V9jK1XyL3m...:19820:0:99999:7:::\n"
                "deploy:$6$d3pl0y$Tq0vB5z...:19820:0:99999:7:::\n"
                "ubuntu:$6$ubunt0$9PzX...:19820:0:99999:7:::\n"
            ),
            "/proc/version": (
                f"Linux version 5.15.0-105-generic (buildd@lcy02-amd64-072) "
                f"(gcc version 11.4.0) #115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2026\n"
            ),
            "/proc/cpuinfo": (
                "processor\t: 0\n"
                "vendor_id\t: GenuineIntel\n"
                "cpu family\t: 6\n"
                "model\t\t: 85\n"
                "model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\n"
                "stepping\t: 7\n"
                "cpu MHz\t\t: 2499.998\n"
                "cache size\t: 36608 KB\n"
            ),
            "/root/.bash_history": (
                "docker ps\n"
                "systemctl status nginx\n"
                "cd /var/www\n"
                "git pull origin main\n"
                "journalctl -u ssh -n 50\n"
            ),
            "/var/log/syslog": "Sep 30 19:35:01 prod-api-gw-01 CRON[1890]: (root) CMD (/usr/local/bin/healthcheck.sh)\n",
            "/var/log/auth.log": "Sep 30 19:40:12 prod-api-gw-01 sshd[2014]: Accepted publickey for deploy from 10.0.1.2 port 48291 ssh2\n",
        }

        # Virtual directories
        self.dirs: set[str] = {
            "/",
            "/bin",
            "/boot",
            "/dev",
            "/etc",
            "/home",
            "/home/deploy",
            "/home/ubuntu",
            "/lib",
            "/lib64",
            "/media",
            "/mnt",
            "/opt",
            "/proc",
            "/root",
            "/run",
            "/sbin",
            "/srv",
            "/sys",
            "/tmp",
            "/usr",
            "/usr/bin",
            "/usr/local",
            "/var",
            "/var/log",
            "/var/www",
        }

    def execute_command(self, raw_command: str) -> Tuple[str, int]:
        """Simulates command execution and returns (stdout_str, exit_code)."""
        cmd_str = raw_command.strip()
        if not cmd_str:
            return "", 0

        # Extract primary binary and tokens
        parts = cmd_str.split()
        binary = parts[0]
        args = parts[1:]

        if binary == "uname":
            if "-a" in args or "--all" in args:
                return (
                    f"Linux {self.hostname} 5.15.0-105-generic #115-Ubuntu SMP "
                    f"Mon Apr 15 17:33:04 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux\n",
                    0,
                )
            if "-r" in args:
                return "5.15.0-105-generic\n", 0
            if "-m" in args:
                return "x86_64\n", 0
            return "Linux\n", 0

        if binary == "whoami":
            return f"{self.current_user}\n", 0

        if binary == "id":
            if self.current_user == "root":
                return "uid=0(root) gid=0(root) groups=0(root)\n", 0
            return (
                f"uid=1000({self.current_user}) gid=1000({self.current_user}) "
                f"groups=1000({self.current_user}),27(sudo)\n",
                0,
            )

        if binary == "pwd":
            return f"{self.cwd}\n", 0

        if binary == "cd":
            target = args[0] if args else "/root"
            new_path = self._resolve_path(target)
            if new_path in self.dirs:
                self.cwd = new_path
                return "", 0
            return f"bash: cd: {target}: No such file or directory\n", 1

        if binary == "ls":
            return self._cmd_ls(args)

        if binary == "cat":
            if not args:
                return "", 0
            target = self._resolve_path(args[0])
            if target in self.files:
                return self.files[target], 0
            if target in self.dirs:
                return f"cat: {args[0]}: Is a directory\n", 1
            return f"cat: {args[0]}: No such file or directory\n", 1

        if binary == "ps":
            return (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:02 systemd\n"
                "  482 ?        00:00:00 systemd-journal\n"
                "  520 ?        00:00:00 systemd-udevd\n"
                "  612 ?        00:00:00 cron\n"
                "  621 ?        00:00:01 rsyslogd\n"
                "  784 ?        00:00:00 sshd\n"
                " 1492 pts/0    00:00:00 bash\n"
                " 1588 pts/0    00:00:00 ps\n"
            ), 0

        if binary in ("ifconfig", "ip"):
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 10.0.1.14  netmask 255.255.255.0  broadcast 10.0.1.255\n"
                "        inet6 fe80::4a2:e0ff:fe19:82a1  prefixlen 64  scopeid 0x20<link>\n"
                "        ether 06:a2:e0:19:82:a1  txqueuelen 1000  (Ethernet)\n"
                "        RX packets 281920  bytes 194820182 (194.8 MB)\n"
                "        TX packets 192831  bytes 84920194 (84.9 MB)\n"
            ), 0

        if binary in ("curl", "wget"):
            # Deceptively simulate fetch without outbound network access
            target_url = args[-1] if args else ""
            filename = posixpath.basename(target_url.split("?")[0]) or "payload.sh"
            payload_path = f"/tmp/{filename}"
            import hashlib
            payload_hash = hashlib.sha256(f"{target_url}:{cmd_str}".encode()).hexdigest()

            # Record forensic payload evidence
            self.captured_payloads.append({
                "url": target_url,
                "destination": payload_path,
                "sha256": payload_hash,
                "command": cmd_str,
            })
            # Persist simulated script in virtual filesystem
            self.files[payload_path] = f"#!/bin/sh\n# Antlion Honeypot Captured Payload\n# Source: {target_url}\n# SHA256: {payload_hash}\n"

            return (
                f"-- Connected to host --\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Saving to: '{payload_path}'\n"
                f"100% [====================================>] 4,096  --.-KB/s in 0.01s\n"
            ), 0

        if binary in ("chmod", "touch", "rm", "mkdir"):
            # Acknowledge file operations silently like real Linux
            return "", 0

        if binary in ("history", "history -c"):
            return "    1  history -c\n", 0

        if binary == "exit":
            return "logout\n", 0

        # Default fallback: realistic bash error
        return f"bash: {binary}: command not found\n", 127

    def _resolve_path(self, target: str) -> str:
        """Resolves target relative or absolute path against virtual CWD."""
        if target.startswith("/"):
            resolved = posixpath.normpath(target)
        else:
            resolved = posixpath.normpath(posixpath.join(self.cwd, target))
        return resolved

    def _cmd_ls(self, args: List[str]) -> Tuple[str, int]:
        target = self.cwd
        show_all = any(a in ("-a", "-la", "-al") for a in args)

        # Find entries matching CWD prefix
        entries = []
        prefix = target if target.endswith("/") else f"{target}/"
        for d in self.dirs:
            if d != target and d.startswith(prefix):
                rel = d[len(prefix) :].split("/")[0]
                if rel and rel not in entries:
                    entries.append(rel)

        for f in self.files:
            if f.startswith(prefix):
                rel = f[len(prefix) :].split("/")[0]
                if rel and rel not in entries:
                    entries.append(rel)

        if not entries:
            if show_all:
                return (
                    "total 8\n"
                    "drwxr-xr-x 2 root root 4096 Sep 30 19:42 .\n"
                    "drwxr-xr-x 4 root root 4096 Sep 30 19:40 ..\n",
                    0,
                )
            return "", 0

        entries.sort()
        if show_all:
            out = ["total 24", "drwxr-xr-x 2 root root 4096 Sep 30 19:42 .", "drwxr-xr-x 4 root root 4096 Sep 30 19:40 .."]
            for e in entries:
                is_dir = self._resolve_path(posixpath.join(target, e)) in self.dirs
                mode = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                out.append(f"{mode} 1 root root 4096 Sep 30 19:42 {e}")
            return "\n".join(out) + "\n", 0

        return "  ".join(entries) + "\n", 0
