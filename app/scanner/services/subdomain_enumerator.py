"""
SentinelASM - Subdomain Enumeration Service
===========================================

Performs passive subdomain enumeration using DNS resolution.
"""

from __future__ import annotations

import socket
from typing import Any

from app.scanner.exceptions import ScannerError
from app.scanner.utils.validators import validate_target


class SubdomainEnumeratorService:
    """Passive subdomain enumeration."""

    COMMON_SUBDOMAINS = [
        "www",
        "mail",
        "webmail",
        "ftp",
        "smtp",
        "imap",
        "pop",
        "ns1",
        "ns2",
        "api",
        "dev",
        "test",
        "staging",
        "beta",
        "admin",
        "portal",
        "vpn",
        "remote",
        "blog",
        "shop",
        "cdn",
        "img",
        "static",
        "files",
        "download",
        "m",
        "mobile",
        "support",
        "help",
        "docs",
        "status",
        "dashboard",
        "auth",
        "login",
    ]

    def enumerate(self, domain: str) -> list[dict[str, Any]]:
        domain = validate_target(domain)

        results = []

        for sub in self.COMMON_SUBDOMAINS:

            hostname = f"{sub}.{domain}"

            try:
                ip = socket.gethostbyname(hostname)

                results.append(
                    {
                        "subdomain": hostname,
                        "ip": ip,
                    }
                )

            except socket.gaierror:
                continue

        return sorted(results, key=lambda x: x["subdomain"])