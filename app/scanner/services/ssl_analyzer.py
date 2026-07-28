"""
SentinelASM - SSL/TLS Analyzer
==============================

Analyzes the SSL/TLS certificate of a target domain.

Extracts:
- Subject
- Issuer
- Common Name (CN)
- Subject Alternative Names (SAN)
- Valid From
- Valid Until
- Days Remaining
- Expired Status
- Self-Signed Status
- TLS Version
- Cipher Suite
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Any

from app.scanner.config import ScannerConfig
from app.scanner.exceptions import SSLAnalysisError
from app.scanner.utils.validators import (
    is_valid_domain,
    validate_target,
)


class SSLAnalyzerService:
    """SSL/TLS certificate analysis service."""

    def analyze(self, target: str, port: int = 443) -> dict[str, Any]:
        """
        Analyze the SSL certificate of a domain.
        """

        target = validate_target(target)

        if not is_valid_domain(target):
            raise SSLAnalysisError(
                "SSL analysis requires a valid domain."
            )

        try:
            context = ssl.create_default_context()

            with socket.create_connection(
                (target, port),
                timeout=ScannerConfig.SSL_TIMEOUT,
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=target,
                ) as tls:

                    cert = tls.getpeercert()

                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))

                    valid_from = datetime.strptime(
                        cert["notBefore"],
                        "%b %d %H:%M:%S %Y %Z",
                    )

                    valid_until = datetime.strptime(
                        cert["notAfter"],
                        "%b %d %H:%M:%S %Y %Z",
                    )

                    days_remaining = (
                        valid_until - datetime.utcnow()
                    ).days

                    san = [
                        value
                        for key, value in cert.get(
                            "subjectAltName", []
                        )
                        if key == "DNS"
                    ]

                    cipher = tls.cipher()

                    return {
                        "domain": target,
                        "subject": subject,
                        "issuer": issuer,
                        "common_name": subject.get("commonName"),
                        "issuer_common_name": issuer.get("commonName"),
                        "subject_alt_names": san,
                        "serial_number": cert.get("serialNumber"),
                        "version": cert.get("version"),
                        "valid_from": valid_from.isoformat(),
                        "valid_until": valid_until.isoformat(),
                        "days_remaining": days_remaining,
                        "expired": days_remaining < 0,
                        "self_signed": subject == issuer,
                        "tls_version": tls.version(),
                        "cipher_suite": cipher[0] if cipher else None,
                        "cipher_protocol": cipher[1] if cipher else None,
                        "cipher_bits": cipher[2] if cipher else None,
                    }

        except Exception as exc:
            raise SSLAnalysisError(str(exc)) from exc