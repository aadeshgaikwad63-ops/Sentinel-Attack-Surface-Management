"""
SentinelASM - DNS Lookup Service
================================

Performs DNS enumeration for a given target.

Supported DNS Records:
- A
- AAAA
- MX
- NS
- TXT
- CNAME
- SOA
"""

from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver

from app.scanner.config import ScannerConfig
from app.scanner.exceptions import DNSLookupError
from app.scanner.utils.validators import validate_target


class DNSLookupService:
    """DNS enumeration service."""

    def __init__(self) -> None:
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = ScannerConfig.DNS_TIMEOUT
        self.resolver.timeout = ScannerConfig.DNS_TIMEOUT

    def _query(self, domain: str, record_type: str) -> list[str]:
        """
        Query a DNS record.

        Returns an empty list if the record does not exist.
        """

        try:
            answers = self.resolver.resolve(domain, record_type)
            return [answer.to_text() for answer in answers]

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):
            return []

        except dns.exception.DNSException as exc:
            raise DNSLookupError(str(exc)) from exc

    def lookup(self, target: str) -> dict[str, Any]:
        """
        Perform complete DNS enumeration.

        Parameters
        ----------
        target : str
            Domain to enumerate.

        Returns
        -------
        dict
            DNS information.
        """

        domain = validate_target(target)

        return {
            "A": self._query(domain, "A"),
            "AAAA": self._query(domain, "AAAA"),
            "MX": self._query(domain, "MX"),
            "NS": self._query(domain, "NS"),
            "TXT": self._query(domain, "TXT"),
            "CNAME": self._query(domain, "CNAME"),
            "SOA": self._query(domain, "SOA"),
        }