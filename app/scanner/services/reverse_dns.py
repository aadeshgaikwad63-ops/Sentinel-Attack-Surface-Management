"""
SentinelASM - Reverse DNS Lookup Service
========================================

Performs Reverse DNS (PTR) lookup for a given IPv4/IPv6 address.
"""

from __future__ import annotations

from typing import Any

from app.scanner.exceptions import ReverseDNSLookupError
from app.scanner.utils.network import reverse_dns_lookup
from app.scanner.utils.validators import is_valid_ip, validate_target


class ReverseDNSService:
    """Service for performing Reverse DNS lookups."""

    def lookup(self, target: str) -> dict[str, Any]:
        """
        Perform a reverse DNS lookup.

        Parameters
        ----------
        target : str
            IPv4 or IPv6 address.

        Returns
        -------
        dict
            Reverse DNS information.
        """

        target = validate_target(target)

        if not is_valid_ip(target):
            raise ReverseDNSLookupError(
                "Reverse DNS lookup requires an IP address."
            )

        hostname = reverse_dns_lookup(target)

        return {
            "ip_address": target,
            "hostname": hostname,
            "resolved": hostname is not None,
        }