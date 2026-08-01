"""
SentinelASM - WHOIS Lookup Service
=================================

Performs WHOIS lookups for domains.

Extracts:
- Registrar
- Creation Date
- Expiration Date
- Updated Date
- Name Servers
- Status
- Organization
- Country
- Domain Age
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import whois

from app.scanner.exceptions import WhoisLookupError
from app.scanner.utils.validators import (
    is_valid_domain,
    validate_target,
)


class WhoisLookupService:
    """Service for performing WHOIS lookups."""

    @staticmethod
    def _first(value: Any) -> Any:
        """
        Some WHOIS fields may be returned as a list.
        Return the first value if a list is encountered.
        """
        if isinstance(value, list):
            return value[0] if value else None
        return value

    @staticmethod
    def _calculate_domain_age(created_date: datetime | None) -> int | None:
        """
        Calculate the domain age in years.
        """

        if created_date is None:
            return None

        # Handle cases where WHOIS returns a list
        if isinstance(created_date, list):
            created_date = created_date[0]

        # Make the datetime timezone-aware if it isn't already
        if created_date.tzinfo is None:
            created_date = created_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        return (now - created_date).days // 365

    def lookup(self, target: str) -> dict[str, Any]:
        """
        Perform WHOIS lookup.
        """

        target = validate_target(target)

        if not is_valid_domain(target):
            raise WhoisLookupError(
                "WHOIS lookup only supports domain names."
            )

        try:
            data = whois.whois(target)

            created = self._first(data.creation_date)
            updated = self._first(data.updated_date)
            expires = self._first(data.expiration_date)

            return {
                "domain": target,
                "registrar": data.registrar,
                "organization": data.org,
                "country": data.country,
                "creation_date": created.isoformat() if created else None,
                "updated_date": updated.isoformat() if updated else None,
                "expiration_date": expires.isoformat() if expires else None,
                "domain_age_years": self._calculate_domain_age(created),
                "name_servers": sorted(list(data.name_servers))
                if data.name_servers
                else [],
                "status": data.status if data.status else [],
                "emails": data.emails,
                "dnssec": getattr(data, "dnssec", None),
            }

        except Exception as exc:
            raise WhoisLookupError(str(exc)) from exc