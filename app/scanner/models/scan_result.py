"""
SentinelASM - Scan Result Model
===============================

Defines the standard data model returned by the Scanner module.

Every scan performed by the Attack Surface Management platform should
return a ScanResult object so that all scanner services have a
consistent output format.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ScanResult:
    """
    Represents the complete output of a target scan.
    """

    target: str

    scan_time: datetime = field(default_factory=datetime.utcnow)

    dns: dict[str, Any] = field(default_factory=dict)

    reverse_dns: dict[str, Any] = field(default_factory=dict)

    whois: dict[str, Any] = field(default_factory=dict)

    ssl: dict[str, Any] = field(default_factory=dict)

    ports: list[dict[str, Any]] = field(default_factory=list)

    technologies: dict[str, Any] = field(default_factory=dict)

    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)

    subdomains: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the ScanResult object into a JSON-serializable dictionary.
        """

        return {
            "target": self.target,
            "scan_time": self.scan_time.isoformat(),
            "dns": self.dns,
            "reverse_dns": self.reverse_dns,
            "whois": self.whois,
            "ssl": self.ssl,
            "ports": self.ports,
            "technologies": self.technologies,
            "vulnerabilities": self.vulnerabilities,
            "errors": self.errors,
            "metadata": self.metadata,
            "subdomains": self.subdomains,
        }