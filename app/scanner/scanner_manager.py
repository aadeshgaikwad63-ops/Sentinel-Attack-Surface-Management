"""
SentinelASM - Scanner Manager
=============================

Coordinates all scanner services and aggregates their results into
a single ScanResult object.
"""

from __future__ import annotations


from app.scanner.models.scan_result import ScanResult
from app.scanner.services.dns_lookup import DNSLookupService
from app.scanner.services.port_scanner import PortScannerService
from app.scanner.services.reverse_dns import ReverseDNSService
from app.scanner.services.ssl_analyzer import SSLAnalyzerService
from app.scanner.services.subdomain_enumerator import SubdomainEnumeratorService
from app.scanner.services.technology_detector import (
    TechnologyDetectorService,
)
from app.scanner.services.whois_lookup import WhoisLookupService
from app.scanner.utils.network import resolve_hostname
from app.scanner.utils.validators import (
    is_valid_domain,
    is_valid_ip,
    validate_target,
)


class ScannerManager:
    """
    Coordinates every scanner service.
    """

    # Canonical module keys - shared contract between the /scan API,
    # the New Scan form checkboxes, and the live progress UI.
    ALL_MODULES = (
        "dns",
        "subdomains",
        "reverse_dns",
        "whois",
        "ssl",
        "ports",
        "technologies",
    )

    def __init__(self) -> None:

        self.dns = DNSLookupService()
        self.reverse_dns = ReverseDNSService()
        self.whois = WhoisLookupService()
        self.ssl = SSLAnalyzerService()
        self.port_scanner = PortScannerService()
        self.tech = TechnologyDetectorService()
        self.subdomains = SubdomainEnumeratorService()

    def scan(self, target: str, modules: set[str] | None = None) -> ScanResult:
        """
        Execute an attack surface scan.

        Args:
            target: hostname or IP to scan.
            modules: iterable of module keys (see ALL_MODULES) to run. If
                None (the default), every module runs - this keeps the
                method backward compatible for direct/programmatic callers
                (tests, CLI, other services) that don't care about partial
                scans. The web "New Scan" form always sends an explicit
                list built from whichever checkboxes are checked, so only
                those modules execute there.
        """

        target = validate_target(target)
        active = set(modules) if modules is not None else set(self.ALL_MODULES)

        result = ScanResult(target=target)
        result.metadata["modules_requested"] = sorted(active)

        # -----------------------------------------------------
        # Resolve IP
        # -----------------------------------------------------
        if is_valid_domain(target):
            ip = resolve_hostname(target)
            result.metadata["resolved_ip"] = ip
        else:
            ip = target

        # -----------------------------------------------------
        # DNS
        # -----------------------------------------------------
        if "dns" in active and is_valid_domain(target):
            try:
                result.dns = self.dns.lookup(target)
            except Exception as exc:
                result.errors.append(f"DNS Lookup: {exc}")

        # -----------------------------------------------------
        # Subdomain Enumeration
        # -----------------------------------------------------
        if "subdomains" in active and is_valid_domain(target):
            try:
                result.subdomains = self.subdomains.enumerate(target)
            except Exception as exc:
                result.errors.append(f"Subdomain Enumeration: {exc}")

        # -----------------------------------------------------
        # Reverse DNS
        # -----------------------------------------------------
        if "reverse_dns" in active and ip:
            try:
                result.reverse_dns = self.reverse_dns.lookup(ip)
            except Exception as exc:
                result.errors.append(f"Reverse DNS: {exc}")

        # -----------------------------------------------------
        # WHOIS
        # -----------------------------------------------------
        if "whois" in active and is_valid_domain(target):
            try:
                result.whois = self.whois.lookup(target)
            except Exception as exc:
                result.errors.append(f"WHOIS: {exc}")

        # -----------------------------------------------------
        # SSL
        # -----------------------------------------------------
        if "ssl" in active and is_valid_domain(target):
            try:
                result.ssl = self.ssl.analyze(target)
            except Exception as exc:
                result.errors.append(f"SSL: {exc}")

        # -----------------------------------------------------
        # Port Scan
        # -----------------------------------------------------
        if "ports" in active:
            try:
                result.ports = self.port_scanner.scan(target)
            except Exception as exc:
                result.errors.append(f"Port Scan: {exc}")

        # -----------------------------------------------------
        # Technology Detection
        # -----------------------------------------------------
        if "technologies" in active and is_valid_domain(target):
            try:
                result.technologies = self.tech.detect(target)
            except Exception as exc:
                result.errors.append(f"Technology Detection: {exc}")

        # -----------------------------------------------------
        # Metadata
        # -----------------------------------------------------
        result.metadata["scan_completed"] = True
        result.metadata["total_open_ports"] = len(result.ports)
        result.metadata["errors"] = len(result.errors)

        return result