"""
SentinelASM - Scanner Manager
=============================

Coordinates all scanner services and aggregates their results into
a single ScanResult object.
"""

from __future__ import annotations
from unittest import result

from app.scanner.models.scan_result import ScanResult
from app.scanner.services.dns_lookup import DNSLookupService
from app.scanner.services.nmap_engine import NmapEngine
from app.scanner.services.port_scanner import PortScannerService
from app.scanner.services.reverse_dns import ReverseDNSService
from app.scanner.services.ssl_analyzer import SSLAnalyzerService
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

    def __init__(self) -> None:

        self.dns = DNSLookupService()
        self.reverse_dns = ReverseDNSService()
        self.whois = WhoisLookupService()
        self.ssl = SSLAnalyzerService()
        self.port_scanner = PortScannerService()
        self.tech = TechnologyDetectorService()
        self.nmap = NmapEngine()

    def scan(self, target: str) -> ScanResult:
        """
        Execute a complete attack surface scan.
        """

        target = validate_target(target)

        result = ScanResult(target=target)

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
        if is_valid_domain(target):
            try:
                result.dns = self.dns.lookup(target)
            except Exception as exc:
                result.errors.append(f"DNS Lookup: {exc}")

        # -----------------------------------------------------
        # Reverse DNS
        # -----------------------------------------------------
        if ip:
            try:
                result.reverse_dns = self.reverse_dns.lookup(ip)
            except Exception as exc:
                result.errors.append(f"Reverse DNS: {exc}")

        # -----------------------------------------------------
        # WHOIS
        # -----------------------------------------------------
        if is_valid_domain(target):
            try:
                result.whois = self.whois.lookup(target)
            except Exception as exc:
                result.errors.append(f"WHOIS: {exc}")

        # -----------------------------------------------------
        # SSL
        # -----------------------------------------------------
        if is_valid_domain(target):
            try:
                result.ssl = self.ssl.analyze(target)
            except Exception as exc:
                result.errors.append(f"SSL: {exc}")

        # -----------------------------------------------------
        # Port Scan
        # -----------------------------------------------------
        try:
            result.ports = self.port_scanner.scan(target)
        except Exception as exc:
            result.errors.append(f"Port Scan: {exc}")

        # -----------------------------------------------------
        # Technology Detection
        # -----------------------------------------------------
        if is_valid_domain(target):
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