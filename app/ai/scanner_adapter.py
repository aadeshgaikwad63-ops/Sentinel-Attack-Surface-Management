"""
Scanner -> AI Engine Adapter
=============================

Converts the raw `ScanResult` object produced by the Scanner module into
the richer structured input the AI Risk/CVE engines consume.

The previous version of this adapter only extracted five flat signals
(open port count, CVE severity counts, a single weak_ssl bool, an
http_enabled bool, and an unknown-service count) which threw away most of
the detail the scanners actually collect (SSL certificate fields, header
presence, DNS records, technology banners). This version extracts that
detail so the Risk Engine can score against CVSS, port criticality, SSL
weakness reasons, missing headers, outdated technology, DNS hygiene, and
service exposure - as specified by the platform's risk model.

Backward compatibility: every key the previous adapter returned
(open_ports, critical_cves, high_cves, medium_cves, weak_ssl,
http_enabled, unknown_services, target) is still present with the same
meaning, so existing consumers (attack surface / exposure engines,
templates) keep working unmodified.
"""

from __future__ import annotations

from typing import Any

from app.ai.cve_engine import CVEEngine, EPSSClient
from app.ai.threat_intel import (
    CERT_EXPIRY_WARNING_DAYS,
    CRITICAL_PORTS,
    DATABASE_PORTS,
    MANAGEMENT_PORTS,
    OUTDATED_SOFTWARE_RULES,
    REMOTE_ACCESS_PORTS,
    WEAK_CIPHER_MARKERS,
    WEAK_TLS_PROTOCOLS,
)


class ScannerAdapter:

    @staticmethod
    def _build_cve_engine() -> CVEEngine:
        """Build a CVEEngine honoring app config when running inside a
        Flask app context, falling back to sane defaults otherwise (e.g.
        in unit tests that construct scan results directly)."""
        try:
            from flask import current_app

            enable_epss = current_app.config.get("EPSS_ENABLED", True)
            timeout = current_app.config.get("EPSS_TIMEOUT_SECONDS", 5)
        except RuntimeError:  # no app context
            enable_epss = True
            timeout = 5

        return CVEEngine(epss_client=EPSSClient(timeout=timeout), enable_epss=enable_epss)

    @classmethod
    def convert(cls, scan_result) -> dict[str, Any]:
        cve_engine = cls._build_cve_engine()
        ports = scan_result.ports or []
        ssl_data = scan_result.ssl or {}
        tech_data = scan_result.technologies or {}
        dns_data = scan_result.dns or {}
        raw_vulns = scan_result.vulnerabilities or []

        open_ports = cls._extract_open_ports(ports)
        critical_ports = cls._extract_critical_ports(open_ports)
        service_exposure = cls._service_exposure(open_ports, critical_ports)
        ssl_analysis = cls._analyze_ssl(ssl_data)
        missing_headers = cls._missing_security_headers(tech_data)
        http_issues = cls._http_security_issues(tech_data)
        outdated_tech = cls._outdated_technologies(tech_data)
        dns_issues = cls._dns_misconfigurations(dns_data)

        cves = cve_engine.analyze_batch(raw_vulns)
        cve_counts = cls._count_by_severity(cves)

        unknown_services = sum(1 for p in open_ports if not p.get("service"))
        http_enabled = any(p.get("port") == 80 for p in open_ports)

        return {
            "target": scan_result.target,

            # --- backward-compatible flat signals -----------------------
            "open_ports": open_ports,
            "critical_cves": cve_counts["critical"],
            "high_cves": cve_counts["high"],
            "medium_cves": cve_counts["medium"],
            "low_cves": cve_counts["low"],
            "weak_ssl": ssl_analysis["weak_ssl"],
            "http_enabled": http_enabled,
            "unknown_services": unknown_services,

            # --- richer signals for the overhauled Risk Engine ----------
            "critical_ports": critical_ports,
            "service_exposure": service_exposure,
            "ssl_analysis": ssl_analysis,
            "missing_security_headers": missing_headers,
            "http_security_issues": http_issues,
            "outdated_technologies": outdated_tech,
            "dns_issues": dns_issues,
            "cves": cves,
            "cve_risk_contribution": cve_engine.calculate_total_risk(raw_vulns),
        }

    # ------------------------------------------------------------------
    # Ports
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_open_ports(ports: list[dict]) -> list[dict]:
        open_ports = []
        for port in ports:
            if not isinstance(port, dict):
                continue
            state = (port.get("state") or "").lower()
            if port.get("port") is None:
                continue
            # If state info is present, only count actually-open ports;
            # if absent (older scanner output), keep prior lenient behavior.
            if state and state != "open":
                continue
            open_ports.append(
                {
                    "port": port.get("port"),
                    "protocol": port.get("protocol", "tcp"),
                    "service": port.get("service"),
                    "product": port.get("product"),
                    "version": port.get("version"),
                    "state": port.get("state", "open"),
                }
            )
        return open_ports

    @staticmethod
    def _extract_critical_ports(open_ports: list[dict]) -> list[dict]:
        critical = []
        for port in open_ports:
            port_num = port.get("port")
            if port_num in CRITICAL_PORTS:
                critical.append(
                    {
                        "port": port_num,
                        "service_name": CRITICAL_PORTS[port_num],
                        "detected_service": port.get("service"),
                    }
                )
        return critical

    @staticmethod
    def _service_exposure(open_ports: list[dict], critical_ports: list[dict]) -> dict:
        port_numbers = {p.get("port") for p in open_ports}
        return {
            "total_open_ports": len(open_ports),
            "critical_port_count": len(critical_ports),
            "database_services_exposed": bool(port_numbers & DATABASE_PORTS),
            "remote_access_exposed": bool(port_numbers & REMOTE_ACCESS_PORTS),
            "management_interfaces_exposed": bool(port_numbers & MANAGEMENT_PORTS),
        }

    # ------------------------------------------------------------------
    # SSL / TLS
    # ------------------------------------------------------------------
    @staticmethod
    def _analyze_ssl(ssl_data: dict) -> dict:
        if not ssl_data:
            return {"weak_ssl": False, "issues": [], "checked": False}

        issues = []

        if ssl_data.get("expired"):
            issues.append("SSL certificate has expired")

        if ssl_data.get("self_signed"):
            issues.append("Self-signed certificate in use")

        tls_version = ssl_data.get("tls_version")
        if tls_version in WEAK_TLS_PROTOCOLS:
            issues.append(f"Weak/deprecated TLS protocol negotiated: {tls_version}")

        cipher_suite = (ssl_data.get("cipher_suite") or "").upper()
        if any(marker in cipher_suite for marker in WEAK_CIPHER_MARKERS):
            issues.append(f"Weak cipher suite negotiated: {ssl_data.get('cipher_suite')}")

        days_remaining = ssl_data.get("days_remaining")
        if isinstance(days_remaining, (int, float)) and 0 <= days_remaining <= CERT_EXPIRY_WARNING_DAYS:
            issues.append(f"Certificate expires soon ({days_remaining} days remaining)")

        return {
            "weak_ssl": bool(issues),
            "issues": issues,
            "checked": True,
            "tls_version": tls_version,
            "days_remaining": days_remaining,
        }

    # ------------------------------------------------------------------
    # HTTP headers / technology
    # ------------------------------------------------------------------
    @staticmethod
    def _missing_security_headers(tech_data: dict) -> list[str]:
        headers = tech_data.get("security_headers") or {}
        return [name for name, present in headers.items() if not present]

    @staticmethod
    def _http_security_issues(tech_data: dict) -> list[str]:
        if not tech_data:
            return []

        issues = []
        if tech_data.get("server"):
            issues.append(f"Server banner discloses software/version: {tech_data['server']}")
        if tech_data.get("powered_by"):
            issues.append(f"X-Powered-By header discloses technology: {tech_data['powered_by']}")
        if (tech_data.get("url") or "").startswith("http://"):
            issues.append("Site served over plain HTTP (no TLS)")
        return issues

    @staticmethod
    def _outdated_technologies(tech_data: dict) -> list[dict]:
        if not tech_data:
            return []

        findings = []
        banners = " ".join(
            str(tech_data.get(field, ""))
            for field in ("server", "powered_by", "generator")
        )
        html_signal = " ".join(tech_data.get("frameworks") or [])
        combined = f"{banners} {html_signal}"

        for rule in OUTDATED_SOFTWARE_RULES:
            if rule["pattern"].search(combined):
                findings.append({"technology": rule["name"], "reason": rule["reason"]})

        return findings

    # ------------------------------------------------------------------
    # DNS hygiene
    # ------------------------------------------------------------------
    @staticmethod
    def _dns_misconfigurations(dns_data: dict) -> list[str]:
        if not dns_data:
            return []

        issues = []
        txt_records = dns_data.get("TXT") or []
        has_spf = any("v=spf1" in record.lower() for record in txt_records)
        mx_records = dns_data.get("MX") or []

        if mx_records and not has_spf:
            issues.append("Mail is configured (MX records present) but no SPF record was found")

        ns_records = dns_data.get("NS") or []
        if 0 < len(ns_records) < 2:
            issues.append("Only a single authoritative name server configured (no redundancy)")

        return issues

    # ------------------------------------------------------------------
    # CVE aggregation
    # ------------------------------------------------------------------
    @staticmethod
    def _count_by_severity(cves: list[dict]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for cve in cves:
            severity = (cve.get("severity") or "").lower()
            if severity in counts:
                counts[severity] += 1
        return counts
