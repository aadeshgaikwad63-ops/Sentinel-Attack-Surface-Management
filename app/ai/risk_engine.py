"""
Risk Engine
============

Calculates the platform's core Risk Score (0-100) from the structured
signals produced by `ScannerAdapter.convert`.

Previous version only weighted five flat signals (port count, three CVE
severity counts as raw counts rather than CVSS-driven, a weak_ssl bool,
and an http_enabled bool). This version scores against every factor the
platform's risk model calls for:

- Open ports (with extra weight for known-critical/database/remote-admin
  ports rather than treating every port equally)
- CVE severity, driven by each finding's actual CVSS score
  (via CVEEngine.calculate_total_risk) rather than raw counts
- SSL/TLS weaknesses (expired/self-signed/weak protocol/weak cipher/
  expiring soon)
- Missing security headers
- Outdated technology banners
- DNS misconfiguration
- HTTP security issues (banner disclosure, plaintext HTTP)
- Service exposure (database/remote-access/management interfaces reachable)

All backward-compatible output keys from the previous engine
(risk_score, severity, open_ports, critical_cves, high_cves, medium_cves,
weak_ssl, http_enabled, unknown_services) are preserved so the Attack
Surface Engine, Exposure Engine, Threat Classifier, and templates that
already read this dict continue to work unmodified.
"""

from __future__ import annotations

from typing import Any


class RiskEngine:

    def __init__(self):
        # Per-port weights
        self.OPEN_PORT_SCORE = 3
        self.CRITICAL_PORT_SCORE = 8
        self.DATABASE_EXPOSED_SCORE = 12
        self.REMOTE_ACCESS_EXPOSED_SCORE = 10
        self.MANAGEMENT_EXPOSED_SCORE = 10

        # CVE severity weights (used as a fallback when the richer
        # CVE-engine risk contribution is not available)
        self.CRITICAL_CVE_SCORE = 40
        self.HIGH_CVE_SCORE = 20
        self.MEDIUM_CVE_SCORE = 10
        self.LOW_CVE_SCORE = 3

        # Other factors
        self.SSL_ISSUE_SCORE = 8          # per distinct SSL/TLS issue
        self.MISSING_HEADER_SCORE = 4      # per missing security header
        self.OUTDATED_TECH_SCORE = 8       # per outdated technology finding
        self.DNS_ISSUE_SCORE = 6           # per DNS misconfiguration
        self.HTTP_ISSUE_SCORE = 5          # per HTTP security issue
        self.UNKNOWN_SERVICE_SCORE = 6

        # Weight given to the CVE engine's own 0-100 CVSS-driven
        # contribution vs. this engine's simpler count-based fallback.
        self.CVE_ENGINE_WEIGHT = 0.6

    def calculate_risk(self, scan_results: dict[str, Any]) -> dict[str, Any]:
        breakdown: dict[str, float] = {}
        risk_score = 0.0

        # --- Open ports / service exposure ------------------------------
        open_ports = scan_results.get("open_ports", [])
        port_count = len(open_ports)
        port_contribution = port_count * self.OPEN_PORT_SCORE
        risk_score += port_contribution
        breakdown["open_ports"] = port_contribution

        critical_ports = scan_results.get("critical_ports", [])
        critical_port_contribution = len(critical_ports) * self.CRITICAL_PORT_SCORE
        risk_score += critical_port_contribution
        breakdown["critical_ports"] = critical_port_contribution

        exposure = scan_results.get("service_exposure", {})
        exposure_contribution = 0
        if exposure.get("database_services_exposed"):
            exposure_contribution += self.DATABASE_EXPOSED_SCORE
        if exposure.get("remote_access_exposed"):
            exposure_contribution += self.REMOTE_ACCESS_EXPOSED_SCORE
        if exposure.get("management_interfaces_exposed"):
            exposure_contribution += self.MANAGEMENT_EXPOSED_SCORE
        risk_score += exposure_contribution
        breakdown["service_exposure"] = exposure_contribution

        # --- CVEs --------------------------------------------------------
        critical = scan_results.get("critical_cves", 0)
        high = scan_results.get("high_cves", 0)
        medium = scan_results.get("medium_cves", 0)
        low = scan_results.get("low_cves", 0)

        count_based_cve_score = (
            critical * self.CRITICAL_CVE_SCORE
            + high * self.HIGH_CVE_SCORE
            + medium * self.MEDIUM_CVE_SCORE
            + low * self.LOW_CVE_SCORE
        )
        count_based_cve_score = min(count_based_cve_score, 100)

        engine_cve_score = scan_results.get("cve_risk_contribution")
        if engine_cve_score is not None:
            # Blend the CVSS-driven engine score with the count-based
            # score so a handful of very severe CVEs still dominates.
            cve_contribution = (
                engine_cve_score * self.CVE_ENGINE_WEIGHT
                + count_based_cve_score * (1 - self.CVE_ENGINE_WEIGHT)
            )
        else:
            cve_contribution = count_based_cve_score

        risk_score += cve_contribution
        breakdown["cves"] = cve_contribution

        # --- SSL/TLS -------------------------------------------------------
        ssl_analysis = scan_results.get("ssl_analysis", {})
        ssl_issues = ssl_analysis.get("issues", [])
        weak_ssl = scan_results.get("weak_ssl", bool(ssl_issues))
        ssl_contribution = len(ssl_issues) * self.SSL_ISSUE_SCORE if ssl_issues else (
            self.SSL_ISSUE_SCORE if weak_ssl else 0
        )
        risk_score += ssl_contribution
        breakdown["ssl"] = ssl_contribution

        # --- Missing security headers --------------------------------------
        missing_headers = scan_results.get("missing_security_headers", [])
        header_contribution = len(missing_headers) * self.MISSING_HEADER_SCORE
        risk_score += header_contribution
        breakdown["missing_headers"] = header_contribution

        # --- Outdated technologies -----------------------------------------
        outdated = scan_results.get("outdated_technologies", [])
        outdated_contribution = len(outdated) * self.OUTDATED_TECH_SCORE
        risk_score += outdated_contribution
        breakdown["outdated_technologies"] = outdated_contribution

        # --- DNS misconfiguration -------------------------------------------
        dns_issues = scan_results.get("dns_issues", [])
        dns_contribution = len(dns_issues) * self.DNS_ISSUE_SCORE
        risk_score += dns_contribution
        breakdown["dns"] = dns_contribution

        # --- HTTP security issues -------------------------------------------
        http_issues = scan_results.get("http_security_issues", [])
        http_contribution = len(http_issues) * self.HTTP_ISSUE_SCORE
        risk_score += http_contribution
        breakdown["http"] = http_contribution

        # --- Unknown services -------------------------------------------------
        unknown = scan_results.get("unknown_services", 0)
        unknown_contribution = unknown * self.UNKNOWN_SERVICE_SCORE
        risk_score += unknown_contribution
        breakdown["unknown_services"] = unknown_contribution

        risk_score = min(round(risk_score), 100)
        severity = self._severity_for(risk_score)

        return {
            "risk_score": risk_score,
            "severity": severity,
            "breakdown": breakdown,

            # Backward-compatible fields relied on by other engines/templates
            "open_ports": port_count,
            "critical_cves": critical,
            "high_cves": high,
            "medium_cves": medium,
            "low_cves": low,
            "weak_ssl": weak_ssl,
            "http_enabled": scan_results.get("http_enabled", False),
            "unknown_services": unknown,

            # Richer context for the report generator / AI assistant
            "critical_ports": critical_ports,
            "ssl_issues": ssl_issues,
            "missing_security_headers": missing_headers,
            "outdated_technologies": outdated,
            "dns_issues": dns_issues,
            "http_security_issues": http_issues,
            "service_exposure": exposure,
        }

    @staticmethod
    def _severity_for(risk_score: int) -> str:
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        elif risk_score >= 20:
            return "Low"
        return "Informational"
