"""
Risk Engine Module

Responsible for:
- Risk Score
- Severity
- Attack Surface Score (Future)
- Security Score (Future)
"""


class RiskEngine:

    def __init__(self):
        self.OPEN_PORT_SCORE = 5
        self.CRITICAL_CVE_SCORE = 40
        self.HIGH_CVE_SCORE = 20
        self.MEDIUM_CVE_SCORE = 10
        self.WEAK_SSL_SCORE = 20
        self.HTTP_SCORE = 10
        self.UNKNOWN_SERVICE_SCORE = 15

    def calculate_risk(self, scan_results):

        # Starting score
        risk_score = 0

        # Open Ports
        open_ports = scan_results.get("open_ports", [])
        risk_score += len(open_ports) * self.OPEN_PORT_SCORE

        # Critical CVEs
        critical = scan_results.get("critical_cves", 0)
        risk_score += critical * self.CRITICAL_CVE_SCORE

        # High CVEs
        high = scan_results.get("high_cves", 0)
        risk_score += high * self.HIGH_CVE_SCORE

        # Medium CVEs
        medium = scan_results.get("medium_cves", 0)
        risk_score += medium * self.MEDIUM_CVE_SCORE

        # Weak SSL
        if scan_results.get("weak_ssl", False):
            risk_score += self.WEAK_SSL_SCORE

        # HTTP Enabled
        if scan_results.get("http_enabled", False):
            risk_score += self.HTTP_SCORE

        # Unknown Services
        unknown = scan_results.get("unknown_services", 0)
        risk_score += unknown * self.UNKNOWN_SERVICE_SCORE

        # Limit score to 100
        risk_score = min(risk_score, 100)

        # Decide severity
        if risk_score >= 80:
            severity = "Critical"
        elif risk_score >= 60:
            severity = "High"
        elif risk_score >= 40:
            severity = "Medium"
        else:
            severity = "Low"

        return {
            "risk_score": risk_score,
            "severity": severity,
            "open_ports": len(open_ports),
            "critical_cves": critical,
            "high_cves": high,
            "medium_cves": medium,
            "weak_ssl": scan_results.get("weak_ssl", False),
            "http_enabled": scan_results.get("http_enabled", False),
            "unknown_services": unknown
        }