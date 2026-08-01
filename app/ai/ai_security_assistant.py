"""
AI Security Assistant

Responsible for:
- Explain Risk
- Explain CVEs
- Explain Ports
- Explain SSL
- Explain Recommendations
"""


class AISecurityAssistant:

    def generate_summary(
        self,
        risk,
        security,
        exposure,
        attack_surface,
        recommendations
    ):

        report = []

        report.append(
            f"Overall Risk Score is {risk['risk_score']} "
            f"({risk['severity']})."
        )

        report.append(
            f"Security Score is "
            f"{security['security_score']}/100."
        )

        report.append(
            f"Exposure Score is "
            f"{exposure['exposure_score']}."
        )

        report.append(
            f"Attack Surface Score is "
            f"{attack_surface['attack_surface_score']}."
        )

        if risk["critical_cves"] > 0:

            report.append(

                f"{risk['critical_cves']} Critical CVEs "
                "require immediate remediation."

            )

        if risk["high_cves"] > 0:

            report.append(

                f"{risk['high_cves']} High Severity "
                "vulnerabilities detected."

            )

        if risk["weak_ssl"]:

            report.append(

                "Weak SSL/TLS configuration detected."

            )

        if risk["http_enabled"]:

            report.append(

                "HTTP service is enabled. "
                "HTTPS is recommended."

            )

        if risk["unknown_services"] > 0:

            report.append(

                f"{risk['unknown_services']} "
                "Unknown services detected."

            )

        report.append("Recommended Actions:")

        for rec in recommendations:

            report.append(

                f"[Priority {rec['priority']}] "
                f"{rec['title']}"

            )

        return "\n".join(report)