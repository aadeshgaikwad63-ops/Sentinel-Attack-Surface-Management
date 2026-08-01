"""
Recommendation Engine

Responsible for:
- Security Recommendations
- Remediation Guidance
- Priority Based Fixes
"""


class RecommendationEngine:

    def generate(self, scan_results):

        recommendations = []

        # Critical CVEs
        if scan_results.get("critical_cves", 0) > 0:

            recommendations.append({

                "priority": 1,

                "title": "Patch Critical Vulnerabilities",

                "description":
                    "Install vendor security patches immediately.",

                "impact":
                    "Prevents remote code execution and privilege escalation."

            })

        # High CVEs
        if scan_results.get("high_cves", 0) > 0:

            recommendations.append({

                "priority": 2,

                "title": "Resolve High Severity CVEs",

                "description":
                    "Upgrade vulnerable software to the latest supported version.",

                "impact":
                    "Reduces attack opportunities."

            })

        # Weak SSL
        if scan_results.get("weak_ssl", False):

            recommendations.append({

                "priority": 3,

                "title": "Strengthen SSL/TLS",

                "description":
                    "Disable weak protocols and use TLS 1.2 or TLS 1.3.",

                "impact":
                    "Improves encrypted communication security."

            })

        # HTTP
        if scan_results.get("http_enabled", False):

            recommendations.append({

                "priority": 4,

                "title": "Redirect HTTP to HTTPS",

                "description":
                    "Disable insecure HTTP or permanently redirect traffic to HTTPS.",

                "impact":
                    "Protects against plaintext traffic interception."

            })

        # Unknown Services
        if scan_results.get("unknown_services", 0) > 0:

            recommendations.append({

                "priority": 5,

                "title": "Investigate Unknown Services",

                "description":
                    "Identify, validate and remove unnecessary services.",

                "impact":
                    "Reduces the external attack surface."

            })

        # Open Ports
        if len(scan_results.get("open_ports", [])) > 5:

            recommendations.append({

                "priority": 6,

                "title": "Reduce Exposed Ports",

                "description":
                    "Close unused ports using firewall rules or service hardening.",

                "impact":
                    "Minimizes network exposure."

            })

        recommendations.sort(
            key=lambda item: item["priority"]
        )

        return recommendations
