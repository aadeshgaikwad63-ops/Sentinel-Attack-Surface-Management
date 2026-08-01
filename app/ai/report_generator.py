"""
Professional Report Generator

Responsible for:
- Executive Summary
- Risk Summary
- Export Data
"""


class ReportGenerator:

    def generate(
        self,
        risk,
        attack_surface,
        exposure,
        security,
        threat,
        recommendations
    ):

        report = {

            "Executive Summary": {

                "Risk Score":
                    risk["risk_score"],

                "Severity":
                    risk["severity"],

                "Security Score":
                    security["security_score"],

                "Attack Surface":
                    attack_surface["attack_surface_score"],

                "Exposure":
                    exposure["exposure_score"],

                "Threat Level":
                    threat["threat_level"]

            },

            "Risk Details": risk,

            "Attack Surface": attack_surface,

            "Exposure": exposure,

            "Security": security,

            "Threat": threat,

            "Recommendations": recommendations

        }

        return report