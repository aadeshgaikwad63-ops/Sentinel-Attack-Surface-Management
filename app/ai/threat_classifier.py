"""
Threat Classification Engine

Responsible for:
- Threat Classification
- Threat Level
- Priority
- Business Impact
"""


class ThreatClassifier:

    def classify(self, risk_data):

        score = risk_data.get("risk_score", 0)

        critical = risk_data.get("critical_cves", 0)
        high = risk_data.get("high_cves", 0)
        medium = risk_data.get("medium_cves", 0)

        if score >= 90:

            level = "Emergency"
            priority = "Immediate Action Required"
            impact = "Severe Business Risk"

        elif score >= 80:

            level = "Critical"
            priority = "Fix Within 24 Hours"
            impact = "Very High"

        elif score >= 60:

            level = "High"
            priority = "Fix Within 3 Days"
            impact = "High"

        elif score >= 40:

            level = "Medium"
            priority = "Fix Within 7 Days"
            impact = "Moderate"

        elif score >= 20:

            level = "Low"
            priority = "Monitor"
            impact = "Minor"

        else:

            level = "Informational"
            priority = "No Immediate Action"
            impact = "Minimal"

        return {

            "threat_level": level,

            "priority": priority,

            "business_impact": impact,

            "critical_cves": critical,

            "high_cves": high,

            "medium_cves": medium

        }