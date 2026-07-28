"""
AI Security Assistant

Responsible for:
- Security Explanation
- Threat Analysis
- Recommendations
- Security Summary
"""


class AISecurityAssistant:


    def __init__(self):

        self.port_knowledge = {

            21: "FTP service detected. FTP transfers data without encryption.",

            22: "SSH service detected. Secure remote administration protocol.",

            23: "Telnet detected. Telnet is insecure because communication is unencrypted.",

            80: "HTTP web service detected. Traffic is not encrypted.",

            443: "HTTPS service detected. Secure encrypted web communication.",

            445: "SMB service detected. Could expose file sharing vulnerabilities."

        }



        self.service_knowledge = {

            "Apache":
                "Apache web server. Check version for known vulnerabilities.",


            "MySQL":
                "Database service. Ensure strong authentication and updates.",


            "SSH":
                "Remote access service. Disable weak authentication methods."

        }



    def explain_port(self, port):

        return self.port_knowledge.get(
            port,
            "Unknown port. Further investigation required."
        )



    def explain_service(self, service):

        return self.service_knowledge.get(
            service,
            "Service information not available."
        )



    def generate_threat_summary(self, risk_data):


        score = risk_data.get(
            "risk_score",
            0
        )


        severity = risk_data.get(
            "severity",
            "Unknown"
        )


        if score >= 80:

            return (
                f"System security risk is {severity}. "
                "Immediate vulnerability remediation is required."
            )


        elif score >= 50:

            return (
                f"System has {severity} risk. "
                "Security improvements are recommended."
            )


        else:

            return (
                "System risk is low. "
                "Continue regular security monitoring."
            )



    def generate_recommendations(self, risk_data):


        recommendations = []


        if risk_data.get("critical_cves",0) > 0:

            recommendations.append(
                "Patch critical vulnerabilities immediately."
            )


        if risk_data.get("weak_ssl"):

            recommendations.append(
                "Upgrade SSL/TLS configuration."
            )


        if risk_data.get("http_enabled"):

            recommendations.append(
                "Enable HTTPS instead of HTTP."
            )


        if risk_data.get("open_ports",0) > 5:

            recommendations.append(
                "Close unnecessary open ports."
            )


        if not recommendations:

            recommendations.append(
                "Maintain regular security updates."
            )


        return recommendations