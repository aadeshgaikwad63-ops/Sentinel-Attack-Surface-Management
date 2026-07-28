"""
Advanced CVE Intelligence Engine

Features:
- CVE Analysis
- CVSS scoring
- Severity Classification
- Exploit Risk
- Remediation Advice
- Asset Impact Analysis
"""


class CVEEngine:


    def __init__(self):

        self.weights = {

            "critical": 40,
            "high": 25,
            "medium": 10,
            "low": 5

        }



    def classify_severity(self, cvss):


        if cvss >= 9:

            return "Critical"


        elif cvss >= 7:

            return "High"


        elif cvss >= 4:

            return "Medium"


        else:

            return "Low"




    def exploit_risk(self, cvss, exploited=False):


        if exploited:

            return "Active Exploit"


        if cvss >= 9:

            return "High Exploit Risk"


        elif cvss >= 7:

            return "Possible Exploit"


        else:

            return "Low Exploit Risk"





    def remediation(self,severity):


        fixes = {


            "Critical":
            "Apply emergency patch immediately and isolate affected assets.",


            "High":
            "Schedule urgent patch deployment.",


            "Medium":
            "Apply security updates during maintenance window.",


            "Low":
            "Monitor vulnerability and update regularly."

        }


        return fixes.get(
            severity,
            "Review vulnerability."
        )





    def analyze_cve(self,cve):


        cvss = cve.get(
            "cvss",
            0
        )


        severity = self.classify_severity(
            cvss
        )


        return {


            "cve_id":
            cve.get(
                "cve_id",
                "UNKNOWN"
            ),



            "asset":
            cve.get(
                "asset",
                "Unknown"
            ),



            "software":
            cve.get(
                "software",
                "Unknown"
            ),



            "version":
            cve.get(
                "version",
                "Unknown"
            ),



            "cvss_score":
            cvss,



            "severity":
            severity,



            "cwe":
            cve.get(
                "cwe",
                "Unknown"
            ),



            "exploit_status":
            self.exploit_risk(
                cvss,
                cve.get(
                    "exploited",
                    False
                )
            ),



            "description":
            cve.get(
                "description",
                "No description provided"
            ),



            "recommendation":
            self.remediation(
                severity
            )

        }





    def calculate_total_risk(self,cves):


        score = 0


        for cve in cves:


            severity = self.classify_severity(
                cve.get(
                    "cvss",
                    0
                )
            )


            score += self.weights.get(
                severity.lower(),
                0
            )



        return min(
            score,
            100
        )