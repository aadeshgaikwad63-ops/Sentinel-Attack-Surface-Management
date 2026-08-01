"""
Security Analytics Engine

Responsible for:
- Attack Surface Score
- Exposure Score
- Security Score
- Business Risk
- Threat Classification
"""


class AnalyticsEngine:

    def __init__(self):

        self.PORT_WEIGHT = 5
        self.CVE_WEIGHT = 15
        self.SERVICE_WEIGHT = 3
        self.EXPOSURE_WEIGHT = 20


    def calculate_attack_surface(self, scan_results):

        score = 0

        # Open ports
        open_ports = scan_results.get("open_ports", [])
        score += len(open_ports) * self.PORT_WEIGHT


        # Services
        services = scan_results.get("services", 0)
        score += services * self.SERVICE_WEIGHT


        # CVEs
        cves = scan_results.get("critical_cves", 0)
        score += cves * self.CVE_WEIGHT


        return min(score,100)



    def calculate_exposure_score(self, scan_results):

        score = 0


        # HTTP exposure
        if scan_results.get("http_enabled"):
            score += self.EXPOSURE_WEIGHT


        # Weak SSL
        if scan_results.get("weak_ssl"):
            score += self.EXPOSURE_WEIGHT


        # Public ports
        ports = len(scan_results.get("open_ports", []))

        score += ports * 5


        return min(score,100)



    def calculate_security_score(self,risk_score):

        security_score = 100 - risk_score

        if security_score < 0:
            security_score = 0

        return security_score



    def calculate_business_risk(self,risk_score):

        if risk_score >= 80:
            return "Critical Business Impact"

        elif risk_score >=60:
            return "High Business Impact"

        elif risk_score >=40:
            return "Medium Business Impact"

        else:
            return "Low Business Impact"



    def classify_threats(self,scan_results):

        threats=[]


        if scan_results.get("critical_cves",0)>0:
            threats.append(
                "Vulnerability Risk"
            )


        if scan_results.get("weak_ssl"):
            threats.append(
                "Configuration Risk"
            )


        if scan_results.get("http_enabled"):
            threats.append(
                "Exposure Risk"
            )


        if len(scan_results.get("open_ports",[]))>5:
            threats.append(
                "Network Attack Surface Risk"
            )


        return threats



    def analyze(self,scan_results,risk_score):


        return {

            "attack_surface_score":
            self.calculate_attack_surface(scan_results),


            "exposure_score":
            self.calculate_exposure_score(scan_results),


            "security_score":
            self.calculate_security_score(risk_score),


            "business_risk":
            self.calculate_business_risk(risk_score),


            "threat_classification":
            self.classify_threats(scan_results)

        }