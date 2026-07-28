"""
SentinelASM - AI Analysis Pipeline

Connects:
Scanner Output (Member 2)
        |
        ↓
AI Intelligence Layer (Member 3)
"""


from app.ai.risk_engine import RiskEngine
from app.ai.attack_surface_engine import AttackSurfaceEngine
from app.ai.exposure_score_engine import ExposureScoreEngine
from app.ai.security_score_engine import SecurityScoreEngine
from app.ai.threat_classifier import ThreatClassifier
from app.ai.recommendation_engine import RecommendationEngine
from app.ai.ai_security_assistant import AISecurityAssistant
from app.ai.report_generator import ReportGenerator


class AnalysisPipeline:

    def __init__(self):

        self.risk_engine = RiskEngine()

        self.attack_engine = AttackSurfaceEngine()

        self.exposure_engine = ExposureScoreEngine()

        self.security_engine = SecurityScoreEngine()

        self.threat_engine = ThreatClassifier()

        self.recommendation_engine = RecommendationEngine()

        self.ai_assistant = AISecurityAssistant()

        self.report_generator = ReportGenerator()


    def analyze(self, scan_results):
        """
        Takes scanner converted output
        and runs complete AI analysis.
        """


        # Risk Calculation
        risk = self.risk_engine.calculate_risk(
            scan_results
        )


        # Attack Surface
        attack_surface = (
            self.attack_engine
            .calculate_attack_surface(scan_results)
        )


        # Exposure Score
        exposure = (
            self.exposure_engine
            .calculate(scan_results)
        )


        # Security Score
        security = (
            self.security_engine
            .calculate_security_score(
                risk["risk_score"],
                attack_surface["attack_surface_score"],
                exposure["exposure_score"]
            )
        )


        # Threat Classification
        threat = (
            self.threat_engine
            .classify(risk)
        )


        # Recommendations
        recommendations = (
            self.recommendation_engine
            .generate(scan_results)
        )


        # AI Explanation
        summary = (
            self.ai_assistant
            .generate_summary(
                risk,
                security,
                exposure,
                attack_surface,
                recommendations
            )
        )


        # Final Report
        report = (
            self.report_generator
            .generate(
                risk,
                attack_surface,
                exposure,
                security,
                threat,
                recommendations
            )
        )


        return {

            "risk": risk,

            "attack_surface": attack_surface,

            "exposure": exposure,

            "security": security,

            "threat": threat,

            "recommendations": recommendations,

            "summary": summary,

            "report": report

        }