"""
Security Score Engine

Responsible for:
- Overall Security Score
- Security Rating
- Security Grade
"""


class SecurityScoreEngine:

    def __init__(self):

        self.RISK_WEIGHT = 0.5
        self.ATTACK_SURFACE_WEIGHT = 0.3
        self.EXPOSURE_WEIGHT = 0.2

    def calculate_security_score(
        self,
        risk_score,
        attack_surface_score,
        exposure_score
    ):

        weighted_risk = risk_score * self.RISK_WEIGHT

        weighted_attack = (
            attack_surface_score *
            self.ATTACK_SURFACE_WEIGHT
        )

        weighted_exposure = (
            exposure_score *
            self.EXPOSURE_WEIGHT
        )

        total = (
            weighted_risk +
            weighted_attack +
            weighted_exposure
        )

        security_score = max(
            0,
            round(100 - total)
        )

        if security_score >= 97:
            rating = "Excellent"
            grade = "A+"

        elif security_score >= 90:
            rating = "Excellent"
            grade = "A"

        elif security_score >= 75:
            rating = "Good"
            grade = "B"

        elif security_score >= 60:
            rating = "Fair"
            grade = "C"

        elif security_score >= 40:
            rating = "Poor"
            grade = "D"

        else:
            rating = "Critical"
            grade = "F"

        return {

            "security_score": security_score,

            "rating": rating,

            "grade": grade

        }