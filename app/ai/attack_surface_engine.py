"""
Attack Surface Engine

Responsible for:
- Attack Surface Score
- Exposure Analysis
- Surface Classification
"""


class AttackSurfaceEngine:

    def __init__(self):

        self.OPEN_PORT_WEIGHT = 8
        self.UNKNOWN_SERVICE_WEIGHT = 12
        self.WEAK_SSL_WEIGHT = 15
        self.HTTP_WEIGHT = 10

    def calculate_attack_surface(self, scan_results):

        score = 0

        reasons = []

        open_ports = scan_results.get("open_ports", [])

        if open_ports:

            score += len(open_ports) * self.OPEN_PORT_WEIGHT

            reasons.append(
                f"{len(open_ports)} Open Ports"
            )

        unknown = scan_results.get(
            "unknown_services",
            0
        )

        if unknown > 0:

            score += unknown * self.UNKNOWN_SERVICE_WEIGHT

            reasons.append(
                f"{unknown} Unknown Services"
            )

        if scan_results.get(
            "weak_ssl",
            False
        ):

            score += self.WEAK_SSL_WEIGHT

            reasons.append(
                "Weak SSL Configuration"
            )

        if scan_results.get(
            "http_enabled",
            False
        ):

            score += self.HTTP_WEIGHT

            reasons.append(
                "HTTP Enabled"
            )

        score = min(score, 100)

        if score >= 80:

            rating = "Critical"

        elif score >= 60:

            rating = "High"

        elif score >= 40:

            rating = "Medium"

        else:

            rating = "Low"

        return {

            "attack_surface_score": score,

            "rating": rating,

            "reasons": reasons

        }