"""
Exposure Score Engine

Responsible for:
- Exposure Score
- Internet Exposure Analysis
- Exposure Rating
"""


class ExposureScoreEngine:

    def __init__(self):

        self.PORT_WEIGHT = 6
        self.HTTP_WEIGHT = 10
        self.WEAK_SSL_WEIGHT = 15
        self.UNKNOWN_SERVICE_WEIGHT = 10

    def calculate_exposure(self, scan_results):

        exposure_score = 0

        reasons = []

        # Open Ports
        open_ports = scan_results.get("open_ports", [])

        if open_ports:

            exposure_score += len(open_ports) * self.PORT_WEIGHT

            reasons.append(
                f"{len(open_ports)} Internet Facing Ports"
            )

        # HTTP Enabled
        if scan_results.get("http_enabled", False):

            exposure_score += self.HTTP_WEIGHT

            reasons.append(
                "HTTP Service Exposed"
            )

        # Weak SSL
        if scan_results.get("weak_ssl", False):

            exposure_score += self.WEAK_SSL_WEIGHT

            reasons.append(
                "Weak SSL Configuration"
            )

        # Unknown Services
        unknown = scan_results.get(
            "unknown_services",
            0
        )

        if unknown > 0:

            exposure_score += (
                unknown *
                self.UNKNOWN_SERVICE_WEIGHT
            )

            reasons.append(
                f"{unknown} Unknown Services"
            )

        exposure_score = min(
            exposure_score,
            100
        )

        if exposure_score >= 80:

            rating = "Critical"

        elif exposure_score >= 60:

            rating = "High"

        elif exposure_score >= 40:

            rating = "Medium"

        else:

            rating = "Low"

        return {

            "exposure_score": exposure_score,

            "rating": rating,

            "reasons": reasons

        }