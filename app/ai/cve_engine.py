"""
Advanced CVE Intelligence Engine
=================================

Turns raw vulnerability records (as produced by scanners or entered
manually) into fully-classified findings:

- CVSS-based severity classification
- Exploit-likelihood heuristic
- CWE lookup (name)
- OWASP Top 10 (2021) category mapping
- MITRE ATT&CK technique mapping
- EPSS (Exploit Prediction Scoring System) enrichment via the FIRST.org
  public API, when a CVE ID is available and the lookup succeeds
- Remediation guidance text

EPSS lookups are network calls and are best-effort: if the EPSS service
is unreachable, slow, or rate-limited, analysis continues without EPSS
data rather than failing the whole scan.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from app.ai.threat_intel import get_cwe_info

logger = logging.getLogger(__name__)


class EPSSClient:
    """Thin client for the FIRST.org EPSS API (no API key required).

    Docs: https://www.first.org/epss/api
    """

    BASE_URL = "https://api.first.org/data/v1/epss"
    TIMEOUT_SECONDS = 5
    BATCH_SIZE = 100  # keep query strings reasonably sized

    def __init__(self, timeout: int | None = None) -> None:
        self.timeout = timeout or self.TIMEOUT_SECONDS

    def get_scores(self, cve_ids: list[str]) -> dict[str, dict[str, float]]:
        """
        Fetch EPSS score + percentile for a batch of CVE IDs.

        Returns a dict keyed by CVE ID: {"epss_score": float, "epss_percentile": float}.
        Missing/failed lookups are simply absent from the result - callers
        should treat a missing entry as "EPSS data unavailable", not zero.
        """
        clean_ids = sorted({c.strip().upper() for c in cve_ids if c and c.upper() != "UNKNOWN"})
        if not clean_ids:
            return {}

        results: dict[str, dict[str, float]] = {}

        for start in range(0, len(clean_ids), self.BATCH_SIZE):
            batch = clean_ids[start : start + self.BATCH_SIZE]
            try:
                response = requests.get(
                    self.BASE_URL,
                    params={"cve": ",".join(batch)},
                    timeout=self.timeout,
                )
                if response.status_code != 200:
                    logger.warning("EPSS API returned status %s", response.status_code)
                    continue

                payload = response.json()
                for item in payload.get("data", []):
                    cve_id = item.get("cve")
                    if not cve_id:
                        continue
                    try:
                        results[cve_id] = {
                            "epss_score": round(float(item.get("epss", 0.0)), 5),
                            "epss_percentile": round(float(item.get("percentile", 0.0)), 5),
                        }
                    except (TypeError, ValueError):
                        continue

            except requests.exceptions.RequestException as exc:
                logger.warning("EPSS lookup failed for batch %s: %s", batch, exc)
                continue
            except ValueError as exc:  # JSON decode error
                logger.warning("EPSS response was not valid JSON: %s", exc)
                continue

        return results


class CVEEngine:
    """Classifies and enriches individual CVE / vulnerability records."""

    def __init__(self, epss_client: EPSSClient | None = None, enable_epss: bool = True) -> None:
        self.weights = {
            "critical": 40,
            "high": 25,
            "medium": 10,
            "low": 5,
        }
        self.enable_epss = enable_epss
        self.epss_client = epss_client or EPSSClient()

    # ------------------------------------------------------------------
    # Classification helpers
    # ------------------------------------------------------------------
    def classify_severity(self, cvss: float) -> str:
        """Map a CVSS base score (0-10) to a severity band."""
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            cvss = 0.0

        if cvss >= 9:
            return "Critical"
        elif cvss >= 7:
            return "High"
        elif cvss >= 4:
            return "Medium"
        elif cvss > 0:
            return "Low"
        return "Informational"

    def exploit_risk(self, cvss: float, exploited: bool = False, epss_score: float | None = None) -> str:
        """Heuristic exploit-likelihood label.

        EPSS (when available) takes priority over CVSS-only heuristics
        since it reflects observed real-world exploitation likelihood
        rather than theoretical severity.
        """
        if exploited:
            return "Active Exploit Observed"

        if epss_score is not None:
            if epss_score >= 0.5:
                return "High Exploit Probability (EPSS)"
            elif epss_score >= 0.1:
                return "Moderate Exploit Probability (EPSS)"
            else:
                return "Low Exploit Probability (EPSS)"

        if cvss >= 9:
            return "High Exploit Risk"
        elif cvss >= 7:
            return "Possible Exploit"
        return "Low Exploit Risk"

    def remediation(self, severity: str) -> str:
        fixes = {
            "Critical": "Apply the vendor patch immediately and consider isolating the affected asset until remediated.",
            "High": "Schedule urgent patch deployment within the next few days.",
            "Medium": "Apply security updates during the next maintenance window.",
            "Low": "Track and remediate during regular patch cycles.",
            "Informational": "No immediate action required; monitor for updates.",
        }
        return fixes.get(severity, "Review the finding and consult vendor advisories.")

    # ------------------------------------------------------------------
    # Single-finding analysis
    # ------------------------------------------------------------------
    def analyze_cve(self, cve: dict[str, Any], epss_lookup: dict[str, dict] | None = None) -> dict[str, Any]:
        """Enrich a single raw CVE/vulnerability record.

        `epss_lookup` may be pre-fetched (via `analyze_batch`) to avoid a
        network round trip per finding; if omitted, EPSS data is simply
        left out for this record.
        """
        cvss = cve.get("cvss", 0) or 0
        severity = self.classify_severity(cvss)
        cve_id = cve.get("cve_id", "UNKNOWN")
        cwe_id = cve.get("cwe")
        cwe_info = get_cwe_info(cwe_id)

        epss_data = (epss_lookup or {}).get((cve_id or "").upper(), {})
        epss_score = epss_data.get("epss_score")
        epss_percentile = epss_data.get("epss_percentile")

        return {
            "cve_id": cve_id,
            "asset": cve.get("asset", "Unknown"),
            "software": cve.get("software", "Unknown"),
            "version": cve.get("version", "Unknown"),
            "cvss_score": cvss,
            "severity": severity,
            "cwe": cwe_id or "Unknown",
            "cwe_name": cwe_info["name"],
            "owasp_category": cwe_info["owasp"],
            "mitre_attack": [
                {"technique_id": tid, "technique_name": tname} for tid, tname in cwe_info["mitre_attack"]
            ],
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "exploit_status": self.exploit_risk(cvss, cve.get("exploited", False), epss_score),
            "description": cve.get("description", "No description provided"),
            "recommendation": self.remediation(severity),
        }

    def analyze_batch(self, cves: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Analyze a list of raw CVE records, fetching EPSS once for the whole batch."""
        epss_lookup: dict[str, dict] = {}
        if self.enable_epss:
            cve_ids = [c.get("cve_id") for c in cves if c.get("cve_id")]
            try:
                epss_lookup = self.epss_client.get_scores(cve_ids)
            except Exception as exc:  # never let EPSS failures break analysis
                logger.warning("EPSS batch lookup failed: %s", exc)
                epss_lookup = {}

        return [self.analyze_cve(cve, epss_lookup) for cve in cves]

    def calculate_total_risk(self, cves: list[dict[str, Any]]) -> int:
        """Aggregate CVE severity into a single 0-100 contribution score."""
        score = 0
        for cve in cves:
            severity = self.classify_severity(cve.get("cvss", 0))
            score += self.weights.get(severity.lower(), 0)
        return min(score, 100)
