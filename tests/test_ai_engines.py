"""
Tests for the AI Risk/CVE Engine overhaul.

Uses synthetic ScanResult objects (no live network/nmap dependency) so
these run reliably in CI. EPSS lookups are disabled explicitly to avoid
a network dependency in the test suite.
"""

from app.ai.cve_engine import CVEEngine
from app.ai.risk_engine import RiskEngine
from app.ai.scanner_adapter import ScannerAdapter
from app.ai.security_score_engine import SecurityScoreEngine
from app.scanner.models.scan_result import ScanResult


def _convert_without_epss(scan_result):
    """Call ScannerAdapter.convert with EPSS disabled (no network in tests)."""
    ScannerAdapter._build_cve_engine = staticmethod(
        lambda: CVEEngine(enable_epss=False)
    )
    return ScannerAdapter.convert(scan_result)


def _risky_scan_result():
    return ScanResult(
        target="risky.example.com",
        dns={
            "A": ["10.0.0.1"], "AAAA": [], "MX": ["10 mail.example.com"],
            "NS": ["ns1.example.com"], "TXT": [], "CNAME": [], "SOA": [],
        },
        ssl={
            "domain": "risky.example.com", "expired": False, "self_signed": False,
            "tls_version": "TLSv1", "cipher_suite": "ECDHE-RSA-RC4-SHA",
            "days_remaining": 5,
        },
        ports=[
            {"host": "10.0.0.1", "port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
            {"host": "10.0.0.1", "port": 3306, "protocol": "tcp", "state": "open", "service": None},
            {"host": "10.0.0.1", "port": 9999, "protocol": "tcp", "state": "closed", "service": None},
        ],
        technologies={
            "url": "http://risky.example.com", "status_code": 200,
            "server": "Apache/2.2.15", "powered_by": "PHP/5.6",
            "frameworks": ["WordPress"], "generator": None,
            "security_headers": {
                "Content-Security-Policy": False, "Strict-Transport-Security": False,
                "X-Frame-Options": False, "X-Content-Type-Options": False,
                "Referrer-Policy": False, "Permissions-Policy": False,
            },
            "response_headers": {},
        },
        vulnerabilities=[
            {"cve_id": "CVE-2021-44228", "cvss": 10.0, "cwe": "CWE-502",
             "description": "Log4Shell", "exploited": True},
        ],
    )


def _clean_scan_result():
    return ScanResult(
        target="clean.example.com",
        dns={"A": ["1.1.1.1"], "AAAA": [], "MX": [], "NS": ["ns1.x", "ns2.x"],
             "TXT": [], "CNAME": [], "SOA": []},
        ssl={"domain": "clean.example.com", "expired": False, "self_signed": False,
             "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384",
             "days_remaining": 200},
        ports=[{"host": "1.1.1.1", "port": 443, "protocol": "tcp", "state": "open", "service": "https"}],
        technologies={
            "url": "https://clean.example.com", "status_code": 200,
            "server": None, "powered_by": None, "frameworks": [], "generator": None,
            "security_headers": {h: True for h in (
                "Content-Security-Policy", "Strict-Transport-Security",
                "X-Frame-Options", "X-Content-Type-Options",
                "Referrer-Policy", "Permissions-Policy",
            )},
            "response_headers": {},
        },
        vulnerabilities=[],
    )


def test_cve_engine_classifies_severity_and_maps_context():
    engine = CVEEngine(enable_epss=False)
    result = engine.analyze_cve({
        "cve_id": "CVE-2021-44228", "cvss": 10.0, "cwe": "CWE-502",
        "description": "Log4Shell", "exploited": True,
    })
    assert result["severity"] == "Critical"
    assert result["owasp_category"] == "A08:2021 - Software and Data Integrity Failures"
    assert result["mitre_attack"][0]["technique_id"] == "T1190"
    assert result["exploit_status"] == "Active Exploit Observed"


def test_scanner_adapter_extracts_rich_signals():
    converted = _convert_without_epss(_risky_scan_result())

    assert converted["critical_cves"] == 1
    assert converted["weak_ssl"] is True
    assert any(p["port"] == 3306 for p in converted["critical_ports"])
    assert converted["service_exposure"]["database_services_exposed"] is True
    assert converted["service_exposure"]["remote_access_exposed"] is True
    assert "Content-Security-Policy" in converted["missing_security_headers"]
    assert any(t["technology"] == "Apache HTTP Server" for t in converted["outdated_technologies"])
    assert any("SPF" in issue for issue in converted["dns_issues"])


def test_risk_engine_scores_risky_target_as_critical():
    converted = _convert_without_epss(_risky_scan_result())
    risk = RiskEngine().calculate_risk(converted)

    assert risk["risk_score"] > 60
    assert risk["severity"] in ("High", "Critical")
    assert risk["critical_cves"] == 1


def test_risk_engine_scores_clean_target_as_low():
    converted = _convert_without_epss(_clean_scan_result())
    risk = RiskEngine().calculate_risk(converted)

    assert risk["risk_score"] < 20
    assert risk["severity"] in ("Informational", "Low")


def test_security_score_engine_grades():
    engine = SecurityScoreEngine()
    assert engine.calculate_security_score(0, 0, 0)["grade"] == "A+"
    assert engine.calculate_security_score(100, 100, 100)["grade"] == "F"
