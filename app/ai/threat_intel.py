"""
Threat Intelligence Reference Data
===================================

Static, curated mapping tables used by the Risk Engine and CVE Engine to
translate raw scanner/CVE data into higher-level security context:

- CWE_DATABASE        : CWE-ID -> name, OWASP Top 10 (2021) category,
                         and MITRE ATT&CK technique(s) commonly associated
                         with that weakness class.
- CRITICAL_PORTS       : Well-known ports that represent especially
                         sensitive services (databases, remote admin,
                         management interfaces) when exposed to the
                         internet.
- WEAK_TLS_PROTOCOLS   : TLS/SSL protocol versions considered insecure.
- WEAK_CIPHER_MARKERS  : Substrings that indicate a weak/legacy cipher
                          suite was negotiated.
- OUTDATED_SOFTWARE_RULES : Lightweight, regex-based heuristics for
                         flagging clearly end-of-life software banners.

None of this is a substitute for a real, continuously-updated CVE/CWE
feed - it exists so the platform can produce *some* grounded, explainable
context (OWASP/MITRE/CWE labels) without a paid threat-intel subscription.
Treat matches as heuristics, not certainties.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# CWE -> (name, OWASP Top 10:2021 category, MITRE ATT&CK techniques)
# ---------------------------------------------------------------------------
CWE_DATABASE: dict[str, dict] = {
    "CWE-89": {
        "name": "SQL Injection",
        "owasp": "A03:2021 - Injection",
        "mitre_attack": [("T1190", "Exploit Public-Facing Application")],
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "owasp": "A03:2021 - Injection",
        "mitre_attack": [("T1189", "Drive-by Compromise")],
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "owasp": "A03:2021 - Injection",
        "mitre_attack": [("T1190", "Exploit Public-Facing Application")],
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "mitre_attack": [("T1078", "Valid Accounts")],
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "mitre_attack": [("T1552.001", "Credentials In Files")],
    },
    "CWE-22": {
        "name": "Path Traversal",
        "owasp": "A01:2021 - Broken Access Control",
        "mitre_attack": [("T1083", "File and Directory Discovery")],
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "owasp": "A01:2021 - Broken Access Control",
        "mitre_attack": [("T1189", "Drive-by Compromise")],
    },
    "CWE-611": {
        "name": "XML External Entity (XXE) Reference",
        "owasp": "A05:2021 - Security Misconfiguration",
        "mitre_attack": [("T1190", "Exploit Public-Facing Application")],
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "mitre_attack": [("T1190", "Exploit Public-Facing Application")],
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "mitre_attack": [("T1190", "Exploit Public-Facing Application")],
    },
    "CWE-269": {
        "name": "Improper Privilege Management",
        "owasp": "A01:2021 - Broken Access Control",
        "mitre_attack": [("T1078", "Valid Accounts"), ("T1068", "Exploitation for Privilege Escalation")],
    },
    "CWE-732": {
        "name": "Incorrect Permission Assignment",
        "owasp": "A01:2021 - Broken Access Control",
        "mitre_attack": [("T1222", "File and Directory Permissions Modification")],
    },
    "CWE-330": {
        "name": "Use of Insufficiently Random Values",
        "owasp": "A02:2021 - Cryptographic Failures",
        "mitre_attack": [("T1552", "Unsecured Credentials")],
    },
    "CWE-327": {
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "owasp": "A02:2021 - Cryptographic Failures",
        "mitre_attack": [("T1600", "Weaken Encryption")],
    },
    "CWE-295": {
        "name": "Improper Certificate Validation",
        "owasp": "A02:2021 - Cryptographic Failures",
        "mitre_attack": [("T1557", "Adversary-in-the-Middle")],
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information",
        "owasp": "A01:2021 - Broken Access Control",
        "mitre_attack": [("T1592", "Gather Victim Host Information")],
    },
    "CWE-16": {
        "name": "Configuration",
        "owasp": "A05:2021 - Security Misconfiguration",
        "mitre_attack": [("T1592", "Gather Victim Host Information")],
    },
    "CWE-284": {
        "name": "Improper Access Control",
        "owasp": "A01:2021 - Broken Access Control",
        "mitre_attack": [("T1078", "Valid Accounts")],
    },
    "CWE-863": {
        "name": "Incorrect Authorization",
        "owasp": "A01:2021 - Broken Access Control",
        "mitre_attack": [("T1078", "Valid Accounts")],
    },
    "CWE-434": {
        "name": "Unrestricted Upload of File with Dangerous Type",
        "owasp": "A04:2021 - Insecure Design",
        "mitre_attack": [("T1105", "Ingress Tool Transfer")],
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "owasp": "A03:2021 - Injection",
        "mitre_attack": [("T1190", "Exploit Public-Facing Application")],
    },
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption",
        "owasp": "A04:2021 - Insecure Design",
        "mitre_attack": [("T1499", "Endpoint Denial of Service")],
    },
    "CWE-521": {
        "name": "Weak Password Requirements",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "mitre_attack": [("T1110", "Brute Force")],
    },
    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "mitre_attack": [("T1190", "Exploit Public-Facing Application")],
    },
}

CWE_FALLBACK = {
    "name": "Unclassified Weakness",
    "owasp": "Uncategorized",
    "mitre_attack": [("T1190", "Exploit Public-Facing Application")],
}

# ---------------------------------------------------------------------------
# Critical / sensitive ports
# ---------------------------------------------------------------------------
CRITICAL_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    2375: "Docker API (unencrypted)",
    2376: "Docker API (TLS)",
    3306: "MySQL / MariaDB",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    8009: "AJP (Tomcat)",
    9200: "Elasticsearch",
    9300: "Elasticsearch (transport)",
    11211: "Memcached",
    27017: "MongoDB",
}

DATABASE_PORTS = {1433, 1521, 3306, 5432, 5984, 6379, 9200, 9300, 11211, 27017}
REMOTE_ACCESS_PORTS = {22, 23, 3389, 5900}
MANAGEMENT_PORTS = {2375, 2376, 8009}

# ---------------------------------------------------------------------------
# TLS / SSL weakness indicators
# ---------------------------------------------------------------------------
WEAK_TLS_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON")
CERT_EXPIRY_WARNING_DAYS = 30

# ---------------------------------------------------------------------------
# Outdated technology heuristics (banner-based, best-effort only)
# ---------------------------------------------------------------------------
OUTDATED_SOFTWARE_RULES: list[dict] = [
    {"pattern": re.compile(r"Apache/(1\.|2\.[0-3]\.)"), "name": "Apache HTTP Server", "reason": "End-of-life Apache version detected in banner"},
    {"pattern": re.compile(r"nginx/(0\.|1\.[0-9]\.|1\.1[0-9]\.)"), "name": "nginx", "reason": "Outdated nginx version detected in banner"},
    {"pattern": re.compile(r"PHP/(4\.|5\.|7\.[0-3])"), "name": "PHP", "reason": "End-of-life PHP version detected in banner"},
    {"pattern": re.compile(r"OpenSSL/(0\.|1\.0)"), "name": "OpenSSL", "reason": "End-of-life OpenSSL version detected in banner"},
    {"pattern": re.compile(r"Microsoft-IIS/[1-7]\."), "name": "Microsoft IIS", "reason": "End-of-life IIS version detected in banner"},
    {"pattern": re.compile(r"wp-content"), "name": "WordPress", "reason": "WordPress detected - verify core/plugins are current"},
]


def get_cwe_info(cwe_id: str | None) -> dict:
    """Look up CWE metadata, falling back to a generic entry if unknown."""
    if not cwe_id:
        return dict(CWE_FALLBACK)
    normalized = cwe_id.strip().upper()
    if not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return dict(CWE_DATABASE.get(normalized, CWE_FALLBACK))
