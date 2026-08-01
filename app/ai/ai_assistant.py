"""
AI Security Assistant - Conversational Chat Engine
====================================================

Answers two kinds of messages:

1. General conversation and cybersecurity knowledge questions ("hi",
   "how are you", "explain SQL injection", "what is SSRF", "cybersecurity
   best practices", ...) - these are answered from a built-in knowledge
   base and work with or without any scan data on the account.

2. Questions about the user's own attack surface ("what CVEs did you
   find", "why is my risk score high", "what ports are open") - these are
   grounded in the structured output already produced by the
   AnalysisPipeline for the user's most recent scan.

This intentionally does not call an external LLM API (none is
configured/available in this project) - instead it's a rule-based
responder. Previously it *only* handled case (2) and, worse, refused to
say anything at all - including "hi" - if the account had no scan yet.
That's fixed below: general conversation and security explanations always
work; scan-specific answers layer on top when there's data to ground them
in.
"""

from __future__ import annotations

import re


class AIAssistant:
    """Rule-based chat responder for the AI Assistant screen."""

    GREETINGS = ("hi", "hello", "hey", "yo", "sup", "hiya", "greetings")

    # Small talk that isn't a greeting but should still get a natural,
    # non-scan-data reply.
    SMALL_TALK = {
        r"how are you": (
            "I'm running smoothly, thanks for asking! I'm here to help with your "
            "attack surface - ask me about a vulnerability class, a scan result, "
            "or general security best practices."
        ),
        r"who are you|what are you": (
            "I'm Sentinel AI, the assistant built into SentinelASM. I can explain "
            "security concepts (SQL injection, XSS, SSRF, DNS, WHOIS, CVEs, Nmap, "
            "and more), and once you've run a scan I can also walk you through "
            "your specific findings and recommend what to fix first."
        ),
        r"thank(s| you)": "You're welcome! Let me know if there's anything else you'd like to dig into.",
        r"(bye|goodbye|see ya)": "Take care! Come back any time you want to review your attack surface.",
    }

    # Cybersecurity knowledge base: keyword-triggered explanations that
    # work regardless of whether the account has scan data yet.
    KNOWLEDGE_BASE = [
        (
            re.compile(r"\bsql\s*injection|\bsqli\b"),
            "**SQL Injection (SQLi)** is a vulnerability where untrusted input is "
            "concatenated directly into a SQL query, letting an attacker alter the "
            "query's logic - e.g. reading other users' data, bypassing login, or "
            "modifying/deleting records. The fix is almost always the same: use "
            "parameterized queries / prepared statements (or an ORM that does this "
            "for you) instead of string-building SQL, and apply least-privilege "
            "database accounts so even a successful injection has limited blast radius.",
        ),
        (
            re.compile(r"\bxss\b|cross[- ]site scripting"),
            "**Cross-Site Scripting (XSS)** happens when untrusted input is "
            "rendered into a page without proper encoding, letting an attacker "
            "run JavaScript in another user's browser session - stealing cookies, "
            "session tokens, or performing actions as that user. Reflected, "
            "stored, and DOM-based are the three main flavors. Defenses: "
            "context-aware output encoding, a strict Content-Security-Policy, and "
            "the HttpOnly/Secure flags on session cookies.",
        ),
        (
            re.compile(r"\bssrf\b|server[- ]side request forgery"),
            "**SSRF (Server-Side Request Forgery)** is when an attacker tricks a "
            "server into making requests on their behalf - often to internal-only "
            "endpoints (cloud metadata services, internal admin panels, other "
            "hosts on the private network) that shouldn't be reachable from the "
            "outside. It typically shows up in features that fetch a URL supplied "
            "by the user (webhooks, image proxies, PDF generators). Mitigate with "
            "allow-lists for outbound destinations, blocking requests to link-local "
            "/ private IP ranges, and network segmentation.",
        ),
        (
            re.compile(r"\bdns\b"),
            "**DNS (Domain Name System)** translates domain names into IP "
            "addresses. From an attack-surface perspective, DNS records "
            "(A/AAAA, MX, TXT, NS, CNAME) reveal a lot about an organization's "
            "infrastructure - mail providers, third-party services (via SPF/TXT "
            "records), and forgotten subdomains that can become easy targets "
            "(subdomain takeover) if they point to a decommissioned service.",
        ),
        (
            re.compile(r"\bwhois\b"),
            "**WHOIS** is a public lookup protocol that returns registration "
            "details for a domain - registrar, creation/expiry dates, and "
            "(when not redacted by privacy protection) registrant contact info. "
            "It's useful for recon and for spotting domains that are about to "
            "expire, which attackers sometimes register to impersonate a brand.",
        ),
        (
            re.compile(r"\bcve\b|\bcves\b"),
            "**CVE (Common Vulnerabilities and Exposures)** is a public "
            "identifier (e.g. CVE-2024-3094) assigned to a specific, known "
            "software vulnerability, so different tools/vendors can all refer to "
            "the same issue unambiguously. Severity is usually expressed via "
            "**CVSS** (0-10 score) and, increasingly, **EPSS** (a 0-1 probability "
            "estimate of real-world exploitation) - the two together help "
            "prioritize what to patch first. Ask me \"what CVEs did my scan find\" "
            "and I'll pull the specifics for your latest scan.",
        ),
        (
            re.compile(r"\bnmap\b"),
            "**Nmap** is a network scanning tool used to discover live hosts, "
            "open ports, and the services/versions running on them. SentinelASM's "
            "port scan module uses it under the hood - a lean open-port list "
            "(only what's actually needed) is one of the simplest ways to shrink "
            "your attack surface.",
        ),
        (
            re.compile(r"\bvulnerabilit(y|ies)\b(?!.*\bmy\b)"),
            "A **vulnerability** is a weakness in a system - a code flaw, a "
            "misconfiguration, an outdated dependency, or a design gap - that "
            "could be exploited to violate confidentiality, integrity, or "
            "availability. Vulnerability *management* is the ongoing cycle of "
            "discovering (scanning), prioritizing (CVSS/EPSS + exposure), fixing "
            "(patching/config changes), and verifying.",
        ),
        (
            re.compile(r"best practice|harden|checklist for security"),
            "A solid baseline for reducing attack surface:\n"
            "1. **Patch promptly** - prioritize critical/high CVEs with known exploits.\n"
            "2. **Minimize exposure** - close ports/services you don't need publicly reachable.\n"
            "3. **Enforce TLS 1.2+** with modern ciphers; disable legacy protocols.\n"
            "4. **Least privilege** everywhere - accounts, API keys, database users.\n"
            "5. **MFA** on every account that supports it, especially admin access.\n"
            "6. **Inventory your assets** - you can't protect what you don't know exists (this is exactly what SentinelASM's scanning is for).\n"
            "7. **Log and monitor** so you notice incidents instead of discovering them later.",
        ),
        (
            re.compile(r"latest threat|current threat|trending threat"),
            "I don't have a live threat-intel feed wired in for real-time news, "
            "but structurally the threat categories worth watching year over year "
            "are: supply-chain compromises (malicious/backdoored dependencies), "
            "credential stuffing against internet-facing logins, unpatched "
            "internet-facing services (VPNs, edge devices, admin panels), and "
            "phishing as the initial access vector for ransomware. If you run a "
            "scan, I can tell you which of your specific findings map to these "
            "patterns.",
        ),
        (
            re.compile(r"what.*(security score|risk score|exposure score)\b.*\bmean|how.*calculat"),
            "**Security score** reflects overall posture (higher = better, out of "
            "100). **Risk score** weighs the severity/exploitability of what was "
            "found (higher = worse). **Exposure score** measures how much of your "
            "attack surface is externally reachable. They're related but "
            "answer different questions - a target can have a decent security "
            "score but still show high exposure if a lot is internet-facing.",
        ),
    ]

    def respond(self, message: str, latest_analysis: dict | None, target: str | None) -> str:
        text = (message or "").strip()
        lower = text.lower()

        if not text:
            return "I didn't catch a message there - go ahead and ask me something."

        # --- 1. Greetings -----------------------------------------------
        if lower.rstrip("!.? ") in self.GREETINGS or (
            any(lower.startswith(g) for g in self.GREETINGS) and len(lower) < 20
        ):
            if latest_analysis:
                risk = latest_analysis.get("risk", {})
                return (
                    f"Hi \U0001F44B I've reviewed your latest scan of {target or 'your target'}. "
                    f"Current risk score is {risk.get('risk_score', 'N/A')} "
                    f"({risk.get('severity', 'unknown')} severity). Ask me about CVEs, "
                    "open ports, SSL, or a general topic like SQL injection or XSS."
                )
            return (
                "Hi there \U0001F44B I'm Sentinel AI. You haven't run a scan yet, so I can't "
                "talk about your specific findings, but ask me about SQL injection, XSS, "
                "SSRF, DNS, CVEs, Nmap, or general security best practices any time."
            )

        # --- 2. Small talk -------------------------------------------------
        for pattern, reply in self.SMALL_TALK.items():
            if re.search(pattern, lower):
                return reply

        # --- 3. Explicit "explain X" / "what is X" / "define X" phrasing:
        #     always answer conceptually from the knowledge base, even if
        #     scan data exists (asking to "explain CVE" shouldn't return a
        #     count of the user's own CVEs).
        is_conceptual = bool(re.match(r"^(explain|what('?s| is)|define|definition of|tell me about)\b", lower))
        if is_conceptual:
            for pattern, explanation in self.KNOWLEDGE_BASE:
                if pattern.search(lower):
                    return explanation

        # --- 4. Scan-grounded questions take priority when phrasing isn't
        #     explicitly conceptual and the account has scan data - e.g.
        #     "what CVEs did my scan find" should return real numbers, not
        #     a generic CVE definition.
        if latest_analysis:
            scan_reply = self._answer_from_scan(lower, latest_analysis, target)
            if scan_reply:
                return scan_reply

        # --- 5. Cybersecurity knowledge base (works with or without scan data) ---
        for pattern, explanation in self.KNOWLEDGE_BASE:
            if pattern.search(lower):
                return explanation

        # --- 6. No scan data and nothing else matched -----------------------
        if not latest_analysis:
            return (
                "I don't have scan data for your account yet, so I can't answer that "
                "specifically - but I can explain security concepts like SQL injection, "
                "XSS, SSRF, DNS, WHOIS, CVEs, Nmap, or vulnerability management any time. "
                "Run a scan from the New Scan page and I'll be able to ground answers in "
                "your real results too."
            )

        # --- 7. Scan data exists but nothing matched - fall back to summary ---
        summary = latest_analysis.get("summary")
        if summary:
            return summary

        return (
            "I can help explain your risk score, CVEs, open ports, SSL configuration, "
            "recommend remediation priorities, or answer general security questions "
            "(SQL injection, XSS, SSRF, DNS, CVE, Nmap, best practices) - just ask."
        )

    def _answer_from_scan(self, lower: str, latest_analysis: dict, target: str | None) -> str | None:
        risk = latest_analysis.get("risk", {})
        security = latest_analysis.get("security", {})
        exposure = latest_analysis.get("exposure", {})
        attack_surface = latest_analysis.get("attack_surface", {})
        recommendations = latest_analysis.get("recommendations", [])
        threat = latest_analysis.get("threat", {})

        if "cve" in lower or "vulnerab" in lower:
            crit = risk.get("critical_cves", 0)
            high = risk.get("high_cves", 0)
            if crit or high:
                return (
                    f"Your latest scan of {target or 'your target'} found {crit} critical and "
                    f"{high} high-severity vulnerabilities. Critical issues should be patched "
                    "first - they carry the highest exploitability weight in the risk score."
                )
            return "No critical or high-severity CVEs were found in your latest scan. Nice work staying patched."

        if "port" in lower:
            open_ports = risk.get("open_ports", 0)
            return (
                f"There are {open_ports} open ports on your most recently scanned target. "
                f"{'Consider closing any that are not required for the service to function.' if open_ports else 'Nothing unusual detected.'}"
            )

        if "ssl" in lower or "tls" in lower or "certificate" in lower:
            if risk.get("weak_ssl"):
                return (
                    "Your SSL/TLS configuration was flagged as weak - likely outdated "
                    "protocol versions or cipher suites. Upgrading to TLS 1.2+ with "
                    "modern ciphers is recommended."
                )
            return "SSL/TLS configuration on your latest scan looked healthy - no weak ciphers or protocol issues detected."

        if "recommend" in lower or "priorit" in lower or "checklist" in lower or "fix" in lower:
            if not recommendations:
                return "No specific recommendations right now - your posture looks solid."
            lines = [f"[Priority {r.get('priority', '-')}] {r.get('title', 'Review finding')}" for r in recommendations[:5]]
            return "Here's what I'd prioritize:\n" + "\n".join(lines)

        if "score" in lower or "risk" in lower:
            threat_display = threat.get("classification", "N/A") if isinstance(threat, dict) else threat
            return (
                f"Risk score: {risk.get('risk_score', 'N/A')} ({risk.get('severity', 'unknown')}). "
                f"Security score: {security.get('security_score', 'N/A')}/100. "
                f"Exposure score: {exposure.get('exposure_score', 'N/A')}. "
                f"Attack surface score: {attack_surface.get('attack_surface_score', 'N/A')}. "
                f"Threat classification: {threat_display}."
            )

        return None
