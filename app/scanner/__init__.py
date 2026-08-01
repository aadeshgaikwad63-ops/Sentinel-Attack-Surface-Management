"""
SentinelASM - Scanner Blueprint
===============================

This package contains the complete Attack Surface Management (ASM)
scanner module responsible for:

- Domain validation
- DNS lookup
- Reverse DNS lookup
- WHOIS lookup
- SSL/TLS analysis
- Nmap scanning
- Port scanning
- Service detection
- Technology detection

The scanner is exposed through its own Flask Blueprint and integrated
into the application using the Application Factory pattern.
"""

from flask import Blueprint

scanner_bp = Blueprint(
    "scanner",
    __name__,
    url_prefix="/scanner",
)

# Import routes after blueprint creation to avoid circular imports.
from app.scanner import routes  # noqa: E402,F401