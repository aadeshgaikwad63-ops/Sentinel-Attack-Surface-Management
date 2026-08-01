"""
SentinelASM - Scanner Exceptions
================================

Custom exception hierarchy for the Scanner module.

Each scanner component should raise one of these exceptions instead of
using generic Exception objects.
"""


class ScannerError(Exception):
    """Base exception for all scanner-related errors."""

    default_message = "An unexpected scanner error occurred."

    def __init__(self, message=None):
        self.message = message or self.default_message
        super().__init__(self.message)


class InvalidTargetError(ScannerError):
    """Raised when a scan target is invalid."""

    default_message = "Invalid target. Please provide a valid domain or IP address."


class DNSLookupError(ScannerError):
    """Raised when DNS lookup fails."""

    default_message = "DNS lookup failed."


class ReverseDNSLookupError(ScannerError):
    """Raised when reverse DNS lookup fails."""

    default_message = "Reverse DNS lookup failed."


class WhoisLookupError(ScannerError):
    """Raised when WHOIS lookup fails."""

    default_message = "WHOIS lookup failed."


class SSLAnalysisError(ScannerError):
    """Raised when SSL/TLS analysis fails."""

    default_message = "SSL certificate analysis failed."


class NmapScanError(ScannerError):
    """Raised when Nmap execution fails."""

    default_message = "Nmap scan failed."


class PortScanError(ScannerError):
    """Raised when port scanning fails."""

    default_message = "Port scanning failed."


class TechnologyDetectionError(ScannerError):
    """Raised when technology detection fails."""

    default_message = "Technology detection failed."


class TimeoutError(ScannerError):
    """Raised when a scanner operation exceeds the timeout."""

    default_message = "The operation timed out."


class UnsupportedProtocolError(ScannerError):
    """Raised when an unsupported protocol is encountered."""

    default_message = "Unsupported protocol."