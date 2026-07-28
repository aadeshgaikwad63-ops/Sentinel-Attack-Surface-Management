"""
SentinelASM - Network Utilities
===============================

Reusable networking helper functions used across the Scanner module.

This module centralizes common socket and IP related operations so that
DNS, WHOIS, SSL, Nmap and Technology Detection services don't duplicate
code.
"""

import ipaddress
import socket
from typing import Optional

from app.scanner.config import ScannerConfig


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve a hostname to its IPv4 address.

    Example:
        google.com -> 142.250.xxx.xxx
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_dns_lookup(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup.

    Example:
        8.8.8.8 -> dns.google
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def is_private_ip(ip: str) -> bool:
    """
    Returns True if the IP belongs to a private network.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    """
    Returns True if the IP is publicly routable.
    """
    try:
        address = ipaddress.ip_address(ip)
        return (
            not address.is_private
            and not address.is_loopback
            and not address.is_reserved
            and not address.is_multicast
        )
    except ValueError:
        return False


def get_hostname() -> str:
    """
    Returns the hostname of the current machine.
    """
    return socket.gethostname()


def create_tcp_socket(timeout: int = ScannerConfig.SOCKET_TIMEOUT) -> socket.socket:
    """
    Create a TCP socket with a configured timeout.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    return sock


def create_udp_socket(timeout: int = ScannerConfig.SOCKET_TIMEOUT) -> socket.socket:
    """
    Create a UDP socket with a configured timeout.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    return sock


def get_local_ip() -> Optional[str]:
    """
    Returns the local IP address of the current machine.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def is_port_open(host: str, port: int, timeout: int = ScannerConfig.SOCKET_TIMEOUT) -> bool:
    """
    Check whether a TCP port is open.

    Returns:
        True if open, otherwise False.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, OSError):
        return False