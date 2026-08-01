"""
SentinelASM - Scanner Validators
================================

Validation utilities for scanner inputs.

These functions validate domains, IP addresses and scan targets before
any scanner service is executed.
"""

import ipaddress
import re
from urllib.parse import urlparse

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


def is_valid_ipv4(ip: str) -> bool:
    """
    Check whether the given string is a valid IPv4 address.
    """
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    """
    Check whether the given string is a valid IPv6 address.
    """
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False


def is_valid_ip(ip: str) -> bool:
    """
    Returns True if the string is either a valid IPv4 or IPv6 address.
    """
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_valid_domain(domain: str) -> bool:
    """
    Validate a domain name.
    """

    if not domain:
        return False

    domain = domain.strip().lower()

    return bool(DOMAIN_REGEX.fullmatch(domain))


def normalize_target(target: str) -> str:
    """
    Normalize the target by removing protocol, port and trailing slash.

    Examples:
        https://google.com/
        http://google.com:8080
        google.com

    becomes

        google.com
    """

    target = target.strip()

    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        target = parsed.hostname or target

    target = target.rstrip("/")

    return target.lower()


def validate_target(target: str) -> str:
    """
    Validate a scan target.

    Returns
    -------
    str
        Normalized target.

    Raises
    ------
    ValueError
        If target is invalid.
    """

    target = normalize_target(target)

    if is_valid_domain(target):
        return target

    if is_valid_ip(target):
        return target

    raise ValueError(
        "Invalid target. Please provide a valid domain or IP address."
    )