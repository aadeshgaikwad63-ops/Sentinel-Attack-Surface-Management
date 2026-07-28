"""
SentinelASM - Nmap Engine
=========================

Provides a wrapper around python-nmap to perform host discovery,
port scanning and service/version detection.
"""

from __future__ import annotations

import nmap

from app.scanner.config import ScannerConfig
from app.scanner.exceptions import NmapScanError
from app.scanner.utils.validators import validate_target


class NmapEngine:
    """
    Wrapper around python-nmap.
    """

    def __init__(self) -> None:
        try:
            self.scanner = nmap.PortScanner()
        except Exception as exc:
            raise NmapScanError(
                "Nmap is not installed or not found in PATH."
            ) from exc

    def scan(
        self,
        target: str,
        arguments: str | None = None,
    ) -> dict:
        """
        Execute an Nmap scan.

        Parameters
        ----------
        target : str
            Target IP or domain.

        arguments : str, optional
            Custom Nmap arguments.

        Returns
        -------
        dict
            Raw Nmap scan result.
        """

        target = validate_target(target)

        if arguments is None:
            arguments = " ".join(
                ScannerConfig.DEFAULT_NMAP_ARGUMENTS
            )

        try:
            result = self.scanner.scan(
                hosts=target,
                arguments=arguments,
            )

            return result

        except Exception as exc:
            raise NmapScanError(str(exc)) from exc

    def all_hosts(self) -> list[str]:
        """
        Return discovered hosts.
        """
        return self.scanner.all_hosts()

    def host_info(self, host: str) -> dict:
        """
        Return host information.
        """
        return self.scanner[host]

    def scan_statistics(self) -> dict:
        """
        Return Nmap statistics.
        """
        return self.scanner.scanstats()

    def command_line(self) -> str:
        """
        Return executed Nmap command.
        """
        return self.scanner.command_line()

    def nmap_version(self):
        """
        Return installed Nmap version.
        """
        return self.scanner.nmap_version()