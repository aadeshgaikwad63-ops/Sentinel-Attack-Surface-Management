"""
SentinelASM - Port Scanner Service
==================================

Uses the NmapEngine to perform port scanning and returns
structured information about open ports and detected services.
"""

from __future__ import annotations

from typing import Any

from app.scanner.services.nmap_engine import NmapEngine


class PortScannerService:
    """Service for port and service enumeration."""

    def __init__(self) -> None:
        self.engine = NmapEngine()

    def scan(
        self,
        target: str,
        arguments: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Perform a port scan.

        Returns
        -------
        list
            List of open ports with service information.
        """

        raw_result = self.engine.scan(
            target=target,
            arguments=arguments,
        )

        results: list[dict[str, Any]] = []

        for host in self.engine.all_hosts():

            tcp = raw_result["scan"][host].get("tcp", {})

            for port, data in tcp.items():

                results.append(
                    {
                        "host": host,
                        "port": port,
                        "protocol": "tcp",
                        "state": data.get("state"),
                        "reason": data.get("reason"),
                        "service": data.get("name"),
                        "product": data.get("product"),
                        "version": data.get("version"),
                        "extra_info": data.get("extrainfo"),
                        "cpe": data.get("cpe"),
                    }
                )

            udp = raw_result["scan"][host].get("udp", {})

            for port, data in udp.items():

                results.append(
                    {
                        "host": host,
                        "port": port,
                        "protocol": "udp",
                        "state": data.get("state"),
                        "reason": data.get("reason"),
                        "service": data.get("name"),
                        "product": data.get("product"),
                        "version": data.get("version"),
                        "extra_info": data.get("extrainfo"),
                        "cpe": data.get("cpe"),
                    }
                )

        return sorted(results, key=lambda x: (x["host"], x["port"]))