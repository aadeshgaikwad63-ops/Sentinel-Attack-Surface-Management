"""
Scanner to AI Engine Adapter

Converts Member 2 ScanResult format
into Member 3 AI Engine input format.
"""


class ScannerAdapter:

    @staticmethod
    def convert(scan_result):

        open_ports = []

        for port in scan_result.ports:
            if isinstance(port, dict):
                if port.get("port"):
                    open_ports.append(port["port"])


        critical = 0
        high = 0
        medium = 0


        for vuln in scan_result.vulnerabilities:

            severity = vuln.get(
                "severity",
                ""
            ).lower()


            if severity == "critical":
                critical += 1

            elif severity == "high":
                high += 1

            elif severity == "medium":
                medium += 1


        weak_ssl = False

        if scan_result.ssl:

            if scan_result.ssl.get(
                "weak",
                False
            ):
                weak_ssl = True



        http_enabled = False

        for port in open_ports:

            if port == 80:
                http_enabled = True



        unknown_services = 0

        for port in scan_result.ports:

            if isinstance(port, dict):

                if not port.get("service"):

                    unknown_services += 1



        return {

            "target": scan_result.target,

            "open_ports": open_ports,

            "critical_cves": critical,

            "high_cves": high,

            "medium_cves": medium,

            "weak_ssl": weak_ssl,

            "http_enabled": http_enabled,

            "unknown_services": unknown_services

        }