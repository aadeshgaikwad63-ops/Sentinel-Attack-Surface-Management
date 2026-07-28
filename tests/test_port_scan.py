from app.scanner.services.port_scanner import PortScannerService

scanner = PortScannerService()

ports = scanner.scan("scanme.nmap.org")

for port in ports:
    print(port)