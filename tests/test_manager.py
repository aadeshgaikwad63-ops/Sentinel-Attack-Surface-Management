from app.scanner.scanner_manager import ScannerManager

manager = ScannerManager()

result = manager.scan("google.com")

print(result.to_dict())