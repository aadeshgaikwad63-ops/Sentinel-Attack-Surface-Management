from app.scanner.services.ssl_analyzer import SSLAnalyzerService

service = SSLAnalyzerService()

print(service.analyze("google.com"))