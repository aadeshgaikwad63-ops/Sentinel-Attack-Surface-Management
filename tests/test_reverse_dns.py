from app.scanner.services.reverse_dns import ReverseDNSService

service = ReverseDNSService()

print(service.lookup("8.8.8.8"))