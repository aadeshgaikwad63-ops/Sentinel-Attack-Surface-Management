from app.scanner.services.whois_lookup import WhoisLookupService

service = WhoisLookupService()

print(service.lookup("google.com"))