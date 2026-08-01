from app.scanner.services.dns_lookup import DNSLookupService

dns = DNSLookupService()

print(dns.lookup("google.com"))