from app.scanner.services.subdomain_enumerator import (
    SubdomainEnumeratorService,
)

service = SubdomainEnumeratorService()

print(service.enumerate("google.com"))