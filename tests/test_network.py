from app.scanner.utils.network import *

print(resolve_hostname("google.com"))

print(reverse_dns_lookup("8.8.8.8"))

print(is_private_ip("192.168.1.1"))

print(is_public_ip("8.8.8.8"))