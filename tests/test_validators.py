from app.scanner.utils.validators import *

print(is_valid_domain("google.com"))
print(is_valid_domain("abc"))
print(is_valid_ipv4("8.8.8.8"))
print(is_valid_ipv6("2001:4860:4860::8888"))
print(validate_target("https://google.com"))