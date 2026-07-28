from app.scanner.services.nmap_engine import NmapEngine

engine = NmapEngine()

result = engine.scan("scanme.nmap.org")

print(result)