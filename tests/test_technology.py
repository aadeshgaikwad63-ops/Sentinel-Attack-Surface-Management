from app.scanner.services.technology_detector import TechnologyDetectorService

tech = TechnologyDetectorService()

print(tech.detect("google.com"))