"""
SentinelASM - Technology Detector
=================================

Detects web technologies by analyzing HTTP response headers and HTML.

Detects:
- Web Server
- Programming Language
- Framework
- CMS
- Security Headers
"""

from __future__ import annotations

from typing import Any

import requests
from bs4 import BeautifulSoup

from app.scanner.config import ScannerConfig
from app.scanner.exceptions import TechnologyDetectionError
from app.scanner.utils.validators import validate_target


class TechnologyDetectorService:
    """Technology fingerprinting service."""

    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    FRAMEWORK_SIGNATURES = {
        "Laravel": "laravel",
        "Django": "csrfmiddlewaretoken",
        "Flask": "__flask",
        "React": "react",
        "Vue.js": "vue",
        "Angular": "ng-version",
        "Bootstrap": "bootstrap",
        "jQuery": "jquery",
        "WordPress": "wp-content",
        "Drupal": "drupal",
        "Joomla": "joomla",
    }

    def detect(self, target: str) -> dict[str, Any]:
        """
        Detect technologies used by the target website.
        """

        target = validate_target(target)

        url = f"https://{target}"

        try:
            response = requests.get(
                url,
                timeout=ScannerConfig.REQUEST_TIMEOUT,
                headers={
                    "User-Agent": ScannerConfig.USER_AGENT,
                },
                verify=True,
            )

        except requests.exceptions.SSLError:
            url = f"http://{target}"

            response = requests.get(
                url,
                timeout=ScannerConfig.REQUEST_TIMEOUT,
                headers={
                    "User-Agent": ScannerConfig.USER_AGENT,
                },
            )

        except Exception as exc:
            raise TechnologyDetectionError(str(exc)) from exc

        headers = response.headers
        html = response.text.lower()

        soup = BeautifulSoup(response.text, "html.parser")

        detected = []

        for name, signature in self.FRAMEWORK_SIGNATURES.items():

            if signature.lower() in html:
                detected.append(name)

        meta_generator = None

        generator = soup.find("meta", attrs={"name": "generator"})

        if generator:
            meta_generator = generator.get("content")

        return {
            "url": url,
            "status_code": response.status_code,
            "server": headers.get("Server"),
            "powered_by": headers.get("X-Powered-By"),
            "frameworks": sorted(set(detected)),
            "generator": meta_generator,
            "security_headers": {
                header: header in headers
                for header in self.SECURITY_HEADERS
            },
            "response_headers": dict(headers),
        }