"""
CVE information service using the NVD API.

This module retrieves general CVE information such as:
- description
- publication dates
- CVSS score and severity
- references

KEV and EPSS enrichment remains handled by enrichment.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import aiohttp

from config import Settings


CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


class CVEError(Exception):
    """Base exception for CVE service errors."""


class InvalidCVEIDError(CVEError):
    """Raised when a CVE identifier is invalid."""


class CVENotFoundError(CVEError):
    """Raised when the requested CVE does not exist in NVD."""


class CVEAPIError(CVEError):
    """Raised when the NVD API cannot be reached or returns an error."""


@dataclass(slots=True)
class CVEInfo:
    """General information about a CVE."""

    cve_id: str
    description: str
    published: str | None
    last_modified: str | None
    cvss_score: float | None
    cvss_severity: str | None
    cvss_version: str | None
    references: list[str]


class CVEService:
    """Retrieve CVE information from the NVD API."""

    def __init__(self, settings: Settings):
        self.settings = settings

    @staticmethod
    def normalize_cve_id(cve_id: str) -> str:
        """
        Validate and normalize a CVE identifier.

        Raises:
            InvalidCVEIDError: if the identifier is invalid.
        """
        normalized = cve_id.strip().upper()

        if not CVE_ID_RE.fullmatch(normalized):
            raise InvalidCVEIDError(
                f"Invalid CVE identifier: {cve_id}"
            )

        return normalized

    async def get(self, cve_id: str) -> CVEInfo:
        """
        Retrieve information about a CVE from NVD.

        Raises:
            InvalidCVEIDError: invalid CVE identifier.
            CVENotFoundError: CVE does not exist.
            CVEAPIError: NVD API request failed.
        """
        normalized_id = self.normalize_cve_id(cve_id)

        headers = {
            "User-Agent": self.settings.user_agent,
            "Accept": "application/json",
        }

        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        timeout = aiohttp.ClientTimeout(
            total=self.settings.http_timeout
        )

        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
            ) as session:
                return await self._fetch(session, normalized_id)

        except CVEError:
            raise

        except (aiohttp.ClientError, TimeoutError) as exc:
            raise CVEAPIError(
                "Unable to contact the NVD API."
            ) from exc

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        cve_id: str,
    ) -> CVEInfo:
        """Fetch and parse a CVE from NVD."""

        try:
            async with session.get(
                self.settings.nvd_url,
                params={"cveId": cve_id},
            ) as response:
                if response.status == 404:
                    raise CVENotFoundError(
                        f"CVE not found: {cve_id}"
                    )

                if response.status != 200:
                    raise CVEAPIError(
                        f"NVD API returned HTTP {response.status}."
                    )

                data = await response.json()

        except CVENotFoundError:
            raise

        except CVEAPIError:
            raise

        except (aiohttp.ClientError, TimeoutError) as exc:
            raise CVEAPIError(
                "Unable to contact the NVD API."
            ) from exc

        return self._parse_response(data, cve_id)

    @classmethod
    def _parse_response(
        cls,
        data: dict[str, Any],
        cve_id: str,
    ) -> CVEInfo:
        """Convert an NVD API response into a CVEInfo object."""

        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            raise CVENotFoundError(
                f"CVE not found: {cve_id}"
            )

        cve = vulnerabilities[0].get("cve", {})

        description = cls._extract_description(cve)
        published = cve.get("published")
        last_modified = cve.get("lastModified")

        cvss_score, cvss_severity, cvss_version = (
            cls._extract_cvss(cve)
        )

        references = cls._extract_references(cve)

        return CVEInfo(
            cve_id=cve.get("id", cve_id),
            description=description,
            published=published,
            last_modified=last_modified,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            cvss_version=cvss_version,
            references=references,
        )

    @staticmethod
    def _extract_description(cve: dict[str, Any]) -> str:
        """Extract the English CVE description."""

        descriptions = cve.get("descriptions", [])

        for description in descriptions:
            if description.get("lang") == "en":
                return description.get("value", "")

        if descriptions:
            return descriptions[0].get("value", "")

        return "No description available."

    @staticmethod
    def _extract_cvss(
        cve: dict[str, Any],
    ) -> tuple[float | None, str | None, str | None]:
        """
        Extract the preferred CVSS score.

        Preference order:
        CVSS v4.0 -> v3.1 -> v3.0 -> v2.0
        """

        metrics = cve.get("metrics", {})

        metric_versions = (
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0"),
        )

        for metric_key, version in metric_versions:
            metric_list = metrics.get(metric_key, [])

            if not metric_list:
                continue

            metric = metric_list[0]
            cvss_data = metric.get("cvssData", {})

            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")

            if severity is None:
                severity = metric.get("baseSeverity")

            return score, severity, version

        return None, None, None

    @staticmethod
    def _extract_references(
        cve: dict[str, Any],
    ) -> list[str]:
        """Extract unique reference URLs."""

        references: list[str] = []
        seen: set[str] = set()

        for reference in cve.get("references", []):
            url = reference.get("url")

            if not url or url in seen:
                continue

            seen.add(url)
            references.append(url)

        return references