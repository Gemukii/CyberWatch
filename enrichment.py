"""
Enrichment via public threat intel: CISA KEV and EPSS (FIRST.org).

Two free, keyless APIs, cached in memory. If either is unavailable,
scoring falls back to keywords alone.
"""

from __future__ import annotations

import logging
import re
import time

import aiohttp

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)


def extract_cves(*texts: str, limit: int = 12) -> list[str]:
    """
    Extracts valid CVE identifiers from one or more texts.

    Validates the year (1999 -> current year + 1) to filter out false
    positives like "CVE-0000-0000" found in examples and templates.
    """
    current_year = time.gmtime().tm_year
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        for match in CVE_RE.finditer(text):
            year = int(match.group(1))
            if not 1999 <= year <= current_year + 1:
                continue
            cve = f"CVE-{match.group(1)}-{match.group(2)}"
            if cve not in seen:
                seen.add(cve)
                found.append(cve)
            if len(found) >= limit:
                return found
    return found


class Enricher:
    """In-memory KEV catalog cache + on-demand EPSS lookup."""

    def __init__(self, settings):
        self.s = settings
        self._kev: dict[str, bool] = {}
        self._kev_fetched_at: float = 0.0
        self._kev_error: str | None = None

    # --- CISA KEV ---
    @property
    def kev_size(self) -> int:
        return len(self._kev)

    @property
    def kev_stale(self) -> bool:
        ttl = self.s.enrichment_ttl_hours * 3600
        return (time.time() - self._kev_fetched_at) > ttl

    async def refresh_kev(self, session: aiohttp.ClientSession, force: bool = False) -> None:
        """Reloads the KEV catalog if the TTL has expired."""
        if not self.s.enable_kev:
            return
        if not force and self._kev and not self.kev_stale:
            return
        try:
            async with session.get(self.s.kev_url) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                # content_type=None: CISA sometimes serves the JSON as text/plain.
                data = await resp.json(content_type=None)
            entries = data.get("vulnerabilities", [])
            # cveID -> exploited by ransomware campaigns. The catalog's
            # strongest signal.
            self._kev = {
                str(item["cveID"]).upper():
                    str(item.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"
                for item in entries
                if item.get("cveID")
            }
            self._kev_fetched_at = time.time()
            self._kev_error = None
            log.info("KEV catalog loaded: %d known exploited CVEs", len(self._kev))
        except Exception as exc:
            # Non-blocking: the bot works without it, with coarser scoring.
            self._kev_error = f"{type(exc).__name__}: {exc}"
            log.warning("Could not load KEV catalog: %s", self._kev_error)

    def in_kev(self, cves: list[str]) -> list[str]:
        """Subset of CVEs present in the KEV catalog."""
        if not self._kev:
            return []
        return [c for c in cves if c.upper() in self._kev]

    def kev_ransomware(self, cves: list[str]) -> bool:
        """True if any of the CVEs is tied to a ransomware campaign."""
        return any(self._kev.get(c.upper(), False) for c in cves)

    # --- EPSS ---
    async def fetch_epss(
        self, session: aiohttp.ClientSession, cves: list[str]
    ) -> dict[str, float]:
        """
        Fetches EPSS scores for a batch of CVEs (a single request).

        Returns {CVE: probability}. A failure returns an empty dict: a
        missing EPSS score must never fail a cycle.
        """
        if not self.s.enable_epss or not cves:
            return {}
        # The API accepts a comma-separated list; capped as a precaution.
        params = {"cve": ",".join(sorted(set(c.upper() for c in cves))[:80])}
        try:
            async with session.get(self.s.epss_url, params=params) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                data = await resp.json(content_type=None)
        except Exception as exc:
            log.debug("EPSS unavailable: %s", exc)
            return {}

        scores: dict[str, float] = {}
        for item in data.get("data", []):
            try:
                scores[str(item["cve"]).upper()] = float(item["epss"])
            except (KeyError, TypeError, ValueError):
                continue
        return scores

    # --- Orchestration ---
    async def enrich(self, articles: list) -> None:
        """
        Extracts CVEs from each article, cross-references them with KEV,
        then fetches EPSS scores for the whole batch in a single request.
        """
        if not articles:
            return

        timeout = aiohttp.ClientTimeout(total=self.s.http_timeout)
        headers = {"User-Agent": self.s.user_agent}
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            await self.refresh_kev(session)

            all_cves: list[str] = []
            for article in articles:
                article.cves = extract_cves(article.title, article.content)
                article.kev_cves = self.in_kev(article.cves)
                article.kev_ransomware = self.kev_ransomware(article.kev_cves)
                all_cves.extend(article.cves)

            scores = await self.fetch_epss(session, all_cves)
            for article in articles:
                values = [scores[c] for c in article.cves if c in scores]
                article.epss_max = max(values) if values else None

        kev_hits = sum(1 for a in articles if a.kev_cves)
        if kev_hits:
            log.info("Enrichment: %d article(s) carrying a KEV-listed CVE", kev_hits)

    def status(self) -> str:
        """Status line for the /cyber-status command."""
        if not self.s.enable_kev:
            return "disabled"
        if self._kev_error and not self._kev:
            return f"⚠️ error ({self._kev_error[:60]})"
        age_h = (time.time() - self._kev_fetched_at) / 3600
        return f"{len(self._kev)} CVEs · updated {age_h:.0f}h ago"