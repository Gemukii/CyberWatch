"""
Enrichissement par threat intel publique : CISA KEV et EPSS (FIRST.org).

Deux API gratuites sans clé, mises en cache. En cas d'indisponibilité,
le scoring retombe sur les mots-clés seuls.
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
    Extrait les identifiants CVE valides d'un ou plusieurs textes.

    Valide l'année (1999 → année courante + 1) pour écarter les faux positifs
    du type « CVE-0000-0000 » présents dans les exemples et les templates.
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
    """Cache mémoire du catalogue KEV + interrogation EPSS à la demande."""

    def __init__(self, settings):
        self.s = settings
        self._kev: set[str] = set()
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
        """Recharge le catalogue KEV si le TTL est dépassé."""
        if not self.s.enable_kev:
            return
        if not force and self._kev and not self.kev_stale:
            return
        try:
            async with session.get(self.s.kev_url) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                # content_type=None : la CISA sert parfois le JSON en text/plain
                data = await resp.json(content_type=None)
            entries = data.get("vulnerabilities", [])
            # cveID -> exploitée par des campagnes de rançongiciel. Signal le plus
        # fort du catalogue.
            self._kev = {
                str(item["cveID"]).upper():
                    str(item.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"
                for item in entries
                if item.get("cveID")
            }
            self._kev_fetched_at = time.time()
            self._kev_error = None
            log.info("Catalogue KEV chargé : %d CVE exploitées connues", len(self._kev))
        except Exception as exc:
            # Non bloquant : le bot fonctionne sans, avec un scoring moins fin.
            self._kev_error = f"{type(exc).__name__}: {exc}"
            log.warning("Chargement du catalogue KEV impossible : %s", self._kev_error)

    def in_kev(self, cves: list[str]) -> list[str]:
        """Sous-ensemble des CVE présentes au catalogue KEV."""
        if not self._kev:
            return []
        return [c for c in cves if c.upper() in self._kev]

    def kev_ransomware(self, cves: list[str]) -> bool:
        """Vrai si l'une des CVE est liée à une campagne de rançongiciel."""
        return any(self._kev.get(c.upper(), False) for c in cves)

    # --- EPSS ---
    async def fetch_epss(
        self, session: aiohttp.ClientSession, cves: list[str]
    ) -> dict[str, float]:
        """
        Récupère les scores EPSS d'un lot de CVE (une seule requête).

        Retourne {CVE: probabilité}. Un échec renvoie un dict vide : l'absence
        d'EPSS ne doit jamais faire échouer un cycle.
        """
        if not self.s.enable_epss or not cves:
            return {}
        # L'API accepte une liste séparée par des virgules ; on borne par prudence.
        params = {"cve": ",".join(sorted(set(c.upper() for c in cves))[:80])}
        try:
            async with session.get(self.s.epss_url, params=params) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                data = await resp.json(content_type=None)
        except Exception as exc:
            log.debug("EPSS indisponible : %s", exc)
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
        Extrait les CVE de chaque article, les croise avec KEV, puis récupère
        les scores EPSS de l'ensemble du lot en une seule requête.
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
            log.info("Enrichissement : %d article(s) portant une CVE du KEV", kev_hits)

    def status(self) -> str:
        """Ligne d'état pour la commande /cyber-status."""
        if not self.s.enable_kev:
            return "désactivé"
        if self._kev_error and not self._kev:
            return f"⚠️ erreur ({self._kev_error[:60]})"
        age_h = (time.time() - self._kev_fetched_at) / 3600
        return f"{len(self._kev)} CVE · maj il y a {age_h:.0f} h"
