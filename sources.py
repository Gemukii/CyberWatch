"""
Collecte : lecture des flux RSS/Atom et extraction du corps des articles.

feedparser est synchrone (exécuté en thread), le téléchargement des pages
est asynchrone via aiohttp.
"""

from __future__ import annotations

import asyncio
import html
import logging
import time
from calendar import timegm
from dataclasses import dataclass, field

import aiohttp
import feedparser
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

# trafilatura est optionnel : le bot fonctionne sans, en mode dégradé.
try:
    import trafilatura

    HAS_TRAFILATURA = True
except ImportError:  # pragma: no cover
    HAS_TRAFILATURA = False


@dataclass
class Article:
    """Un article candidat, enrichi au fil du pipeline."""

    title: str
    url: str
    source: str
    source_weight: int = 0
    summary: str = ""            # description fournie par le flux RSS
    published_ts: float = 0.0    # epoch UTC
    fulltext: str = ""           # corps de l'article, si récupéré

    # Enrichissement (voir enrichment.py)
    cves: list[str] = field(default_factory=list)
    kev_cves: list[str] = field(default_factory=list)   # présentes au catalogue CISA KEV
    kev_ransomware: bool = False                        # liée à une campagne de rançongiciel
    epss_max: float | None = None                       # probabilité d'exploitation 0-1

    # Filtrage (voir filters.py)
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    @property
    def content(self) -> str:
        """Le meilleur texte disponible pour l'analyse et le résumé."""
        return self.fulltext or self.summary


@dataclass
class FeedResult:
    """Résultat de la lecture d'un flux, pour le suivi de santé."""

    name: str
    articles: list[Article] = field(default_factory=list)
    error: str | None = None


def _strip_html(raw: str) -> str:
    """Transforme un fragment HTML en texte brut lisible."""
    if not raw:
        return ""
    text = BeautifulSoup(raw, "html.parser").get_text(" ", strip=True)
    return html.unescape(" ".join(text.split()))


def _entry_timestamp(entry) -> float:
    """Date de publication de l'entrée en epoch UTC. 0 si introuvable."""
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        parsed = entry.get(key)
        if parsed:
            try:
                return float(timegm(parsed))  # les *_parsed sont en UTC
            except (TypeError, ValueError):
                continue
    return 0.0


def _parse_feed(url: str, name: str, weight: int) -> FeedResult:
    """Parse un flux (appelé dans un thread : feedparser est bloquant)."""
    try:
        parsed = feedparser.parse(url)
    except Exception as exc:
        return FeedResult(name=name, error=f"{type(exc).__name__}: {exc}")

    if parsed.bozo and not parsed.entries:
        return FeedResult(name=name, error=str(parsed.get("bozo_exception", "flux illisible")))

    articles = []
    for entry in parsed.entries:
        link = (entry.get("link") or "").strip()
        title = _strip_html(entry.get("title") or "")
        if not link or not title:
            continue
        raw_summary = entry.get("summary") or ""
        if not raw_summary and entry.get("content"):
            raw_summary = entry["content"][0].get("value", "")
        articles.append(
            Article(
                title=title,
                url=link,
                source=name,
                source_weight=weight,
                summary=_strip_html(raw_summary)[:2000],
                published_ts=_entry_timestamp(entry),
            )
        )
    return FeedResult(name=name, articles=articles)


async def fetch_all_feeds(
    feeds: list[dict], max_age_hours: int
) -> tuple[list[Article], list[FeedResult]]:
    """
    Récupère tous les flux en parallèle et ne garde que les articles récents.

    Retourne (articles, résultats par flux). Le second élément alimente le
    suivi de santé : un flux mort doit être visible, pas silencieux.
    """
    tasks = [
        asyncio.to_thread(_parse_feed, feed["url"], feed["name"], feed["weight"])
        for feed in feeds
    ]
    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    cutoff = time.time() - max_age_hours * 3600
    articles: list[Article] = []
    results: list[FeedResult] = []

    for feed, result in zip(feeds, raw_results):
        if isinstance(result, Exception):
            result = FeedResult(name=feed["name"], error=f"{type(result).__name__}: {result}")
        results.append(result)

        if result.error:
            log.warning("Flux %s en erreur : %s", result.name, result.error)
            continue

        fresh = [a for a in result.articles if not a.published_ts or a.published_ts >= cutoff]
        articles.extend(fresh)
        log.info("%-22s → %d entrées (%d récentes)", result.name, len(result.articles), len(fresh))

    # Plus récent d'abord (les articles sans date passent en dernier).
    articles.sort(key=lambda a: a.published_ts, reverse=True)
    return articles, results


def _extract_with_soup(raw_html: str) -> str:
    """Repli maison : les paragraphes du conteneur d'article le plus probable."""
    soup = BeautifulSoup(raw_html, "html.parser")
    for tag in soup(["script", "style", "nav", "header", "footer", "aside", "form", "iframe"]):
        tag.decompose()
    container = soup.find("article") or soup.find("main") or soup.body
    if container is None:
        return ""
    paragraphs = [p.get_text(" ", strip=True) for p in container.find_all("p")]
    return " ".join(p for p in paragraphs if len(p) > 40)


def extract_text(raw_html: str) -> str:
    """
    Extrait le texte principal d'une page.

    trafilatura sait écarter menus, encarts et blocs de recommandation bien
    mieux qu'une heuristique sur les balises <p>. On l'utilise s'il est
    installé, sinon on retombe sur BeautifulSoup.
    """
    if HAS_TRAFILATURA:
        try:
            extracted = trafilatura.extract(
                raw_html,
                include_comments=False,
                include_tables=False,
                favor_precision=True,
            )
            if extracted and len(extracted) > 200:
                return " ".join(extracted.split())
        except Exception as exc:  # pragma: no cover
            log.debug("trafilatura a échoué, repli sur BeautifulSoup : %s", exc)
    return " ".join(_extract_with_soup(raw_html).split())


async def _fetch_one(session: aiohttp.ClientSession, article: Article, max_chars: int) -> None:
    """Télécharge la page et en extrait le texte principal (best effort)."""
    try:
        async with session.get(article.url, allow_redirects=True) as resp:
            if resp.status != 200:
                log.debug("HTTP %s sur %s", resp.status, article.url)
                return
            ctype = resp.headers.get("Content-Type", "")
            if "html" not in ctype and "xml" not in ctype:
                return
            raw = await resp.text(errors="ignore")
    except Exception as exc:  # réseau, timeout, SSL...
        log.debug("Impossible de récupérer %s : %s", article.url, exc)
        return

    text = extract_text(raw)
    if len(text) < 200:  # extraction ratée : on garde le résumé RSS
        return
    article.fulltext = html.unescape(text)[:max_chars]


async def enrich_with_fulltext(
    articles: list[Article], user_agent: str, timeout: int, max_chars: int
) -> None:
    """Récupère le corps de plusieurs articles en parallèle (5 max à la fois)."""
    if not articles:
        return
    connector = aiohttp.TCPConnector(limit=5)
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(
        connector=connector, timeout=client_timeout, headers={"User-Agent": user_agent}
    ) as session:
        await asyncio.gather(
            *(_fetch_one(session, a, max_chars) for a in articles),
            return_exceptions=True,
        )
