"""
Collection: reading RSS/Atom feeds and extracting article bodies.

Downloads are async via aiohttp; feedparser only parses, in a thread.
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
import logging
import time
from calendar import timegm
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import aiohttp
import feedparser
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

# trafilatura is optional: the bot works without it, in degraded mode.
try:
    import trafilatura

    HAS_TRAFILATURA = True
except ImportError:  # pragma: no cover
    HAS_TRAFILATURA = False


@dataclass
class Article:
    """A candidate article, enriched as it moves through the pipeline."""

    title: str
    url: str
    source: str
    source_weight: int = 0
    source_type: str = "general"
    priority: str = "normal"
    summary: str = ""
    published_ts: float = 0.0
    fulltext: str = ""

    # Enrichment
    cves: list[str] = field(default_factory=list)
    kev_cves: list[str] = field(default_factory=list)
    kev_ransomware: bool = False
    epss_max: float | None = None

    # Watchlist terms found in the article
    watch_matches: list[str] = field(default_factory=list)

    # Classification
    category: str = "General Security"
    category_tags: list[str] = field(default_factory=list)

    # Filtering
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    @property
    def content(self) -> str:
        """Best available text for analysis and summarization."""
        return self.fulltext or self.summary

@dataclass
class FeedResult:
    """Result of reading a feed, for health tracking."""

    name: str
    articles: list[Article] = field(default_factory=list)
    error: str | None = None


def is_public_http_url(url: str) -> bool:
    """
    True for a web address the bot may fetch and publish.

    Links come from feeds, and the bot downloads them: a hijacked feed must
    not be able to point it at localhost or a private network.
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True  # a hostname, not an IP address


def _strip_html(raw: str) -> str:
    """Turns an HTML fragment into readable plain text."""
    if not raw:
        return ""
    text = BeautifulSoup(raw, "html.parser").get_text(" ", strip=True)
    return html.unescape(" ".join(text.split()))


def _entry_timestamp(entry) -> float:
    """Publication date of the entry, as a UTC epoch. 0 if not found."""
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        parsed = entry.get(key)
        if parsed:
            try:
                return float(timegm(parsed))  # the *_parsed fields are UTC
            except (TypeError, ValueError):
                continue
    return 0.0


def _parse_feed(
    raw: bytes,
    name: str,
    weight: int,
    source_type: str,
    priority: str,
) -> FeedResult:
    """Parses an already-downloaded feed (run in a thread: CPU-bound)."""
    try:
        parsed = feedparser.parse(raw)
    except Exception as exc:
        return FeedResult(name=name, error=f"{type(exc).__name__}: {exc}")

    if parsed.bozo and not parsed.entries:
        return FeedResult(name=name, error=str(parsed.get("bozo_exception", "unreadable feed")))

    articles = []
    for entry in parsed.entries:
        link = (entry.get("link") or "").strip()
        title = _strip_html(entry.get("title") or "")
        if not title or not is_public_http_url(link):
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
                source_type=source_type,
                priority=priority,
                summary=_strip_html(raw_summary)[:2000],
                published_ts=_entry_timestamp(entry),
            )
        )
    return FeedResult(name=name, articles=articles)


async def _fetch_feed(session: aiohttp.ClientSession, feed: dict) -> FeedResult:
    """
    Downloads then parses one feed.

    The download goes through aiohttp rather than feedparser's own fetcher,
    which has no timeout: one stalled server would hang the whole cycle.
    """
    name = feed["name"]
    try:
        async with session.get(feed["url"], allow_redirects=True) as resp:
            if resp.status != 200:
                return FeedResult(name=name, error=f"HTTP {resp.status}")
            raw = await resp.read()
    except Exception as exc:  # network, timeout, SSL...
        return FeedResult(name=name, error=f"{type(exc).__name__}: {exc}")

    return await asyncio.to_thread(
        _parse_feed,
        raw,
        name,
        feed["weight"],
        feed.get("source_type", "general"),
        feed.get("priority", "normal"),
    )


async def fetch_all_feeds(
    feeds: list[dict],
    max_age_hours: int,
    user_agent: str = "CyberWatchBot/2.0",
    timeout: int = 20,
) -> tuple[list[Article], list[FeedResult]]:
    """
    Fetches all feeds in parallel and keeps only recent articles.

    Returns (articles, per-feed results). The second element feeds health
    tracking: a dead feed needs to be visible, not silent.
    """
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(
        timeout=client_timeout, headers={"User-Agent": user_agent}
    ) as session:
        raw_results = await asyncio.gather(
            *(_fetch_feed(session, feed) for feed in feeds),
            return_exceptions=True,
        )

    cutoff = time.time() - max_age_hours * 3600
    articles: list[Article] = []
    results: list[FeedResult] = []

    for feed, result in zip(feeds, raw_results):
        if isinstance(result, Exception):
            result = FeedResult(name=feed["name"], error=f"{type(result).__name__}: {result}")
        results.append(result)

        if result.error:
            log.warning("Feed %s errored: %s", result.name, result.error)
            continue

        fresh = [a for a in result.articles if not a.published_ts or a.published_ts >= cutoff]
        articles.extend(fresh)
        log.info("%-22s -> %d entries (%d recent)", result.name, len(result.articles), len(fresh))

    # Most recent first (articles with no date sort last).
    articles.sort(key=lambda a: a.published_ts, reverse=True)
    return articles, results


def _extract_with_soup(raw_html: str) -> str:
    """Home-grown fallback: paragraphs from the most likely article container."""
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
    Extracts the main text of a page.

    trafilatura filters out menus, sidebars and recommendation blocks far
    better than a heuristic on <p> tags. Used if installed, otherwise
    falls back to BeautifulSoup.
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
            log.debug("trafilatura failed, falling back to BeautifulSoup: %s", exc)
    return " ".join(_extract_with_soup(raw_html).split())


async def _fetch_one(session: aiohttp.ClientSession, article: Article, max_chars: int) -> None:
    """Downloads the page and extracts its main text (best effort)."""
    try:
        async with session.get(article.url, allow_redirects=True) as resp:
            if resp.status != 200:
                log.debug("HTTP %s on %s", resp.status, article.url)
                return
            ctype = resp.headers.get("Content-Type", "")
            if "html" not in ctype and "xml" not in ctype:
                return
            raw = await resp.text(errors="ignore")
    except Exception as exc:  # network, timeout, SSL...
        log.debug("Could not fetch %s: %s", article.url, exc)
        return

    text = extract_text(raw)
    if len(text) < 200:  # extraction failed: keep the RSS summary
        return
    article.fulltext = html.unescape(text)[:max_chars]


async def enrich_with_fulltext(
    articles: list[Article], user_agent: str, timeout: int, max_chars: int
) -> None:
    """Fetches the body of several articles in parallel (5 at a time max)."""
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