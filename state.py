"""
Index anti-doublons en mémoire, amorcé depuis l'historique Discord.

Aucune écriture disque : Discord fait office de stockage persistant.
Voir docs/ARCHITECTURE.md §3.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

log = logging.getLogger(__name__)

# Marqueurs discrets inscrits dans le pied des embeds par publisher.py.
# Ils permettent de reconstruire l'état de publication depuis Discord seul,
# sans aucun fichier local.
DIGEST_MARKER = "#digest"
URGENT_MARKER = "#urgent"

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source",
}

# Plafond absolu de messages relus, quelle que soit la configuration :
# évite qu'un salon très ancien ne bloque le démarrage pendant des minutes.
HARD_HISTORY_CAP = 5000


def canonical_url(url: str) -> str:
    """Normalise une URL : host en minuscule, sans tracking ni fragment."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url.strip()
    query = [(k, v) for k, v in parse_qsl(parts.query) if k.lower() not in TRACKING_PARAMS]
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/"), urlencode(query), "")
    )


def url_hash(url: str) -> str:
    return hashlib.sha256(canonical_url(url).encode("utf-8")).hexdigest()[:16]


def normalize_title(title: str) -> str:
    """Titre réduit à l'essentiel pour comparer deux articles entre eux."""
    cleaned = "".join(c.lower() if c.isalnum() or c.isspace() else " " for c in title)
    return " ".join(cleaned.split())


class FeedHealth:
    """
    Suivi de santé d'un flux.

    Un flux mort échoue en silence : l'URL a changé, le site a fermé, et le
    bot continue tranquillement sans jamais rien remonter. On compte donc
    les cycles consécutifs sans article pour rendre la panne visible.
    """

    def __init__(self, name: str):
        self.name = name
        self.consecutive_failures = 0
        self.last_error: str | None = None
        self.last_success_ts: float = 0.0
        self.total_articles = 0

    def record(self, count: int, error: str | None) -> None:
        if error or count == 0:
            self.consecutive_failures += 1
            self.last_error = error or "aucun article remonté"
        else:
            self.consecutive_failures = 0
            self.last_error = None
            self.last_success_ts = time.time()
            self.total_articles += count

    def is_unhealthy(self, threshold: int) -> bool:
        return self.consecutive_failures >= threshold


class State:
    """Index en mémoire des articles publiés + santé des flux."""

    def __init__(self, retention_days: int = 7):
        self.retention_days = retention_days
        self.retention_seconds = retention_days * 86400
        self._seen: dict[str, float] = {}                  # url_hash -> timestamp
        self._titles: deque[tuple[str, float]] = deque()   # (titre normalisé, timestamp)
        self._runs: deque[dict] = deque(maxlen=20)
        self._feeds: dict[str, FeedHealth] = {}
        self._primed = False
        self.started_at = time.time()

    # --- Amorçage depuis Discord ---
    @property
    def primed(self) -> bool:
        return self._primed

    async def prime_from_channel(self, channel, limit: int = 0, budget=None) -> int:
        """
        Reconstruit l'index à partir des messages déjà publiés dans le salon.

        La lecture est bornée **par la date** (fenêtre `retention_days`), pas
        par un nombre fixe de messages : c'est ce qui garantit que l'index
        couvre exactement la fenêtre anti-doublons, quel que soit le rythme
        de publication. discord.py pagine automatiquement.

        `limit` sert de plafond de sécurité optionnel (0 = pas de plafond).
        Nécessite la permission « Lire l'historique des messages ».

        Si `budget` est fourni, on y reporte aussi la date du dernier digest
        et le nombre d'alertes urgentes du jour : sans ça, un redémarrage à
        10 h republierait le digest déjà envoyé à 8 h.
        """
        if self._primed:
            # on_ready se redéclenche à chaque reconnexion : sans ce garde-fou on
        # relirait tout l'historique pour rien.
            log.debug("Index déjà amorcé, relecture ignorée")
            return 0

        after = datetime.now(tz=timezone.utc) - timedelta(days=self.retention_days)
        effective_limit = min(limit, HARD_HISTORY_CAP) if limit > 0 else HARD_HISTORY_CAP

        found = 0
        scanned = 0
        try:
            async for message in channel.history(
                limit=effective_limit, after=after, oldest_first=False
            ):
                scanned += 1
                for embed in message.embeds:
                    ts = message.created_at.timestamp()
                    if not embed.url:
                        # En-tête sans lien : c'est lui qui marque un digest
                        # déjà envoyé (cf. publisher.DIGEST_MARKER).
                        if budget is not None and embed.footer and embed.footer.text:
                            if DIGEST_MARKER in embed.footer.text:
                                budget.note_digest_from_timestamp(ts)
                        continue
                    if budget is not None and embed.footer and embed.footer.text:
                        if URGENT_MARKER in embed.footer.text:
                            budget.note_urgent_from_timestamp(ts)
                    self._seen[url_hash(embed.url)] = ts
                    raw_title = (embed.author.name if embed.author else None) or embed.title or ""
                    if raw_title:
                        self._titles.append((normalize_title(raw_title), ts))
                    found += 1
        except Exception as exc:
            # Échec non bloquant : au pire quelques articles republiés une fois.
            log.warning(
                "Amorçage depuis l'historique impossible (%s). "
                "Vérifie la permission « Lire l'historique des messages ».",
                exc,
            )
            return 0

        # L'historique est parcouru du plus récent au plus ancien : on remet
        # la deque dans l'ordre chronologique pour que la purge fonctionne.
        self._titles = deque(sorted(self._titles, key=lambda item: item[1]))
        self._primed = True

        if scanned >= effective_limit:
            log.warning(
                "Plafond de %d messages atteint à l'amorçage : l'index peut être "
                "incomplet sur la fenêtre de %d jours.",
                effective_limit,
                self.retention_days,
            )
        log.info(
            "Amorçage : %d articles retrouvés dans %d messages d'historique (%d j)",
            found, scanned, self.retention_days,
        )
        return found

    # --- Déduplication ---
    def _purge(self) -> None:
        """Oublie ce qui dépasse la fenêtre de rétention."""
        cutoff = time.time() - self.retention_seconds
        for h in [h for h, ts in self._seen.items() if ts < cutoff]:
            del self._seen[h]
        while self._titles and self._titles[0][1] < cutoff:
            self._titles.popleft()

    def is_known(self, url: str) -> bool:
        return url_hash(url) in self._seen

    def recent_titles(self, days: int = 5) -> list[str]:
        self._purge()
        cutoff = time.time() - days * 86400
        return [title for title, ts in self._titles if ts >= cutoff]

    def mark_published(self, url: str, title: str, source: str = "", severity: str = "") -> None:
        now = time.time()
        self._seen[url_hash(url)] = now
        self._titles.append((normalize_title(title), now))

    # --- Santé des flux ---
    def record_feed_results(self, results) -> None:
        for result in results:
            health = self._feeds.setdefault(result.name, FeedHealth(result.name))
            health.record(len(result.articles), result.error)

    def unhealthy_feeds(self, threshold: int) -> list[FeedHealth]:
        return [f for f in self._feeds.values() if f.is_unhealthy(threshold)]

    def feed_report(self, threshold: int) -> list[str]:
        """Lignes d'état par flux, pour /cyber-sources."""
        lines = []
        for health in sorted(self._feeds.values(), key=lambda f: f.name):
            if health.is_unhealthy(threshold):
                icon, detail = "🔴", f"{health.consecutive_failures} cycles sans article"
                if health.last_error:
                    detail += f" — {health.last_error[:60]}"
            elif health.consecutive_failures:
                icon, detail = "🟡", f"{health.consecutive_failures} cycle(s) vide(s)"
            else:
                icon, detail = "🟢", f"{health.total_articles} articles vus"
            lines.append(f"{icon} **{health.name}** — {detail}")
        return lines

    # --- Statistiques ---
    def log_run(
        self,
        fetched: int = 0,
        queued: int = 0,
        queue_size: int = 0,
        urgent: int = 0,
        digest: int = 0,
        posted: int = 0,
        deferred: int = 0,
        error: str | None = None,
    ) -> None:
        """Enregistre le bilan d'un cycle. Les compteurs distinguent la
        collecte (continue) de la publication (arbitrée)."""
        self._runs.append(
            {
                "started_at": int(time.time()),
                "fetched": fetched,
                "queued": queued,
                "queue_size": queue_size,
                "urgent": urgent,
                "digest": digest,
                "posted": posted,
                "deferred": deferred,
                "error": error,
            }
        )

    def last_run(self) -> dict | None:
        return self._runs[-1] if self._runs else None

    def count_published(self, days: int = 7) -> int:
        cutoff = time.time() - days * 86400
        return sum(1 for ts in self._seen.values() if ts >= cutoff)

    def memory_footprint(self) -> str:
        approx = len(self._seen) * 40 + sum(len(t) for t, _ in self._titles)
        return f"{approx / 1024:.1f} Ko"

    def uptime(self) -> str:
        seconds = int(time.time() - self.started_at)
        days, rest = divmod(seconds, 86400)
        hours, minutes = divmod(rest // 60, 60)
        return f"{days} j {hours} h" if days else f"{hours} h {minutes} min"
