"""
File d'attente des candidats, quotas quotidiens, arbitrage urgence/digest.

Les articles ne sont pas publiés à l'arrivée : ils concourent entre eux et
seuls les meilleurs de la journée sortent. Voir docs/ARCHITECTURE.md §1.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

log = logging.getLogger(__name__)


class CandidateQueue:
    """File des articles en attente d'arbitrage, dédupliquée par URL."""

    def __init__(self, ttl_hours: int = 36):
        self.ttl_seconds = ttl_hours * 3600
        self._items: dict[str, tuple[object, float]] = {}  # url_hash -> (article, ts)

    def __len__(self) -> int:
        return len(self._items)

    def add(self, article, key: str) -> bool:
        """
        Ajoute ou met à jour un candidat. Retourne True si c'est un nouveau.

        Un article déjà en file voit son score actualisé : le contenu a pu
        s'enrichir entre-temps (ajout au KEV, score EPSS qui monte), et c'est
        le score le plus récent qui doit arbitrer.
        """
        is_new = key not in self._items
        if not is_new:
            previous, first_seen = self._items[key]
            if getattr(article, "score", 0) >= getattr(previous, "score", 0):
                self._items[key] = (article, first_seen)  # on garde la date d'entrée
            return False
        self._items[key] = (article, time.time())
        return True

    def purge(self, max_age_hours: int | None = None) -> int:
        """Retire les candidats trop vieux pour être encore d'actualité."""
        ttl = (max_age_hours * 3600) if max_age_hours else self.ttl_seconds
        cutoff = time.time() - ttl
        expired = [k for k, (_, ts) in self._items.items() if ts < cutoff]
        for key in expired:
            del self._items[key]
        return len(expired)

    def remove(self, keys: list[str]) -> None:
        for key in keys:
            self._items.pop(key, None)

    def ranked(self) -> list[tuple[str, object]]:
        """Candidats triés par score décroissant, meilleur en tête."""
        return [
            (key, article)
            for key, (article, _) in sorted(
                self._items.items(),
                key=lambda item: getattr(item[1][0], "score", 0),
                reverse=True,
            )
        ]

    def top_scores(self, count: int = 5) -> list[int]:
        return [getattr(a, "score", 0) for _, a in self.ranked()[:count]]


class DailyBudget:
    """
    Suit ce qui a été publié aujourd'hui et décide s'il est l'heure du digest.

    La journée est calculée dans le fuseau de l'utilisateur, pas en UTC :
    un digest « à 8 h » doit tomber à 8 h locales, y compris en heure d'été.
    """

    def __init__(self, timezone_name: str = "Europe/Paris", digest_hour: int = 8):
        try:
            self.tz = ZoneInfo(timezone_name)
        except Exception:
            log.warning("Fuseau %r inconnu, repli sur UTC", timezone_name)
            self.tz = timezone.utc
        self.digest_hour = digest_hour
        self._last_digest_date: str | None = None
        self._urgent_by_date: dict[str, int] = {}

    # ------------------------------------------------------------------ #
    def now(self) -> datetime:
        return datetime.now(tz=self.tz)

    def today_key(self, moment: datetime | None = None) -> str:
        return (moment or self.now()).strftime("%Y-%m-%d")

    # --- Digest ---
    @property
    def last_digest_date(self) -> str | None:
        return self._last_digest_date

    def note_digest(self, moment: datetime | None = None) -> None:
        self._last_digest_date = self.today_key(moment)

    def note_digest_from_timestamp(self, ts: float) -> None:
        """Utilisé à l'amorçage, en relisant l'historique Discord."""
        date_key = self.today_key(datetime.fromtimestamp(ts, tz=self.tz))
        if self._last_digest_date is None or date_key > self._last_digest_date:
            self._last_digest_date = date_key

    def digest_due(self, moment: datetime | None = None) -> bool:
        """
        Vrai si le digest du jour doit partir maintenant.

        On publie dès que l'heure cible est atteinte ou dépassée : si le VPS
        était éteint à 8 h, le digest part au premier cycle après le
        redémarrage plutôt que d'être sauté pour la journée.
        """
        moment = moment or self.now()
        if moment.hour < self.digest_hour:
            return False
        return self._last_digest_date != self.today_key(moment)

    def next_digest_at(self, moment: datetime | None = None) -> datetime:
        moment = moment or self.now()
        target = moment.replace(
            hour=self.digest_hour, minute=0, second=0, microsecond=0
        )
        if moment >= target and self._last_digest_date == self.today_key(moment):
            target += timedelta(days=1)
        elif moment >= target:
            return moment  # en retard : dû immédiatement
        return target

    # --- Urgences ---
    def urgent_count_today(self, moment: datetime | None = None) -> int:
        return self._urgent_by_date.get(self.today_key(moment), 0)

    def note_urgent(self, count: int = 1, moment: datetime | None = None) -> None:
        key = self.today_key(moment)
        self._urgent_by_date[key] = self._urgent_by_date.get(key, 0) + count
        # On ne garde que quelques jours d'historique.
        for old in sorted(self._urgent_by_date)[:-7]:
            del self._urgent_by_date[old]

    def note_urgent_from_timestamp(self, ts: float) -> None:
        moment = datetime.fromtimestamp(ts, tz=self.tz)
        self.note_urgent(1, moment)

    def urgent_slots_left(self, daily_max: int) -> int:
        return max(0, daily_max - self.urgent_count_today())


def is_urgent(article, settings) -> tuple[bool, str]:
    """
    Décide si un article justifie une publication immédiate, hors quota.

    Les critères reposent sur des sources autoritatives plutôt que sur du
    vocabulaire journalistique : une alerte qui se déclenche trop souvent
    cesse d'être une alerte.

    Retourne (urgent, motif lisible).
    """
    # 1. Inscrite au catalogue CISA KEV = exploitation avérée en conditions
    #    réelles. C'est le signal le plus fort disponible gratuitement.
    if getattr(article, "kev_cves", None):
        cve = article.kev_cves[0]
        if getattr(article, "kev_ransomware", False):
            return True, f"{cve} au catalogue CISA KEV — campagne de rançongiciel connue"
        return True, f"{cve} au catalogue CISA KEV — exploitation avérée"

    # 2. EPSS très élevé : exploitation jugée hautement probable à 30 jours.
    epss = getattr(article, "epss_max", None)
    if epss is not None and epss >= settings.urgent_epss_threshold:
        return True, f"EPSS {epss:.0%} — exploitation hautement probable sous 30 jours"

    # 3. Filet de sécurité : score exceptionnel, très au-dessus du seuil
    #    habituel. Couvre les sujets sans CVE (compromission majeure,
    #    incident de chaîne d'approvisionnement) qu'aucun catalogue ne voit.
    if getattr(article, "score", 0) >= settings.urgent_score_threshold:
        return True, f"score de pertinence exceptionnel ({article.score})"

    return False, ""
