"""
Apprentissage des poids de scoring depuis les réactions 👍/👎.

Les votes vivent dans Discord, donc les poids sont recalculés depuis
l'historique plutôt que stockés. Garde-fous et calcul : docs/ARCHITECTURE.md §4.
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

log = logging.getLogger(__name__)

# Réactions reconnues comme un vote. Toute autre réaction est ignorée,
# ce qui laisse 🔖, 👀 ou autres libres pour un usage personnel.
UPVOTE = "👍"
DOWNVOTE = "👎"

# Marqueur inscrit dans le pied de l'embed. Format : "sig:nom1,nom2,nom3"
SIGNAL_PREFIX = "sig:"
SIGNAL_RE = re.compile(r"sig:([a-z0-9\-,]+)", re.IGNORECASE)

# Ces signaux décrivent des faits, pas des goûts : ils ne s'apprennent pas.
FACTUAL_SIGNALS = frozenset({"kev", "epss", "cve", "cvss"})


def encode_signals(signals: list[str]) -> str:
    """Sérialise les signaux pour le pied d'embed."""
    apprenables = [s for s in signals if s not in FACTUAL_SIGNALS]
    return SIGNAL_PREFIX + ",".join(apprenables[:8]) if apprenables else ""


def decode_signals(footer_text: str) -> list[str]:
    """Relit les signaux depuis le pied d'un embed déjà publié."""
    match = SIGNAL_RE.search(footer_text or "")
    if not match:
        return []
    return [s for s in match.group(1).lower().split(",") if s]


@dataclass
class Tally:
    """Compteur de votes pour un signal ou une source."""
    up: int = 0
    down: int = 0

    @property
    def total(self) -> int:
        return self.up + self.down

    @property
    def ratio(self) -> float:
        """Entre -1 (rejet unanime) et +1 (adhésion unanime)."""
        return (self.up - self.down) / self.total if self.total else 0.0


@dataclass
class LearnedWeights:
    """
    Ajustements appris, prêts à être appliqués au scoring.

    Instancié par `collect_feedback()`, puis passé à `filters.score_article()`.
    """
    signals: dict[str, Tally] = field(default_factory=dict)
    sources: dict[str, Tally] = field(default_factory=dict)
    votes_seen: int = 0
    articles_voted: int = 0
    computed_at: float = field(default_factory=time.time)
    min_votes: int = 3
    max_adjustment: int = 4

    def _delta(self, tally: Tally) -> int:
        """
        Convertit un compteur en ajustement de score.

        La confiance croît avec le nombre de votes : 3 votes unanimes pèsent
        moins que 20. Le facteur n/(n+3) évite qu'un petit échantillon ne
        produise l'ajustement maximal.
        """
        if tally.total < self.min_votes:
            return 0
        confiance = tally.total / (tally.total + 3)
        return round(self.max_adjustment * tally.ratio * confiance)

    def adjustment(self, signals: list[str], source: str = "") -> tuple[int, str]:
        """
        Ajustement total pour un article, avec son explication lisible.

        Retourne (delta, explication). L'explication alimente `/cyber-queue`
        et les logs : une boucle de feedback opaque est impossible à déboguer.
        """
        details: list[str] = []
        total = 0

        for name in signals:
            if name in FACTUAL_SIGNALS:
                continue  # garde-fou n°1
            tally = self.signals.get(name)
            if not tally:
                continue
            delta = self._delta(tally)
            if delta:
                total += delta
                details.append(f"{name} {delta:+d}")

        if source:
            tally = self.sources.get(source)
            if tally:
                delta = self._delta(tally)
                if delta:
                    total += delta
                    details.append(f"{source} {delta:+d}")

        # Garde-fou n°3 : bornage global, pour qu'un cumul de petits
        # ajustements ne finisse pas par dominer le score factuel.
        borne = self.max_adjustment * 2
        total = max(-borne, min(borne, total))
        return total, ", ".join(details[:4]) if details else "—"

    def top_signals(self, count: int = 8) -> list[tuple[str, Tally, int]]:
        """Signaux les plus influents, pour la commande de transparence."""
        rows = [
            (name, tally, self._delta(tally))
            for name, tally in self.signals.items()
            if tally.total >= self.min_votes
        ]
        rows.sort(key=lambda row: abs(row[2]), reverse=True)
        return rows[:count]

    def top_sources(self, count: int = 5) -> list[tuple[str, Tally, int]]:
        rows = [
            (name, tally, self._delta(tally))
            for name, tally in self.sources.items()
            if tally.total >= self.min_votes
        ]
        rows.sort(key=lambda row: abs(row[2]), reverse=True)
        return rows[:count]

    @property
    def is_active(self) -> bool:
        """Vrai dès qu'au moins un ajustement non nul s'applique."""
        return any(self._delta(t) for t in self.signals.values()) or any(
            self._delta(t) for t in self.sources.values()
        )


def _source_from_author(author_name: str) -> str:
    """L'auteur de l'embed vaut « Source · Titre d'origine »."""
    return (author_name or "").split("·")[0].strip()


async def collect_feedback(
    channel,
    lookback_days: int = 30,
    min_votes: int = 3,
    max_adjustment: int = 4,
    message_limit: int = 500,
) -> LearnedWeights:
    """
    Relit l'historique du salon et agrège les réactions en poids appris.

    Ne lève jamais : un feedback indisponible doit dégrader le classement,
    pas interrompre la veille.
    """
    weights = LearnedWeights(min_votes=min_votes, max_adjustment=max_adjustment)
    signals: dict[str, Tally] = defaultdict(Tally)
    sources: dict[str, Tally] = defaultdict(Tally)

    after = datetime.now(tz=timezone.utc) - timedelta(days=lookback_days)
    try:
        async for message in channel.history(limit=message_limit or None, after=after):
            if not message.reactions:
                continue
            for embed in message.embeds:
                if not embed.url:
                    continue  # en-tête de digest, statut… : pas un article

                footer = embed.footer.text if embed.footer else ""
                noms = decode_signals(footer)
                source = _source_from_author(embed.author.name if embed.author else "")
                if not noms and not source:
                    continue

                up = down = 0
                for reaction in message.reactions:
                    emoji = str(reaction.emoji)
                    # On retire le vote du bot lui-même, qui pré-pose les
                    # réactions pour rendre le vote accessible en un clic.
                    compte = max(0, reaction.count - (1 if reaction.me else 0))
                    if emoji == UPVOTE:
                        up += compte
                    elif emoji == DOWNVOTE:
                        down += compte

                if not (up or down):
                    continue

                weights.votes_seen += up + down
                weights.articles_voted += 1
                for nom in noms:
                    signals[nom].up += up
                    signals[nom].down += down
                if source:
                    sources[source].up += up
                    sources[source].down += down

    except Exception as exc:
        log.warning("Collecte du feedback impossible (%s) — scoring non ajusté", exc)
        return weights

    weights.signals = dict(signals)
    weights.sources = dict(sources)
    if weights.articles_voted:
        log.info(
            "Feedback : %d vote(s) sur %d article(s), %d signal(aux) ajusté(s)",
            weights.votes_seen,
            weights.articles_voted,
            sum(1 for t in weights.signals.values() if weights._delta(t)),
        )
    return weights
