"""
Tests de l'état sans base de données et de la robustesse du cycle.

Vérifient notamment les trois bugs corrigés en v2 :
  - marquage limité aux articles réellement publiés
  - amorçage borné par la date, pas par un nombre fixe de messages
  - idempotence de l'amorçage sur reconnexion Discord
"""

import asyncio
import time
import types

import pytest

import filters
from enrichment import extract_cves
from sources import Article, FeedResult
from state import State


def article(**kwargs) -> Article:
    base = {"title": "Titre", "url": "https://example.test/a", "source": "Test"}
    base.update(kwargs)
    return Article(**base)


# --------------------------------------------------------------------------- #
# Faux objets Discord
# --------------------------------------------------------------------------- #
class FakeEmbed:
    def __init__(self, url, author_name=None, title="🔴 Titre reformulé"):
        self.url = url
        self.title = title
        self.author = types.SimpleNamespace(name=author_name) if author_name else None


class FakeMessage:
    def __init__(self, embeds, age_seconds=3600):
        self.embeds = embeds
        self.created_at = types.SimpleNamespace(timestamp=lambda: time.time() - age_seconds)


class FakeChannel:
    """Salon Discord minimal : historique en lecture, envois comptabilisés."""

    def __init__(self, messages=None, fail_on=()):
        self.messages = messages or []
        self.fail_on = fail_on          # indices d'envois qui doivent échouer
        self.sent = 0

    def history(self, limit=None, after=None, oldest_first=None):
        async def generator():
            for message in self.messages:
                yield message
        return generator()

    async def send(self, *args, **kwargs):
        index = self.sent
        self.sent += 1
        if index in self.fail_on:
            raise RuntimeError("échec simulé d'envoi")
        return object()


# --------------------------------------------------------------------------- #
# Amorçage depuis l'historique Discord
# --------------------------------------------------------------------------- #
def test_index_reconstruit_apres_redemarrage():
    """Un bot qui redémarre ne doit pas republier ce qui est déjà dans le salon."""
    titre_origine = "Critical Fortinet zero-day actively exploited"
    channel = FakeChannel([
        FakeMessage([FakeEmbed("https://cert.test/1", f"CERT-FR · {titre_origine}")]),
        FakeMessage([FakeEmbed(None, title="🛡️ Veille cyber")]),  # en-tête, ignoré
    ])
    state = State(retention_days=7)
    assert asyncio.run(state.prime_from_channel(channel)) == 1
    assert state.is_known("https://cert.test/1?utm_source=twitter")


def test_dedup_par_titre_preservee_apres_redemarrage():
    """
    Le titre publié est reformulé en français ; c'est author.name qui porte
    le titre d'origine et permet de reconnaître la même news ailleurs.
    """
    titre_origine = "Critical Fortinet zero-day actively exploited"
    channel = FakeChannel([
        FakeMessage([FakeEmbed("https://cert.test/1", f"CERT-FR · {titre_origine}")])
    ])
    state = State(retention_days=7)
    asyncio.run(state.prime_from_channel(channel))

    reprise = article(
        title=titre_origine + "!", url="https://autre.test/9",
        summary="CVE-2026-1234 RCE. CVSS: 9.8.", cves=["CVE-2026-1234"],
    )
    assert filters.select_articles([reprise], state, 5, 0.72, 10) == []


def test_amorcage_idempotent_sur_reconnexion():
    """
    on_ready se redéclenche à chaque reconnexion Discord. Relire tout
    l'historique à chaque fois serait inutile et coûteux.
    """
    channel = FakeChannel([FakeMessage([FakeEmbed("https://cert.test/1", "S · T")])])
    state = State(retention_days=7)
    assert asyncio.run(state.prime_from_channel(channel)) == 1
    assert asyncio.run(state.prime_from_channel(channel)) == 0   # déjà amorcé
    assert state.primed


def test_amorcage_echoue_sans_bloquer():
    """Sans permission de lecture d'historique, le bot démarre quand même."""
    class BrokenChannel:
        def history(self, **kwargs):
            async def generator():
                raise PermissionError("Missing Read Message History")
                yield  # pragma: no cover
            return generator()

    state = State(retention_days=7)
    assert asyncio.run(state.prime_from_channel(BrokenChannel())) == 0
    assert not state.primed          # signalé comme non amorcé dans /cyber-status


# --------------------------------------------------------------------------- #
# Publication partielle
# --------------------------------------------------------------------------- #
def test_seuls_les_articles_publies_sont_memorises():
    """
    Bug corrigé en v2 : un embed dont l'envoi échoue ne doit PAS être marqué
    comme vu, sinon il est perdu définitivement.
    """
    pytest.importorskip("discord")
    import publisher
    from summarizer import Summary

    # envoi 0 = en-tête, 1 = premier article (échoue), 2 = second article
    channel = FakeChannel(fail_on=(1,))
    items = [
        (article(url="https://a.test/1"), Summary(title="A", bullets=["x"], severity="Moyen")),
        (article(url="https://a.test/2"), Summary(title="B", bullets=["y"], severity="Moyen")),
    ]

    # publisher attend discord.HTTPException ; on élargit le filet pour le test
    original = publisher.discord.HTTPException
    publisher.discord.HTTPException = RuntimeError
    try:
        posted = asyncio.run(publisher.publish(channel, items, "gemini"))
    finally:
        publisher.discord.HTTPException = original

    assert len(posted) == 1
    assert posted[0][0].url == "https://a.test/2"


# --------------------------------------------------------------------------- #
# Santé des flux
# --------------------------------------------------------------------------- #
def test_flux_mort_signale_apres_n_cycles():
    state = State(retention_days=7)
    for _ in range(3):
        state.record_feed_results([
            FeedResult(name="MortRSS", articles=[], error="HTTP 404"),
            FeedResult(name="VivantRSS", articles=[article()]),
        ])
    morts = [f.name for f in state.unhealthy_feeds(threshold=3)]
    assert morts == ["MortRSS"]


def test_flux_retabli_remet_le_compteur_a_zero():
    state = State(retention_days=7)
    state.record_feed_results([FeedResult(name="F", articles=[], error="HTTP 500")])
    state.record_feed_results([FeedResult(name="F", articles=[article()])])
    assert state.unhealthy_feeds(threshold=1) == []


# --------------------------------------------------------------------------- #
# Extraction de CVE
# --------------------------------------------------------------------------- #
def test_extraction_cve_valides():
    cves = extract_cves("Voir CVE-2026-1234 et cve-2025-99999, corrigées.")
    assert cves == ["CVE-2026-1234", "CVE-2025-99999"]


@pytest.mark.parametrize("faux", ["CVE-0000-0000", "CVE-1990-1234", "CVE-2099-1234"])
def test_annee_aberrante_rejetee(faux):
    assert extract_cves(faux) == []


def test_doublons_cve_supprimes():
    assert extract_cves("CVE-2026-1234 puis encore CVE-2026-1234") == ["CVE-2026-1234"]
