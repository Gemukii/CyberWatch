"""
Tests de la boucle de feedback.

Les cas couverts portent surtout sur les **garde-fous** : un système qui
apprend d'un signal faible dérive vite, et c'est ce qui doit être verrouillé
par des tests plutôt que par de la vigilance.
"""

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import feedback as fb


# --------------------------------------------------------------------------- #
# Encodage / décodage des signaux
# --------------------------------------------------------------------------- #
def test_encodage_puis_decodage_conserve_les_signaux():
    encode = fb.encode_signals(["ransomware", "produit-repandu"])
    assert fb.decode_signals(f"Score 21 · {encode}") == ["ransomware", "produit-repandu"]


def test_signaux_factuels_non_encodes():
    """KEV et EPSS ne s'apprennent pas : ils ne doivent pas être encodés."""
    encode = fb.encode_signals(["kev", "epss", "ransomware"])
    assert fb.decode_signals(encode) == ["ransomware"]


def test_pied_sans_signaux_renvoie_liste_vide():
    assert fb.decode_signals("Score 12 · #fortinet") == []
    assert fb.decode_signals("") == []


def test_encodage_borne_le_nombre_de_signaux():
    encode = fb.encode_signals([f"signal-{i}" for i in range(20)])
    assert len(fb.decode_signals(encode)) <= 8


# --------------------------------------------------------------------------- #
# Calcul des ajustements
# --------------------------------------------------------------------------- #
def make_weights(signals=None, sources=None, min_votes=3, max_adjustment=4):
    return fb.LearnedWeights(
        signals={k: fb.Tally(*v) for k, v in (signals or {}).items()},
        sources={k: fb.Tally(*v) for k, v in (sources or {}).items()},
        min_votes=min_votes,
        max_adjustment=max_adjustment,
    )


def test_aucun_ajustement_sous_le_minimum_de_votes():
    """Un ou deux clics ne doivent pas réorienter la veille."""
    w = make_weights({"phishing": (2, 0)}, min_votes=3)
    delta, _ = w.adjustment(["phishing"])
    assert delta == 0


def test_votes_positifs_augmentent_le_score():
    w = make_weights({"ransomware": (10, 0)})
    delta, explication = w.adjustment(["ransomware"])
    assert delta > 0 and "ransomware" in explication


def test_votes_negatifs_diminuent_le_score():
    w = make_weights({"phishing": (0, 10)})
    delta, _ = w.adjustment(["phishing"])
    assert delta < 0


def test_votes_partages_donnent_un_ajustement_faible():
    w = make_weights({"correctif": (5, 5)})
    delta, _ = w.adjustment(["correctif"])
    assert delta == 0


def test_confiance_croit_avec_le_nombre_de_votes():
    """20 votes unanimes doivent peser plus que 3 votes unanimes."""
    peu = make_weights({"malware": (3, 0)})
    beaucoup = make_weights({"malware": (30, 0)})
    assert beaucoup.adjustment(["malware"])[0] > peu.adjustment(["malware"])[0]


# --------------------------------------------------------------------------- #
# Garde-fous
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("factuel", ["kev", "epss", "cve", "cvss"])
def test_signaux_factuels_jamais_ajustes(factuel):
    """
    Garde-fou central : un vote exprime un goût, pas un fait. Le KEV dit
    qu'une vulnérabilité est exploitée — aucun 👎 ne peut rendre ça faux.
    """
    w = make_weights({factuel: (0, 50)})
    delta, _ = w.adjustment([factuel])
    assert delta == 0


def test_ajustement_borne_par_signal():
    w = make_weights({"ransomware": (1000, 0)}, max_adjustment=4)
    delta, _ = w.adjustment(["ransomware"])
    assert delta <= 4


def test_cumul_de_signaux_borne_globalement():
    """Dix signaux positifs ne doivent pas produire un ajustement de +40."""
    w = make_weights({f"s{i}": (50, 0) for i in range(10)}, max_adjustment=4)
    delta, _ = w.adjustment([f"s{i}" for i in range(10)])
    assert delta <= 8


def test_signal_inconnu_ignore():
    w = make_weights({"ransomware": (10, 0)})
    delta, _ = w.adjustment(["signal-jamais-vu"])
    assert delta == 0


def test_source_ajustee_separement():
    w = make_weights(sources={"SecurityWeek": (0, 12)})
    delta, explication = w.adjustment([], source="SecurityWeek")
    assert delta < 0 and "SecurityWeek" in explication


# --------------------------------------------------------------------------- #
# Collecte depuis l'historique Discord
# --------------------------------------------------------------------------- #
class FakeReaction:
    def __init__(self, emoji, count, me=False):
        self.emoji, self.count, self.me = emoji, count, me


class FakeEmbed:
    def __init__(self, url, footer, author=None):
        self.url = url
        self.footer = types.SimpleNamespace(text=footer)
        self.author = types.SimpleNamespace(name=author) if author else None


class FakeMessage:
    def __init__(self, embeds, reactions):
        self.embeds, self.reactions = embeds, reactions


class FakeChannel:
    def __init__(self, messages):
        self._messages = messages

    def history(self, limit=None, after=None):
        async def gen():
            for message in self._messages:
                yield message
        return gen()


async def _collect(messages, **kw):
    return await fb.collect_feedback(FakeChannel(messages), **kw)


@pytest.mark.asyncio
async def test_collecte_agrege_les_votes():
    messages = [
        FakeMessage(
            [FakeEmbed("https://ex.com/1", "Score 20 · sig:ransomware,rce",
                       "BleepingComputer · Titre")],
            [FakeReaction(fb.UPVOTE, 3), FakeReaction(fb.DOWNVOTE, 1)],
        ),
    ]
    w = await _collect(messages)
    assert w.signals["ransomware"].up == 3
    assert w.signals["ransomware"].down == 1
    assert w.sources["BleepingComputer"].up == 3
    assert w.articles_voted == 1


@pytest.mark.asyncio
async def test_reaction_du_bot_non_comptee():
    """Le bot pré-pose 👍/👎 : sa propre réaction ne doit pas voter."""
    messages = [
        FakeMessage(
            [FakeEmbed("https://ex.com/1", "sig:phishing")],
            [FakeReaction(fb.UPVOTE, 1, me=True), FakeReaction(fb.DOWNVOTE, 1, me=True)],
        ),
    ]
    w = await _collect(messages)
    assert w.votes_seen == 0
    assert not w.signals


@pytest.mark.asyncio
async def test_autres_emojis_ignores():
    """🔖 ou 👀 restent disponibles pour un usage personnel."""
    messages = [
        FakeMessage(
            [FakeEmbed("https://ex.com/1", "sig:phishing")],
            [FakeReaction("🔖", 5), FakeReaction("👀", 2)],
        ),
    ]
    w = await _collect(messages)
    assert w.votes_seen == 0


@pytest.mark.asyncio
async def test_messages_sans_reaction_ignores():
    messages = [FakeMessage([FakeEmbed("https://ex.com/1", "sig:rce")], [])]
    w = await _collect(messages)
    assert w.articles_voted == 0


@pytest.mark.asyncio
async def test_entetes_de_digest_ignorees():
    """Un embed sans URL est un en-tête, pas un article."""
    messages = [
        FakeMessage(
            [FakeEmbed(None, "Résumés : gemini · Synthèse quotidienne")],
            [FakeReaction(fb.UPVOTE, 4)],
        ),
    ]
    w = await _collect(messages)
    assert w.articles_voted == 0


@pytest.mark.asyncio
async def test_collecte_ne_leve_jamais():
    """Une API Discord indisponible dégrade le classement, n'arrête pas la veille."""
    class Cassé:
        def history(self, limit=None, after=None):
            async def gen():
                raise RuntimeError("403 Forbidden")
                yield  # pragma: no cover
            return gen()

    w = await fb.collect_feedback(Cassé())
    assert w.votes_seen == 0
    assert not w.is_active
