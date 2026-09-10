"""
Tests de l'arbitrage quotidien : file de candidats, budget, urgences.

Ces tests protègent l'invariant principal du projet : **au plus N articles
par jour**, sauf urgence avérée, et jamais de remplissage pour atteindre le
quota.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

from selection import CandidateQueue, DailyBudget, is_urgent
from sources import Article

TZ = ZoneInfo("Europe/Paris")


def make_article(title="Titre", url="https://ex.com/a", score=10, **kw):
    article = Article(title=title, url=url, source=kw.pop("source", "S"))
    article.score = score
    article.cves = kw.pop("cves", [])
    article.kev_cves = kw.pop("kev_cves", [])
    article.kev_ransomware = kw.pop("kev_ransomware", False)
    article.epss_max = kw.pop("epss_max", None)
    return article


def make_settings(**overrides):
    base = dict(
        urgent_epss_threshold=0.7,
        urgent_score_threshold=30,
        urgent_daily_max=3,
        daily_quota=4,
        digest_floor_score=7,
        digest_min_articles=2,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


# --------------------------------------------------------------------------- #
# File de candidats
# --------------------------------------------------------------------------- #
def test_articles_de_cycles_differents_concourent_ensemble():
    """Le cœur du changement : un article de 14 h doit pouvoir battre
    un article de 3 h, au lieu d'être rejeté car arrivé après lui."""
    queue = CandidateQueue()
    queue.add(make_article("Article de 3h", "https://ex.com/nuit", score=14), "k1")
    queue.add(make_article("Article de 14h", "https://ex.com/apresmidi", score=28), "k2")

    meilleur = queue.ranked()[0][1]
    assert meilleur.title == "Article de 14h"


def test_doublon_ne_gonfle_pas_la_file():
    queue = CandidateQueue()
    assert queue.add(make_article(score=10), "k1") is True
    assert queue.add(make_article(score=10), "k1") is False
    assert len(queue) == 1


def test_score_actualise_si_larticle_gagne_en_gravite():
    """Un CVE peut entrer au catalogue KEV entre deux cycles : le candidat
    doit être reclassé avec son nouveau score, pas figé à l'ancien."""
    queue = CandidateQueue()
    queue.add(make_article(score=10), "k1")
    queue.add(make_article(score=35), "k1")  # même URL, score réévalué
    assert queue.ranked()[0][1].score == 35


def test_candidat_perime_quitte_la_file():
    queue = CandidateQueue(ttl_hours=1)
    queue.add(make_article(), "k1")
    queue._items["k1"] = (queue._items["k1"][0], 0.0)  # entrée très ancienne
    assert queue.purge() == 1
    assert len(queue) == 0


def test_publication_retire_de_la_file():
    queue = CandidateQueue()
    queue.add(make_article(url="https://ex.com/1"), "k1")
    queue.add(make_article(url="https://ex.com/2"), "k2")
    queue.remove(["k1"])
    assert len(queue) == 1


# --------------------------------------------------------------------------- #
# Budget quotidien
# --------------------------------------------------------------------------- #
def test_digest_non_du_avant_lheure():
    budget = DailyBudget("Europe/Paris", digest_hour=8)
    assert budget.digest_due(datetime(2026, 8, 23, 7, 30, tzinfo=TZ)) is False


def test_digest_du_a_lheure_prevue():
    budget = DailyBudget("Europe/Paris", digest_hour=8)
    assert budget.digest_due(datetime(2026, 8, 23, 8, 5, tzinfo=TZ)) is True


def test_digest_envoye_une_seule_fois_par_jour():
    budget = DailyBudget("Europe/Paris", digest_hour=8)
    moment = datetime(2026, 8, 23, 8, 5, tzinfo=TZ)
    budget.note_digest(moment)
    assert budget.digest_due(moment) is False
    assert budget.digest_due(datetime(2026, 8, 23, 20, 0, tzinfo=TZ)) is False
    # Le lendemain, il redevient dû.
    assert budget.digest_due(datetime(2026, 8, 24, 8, 1, tzinfo=TZ)) is True


def test_digest_rattrape_apres_une_coupure():
    """VPS éteint à 8 h : le digest doit partir au redémarrage, pas être
    sauté pour la journée."""
    budget = DailyBudget("Europe/Paris", digest_hour=8)
    assert budget.digest_due(datetime(2026, 8, 23, 15, 0, tzinfo=TZ)) is True


def test_redemarrage_ne_republie_pas_le_digest():
    """L'état est relu depuis Discord : un redémarrage à 10 h ne doit pas
    renvoyer le digest déjà publié à 8 h."""
    budget = DailyBudget("Europe/Paris", digest_hour=8)
    envoye_a_8h = datetime(2026, 8, 23, 8, 0, tzinfo=TZ).timestamp()
    budget.note_digest_from_timestamp(envoye_a_8h)
    assert budget.digest_due(datetime(2026, 8, 23, 10, 0, tzinfo=TZ)) is False


def test_quota_urgences_borne_la_journee():
    budget = DailyBudget("Europe/Paris", digest_hour=8)
    assert budget.urgent_slots_left(3) == 3
    budget.note_urgent(2)
    assert budget.urgent_slots_left(3) == 1
    budget.note_urgent(5)
    assert budget.urgent_slots_left(3) == 0  # jamais négatif


# --------------------------------------------------------------------------- #
# Critère d'urgence
# --------------------------------------------------------------------------- #
def test_kev_declenche_une_urgence():
    article = make_article(score=15, cves=["CVE-2026-1"], kev_cves=["CVE-2026-1"])
    urgent, motif = is_urgent(article, make_settings())
    assert urgent and "KEV" in motif


def test_kev_rancongiciel_precise_le_motif():
    article = make_article(
        cves=["CVE-2026-1"], kev_cves=["CVE-2026-1"], kev_ransomware=True
    )
    urgent, motif = is_urgent(article, make_settings())
    assert urgent and "rançongiciel" in motif


def test_epss_eleve_declenche_une_urgence():
    article = make_article(score=15, cves=["CVE-2026-1"], epss_max=0.85)
    urgent, motif = is_urgent(article, make_settings())
    assert urgent and "EPSS" in motif


def test_epss_modere_ne_declenche_pas():
    article = make_article(score=15, cves=["CVE-2026-1"], epss_max=0.3)
    urgent, _ = is_urgent(article, make_settings())
    assert urgent is False


def test_score_exceptionnel_couvre_les_sujets_sans_cve():
    """Une compromission majeure sans CVE (chaîne d'approvisionnement,
    fuite massive) doit rester capturable."""
    article = make_article(score=32)
    urgent, motif = is_urgent(article, make_settings())
    assert urgent and "score" in motif


def test_article_ordinaire_attend_le_digest():
    article = make_article(score=18, cves=["CVE-2026-1"], epss_max=0.1)
    urgent, _ = is_urgent(article, make_settings())
    assert urgent is False


# --------------------------------------------------------------------------- #
# Invariant central : le quota est un plafond, jamais un objectif
# --------------------------------------------------------------------------- #
def _simuler_digest(scores, settings):
    """
    Reproduit l'arbitrage du digest tel qu'implémenté dans bot.py.

    La sélection est RELATIVE : on prend les N meilleurs du jour, avec un
    plancher qui n'écarte que le hors-sujet, et une garantie anti-silence
    qui repêche les meilleurs disponibles si le plancher ne laisse rien.
    """
    queue = CandidateQueue()
    for index, score in enumerate(scores):
        queue.add(make_article(f"A{index}", f"https://ex.com/{index}", score=score), f"k{index}")
    classes = [a for _, a in queue.ranked()]
    retenus = [a for a in classes if a.score >= settings.digest_floor_score][
        : settings.daily_quota
    ]
    objectif = min(settings.digest_min_articles, settings.daily_quota)
    if len(retenus) < objectif and classes:
        complement = [a for a in classes if a not in retenus]
        retenus += complement[: objectif - len(retenus)]
    return retenus


def test_jamais_plus_que_le_quota():
    settings = make_settings(daily_quota=3)
    assert len(_simuler_digest([30, 28, 25, 22, 20, 18, 15, 14, 13], settings)) == 3


def test_les_meilleurs_sont_choisis():
    settings = make_settings(daily_quota=2)
    retenus = _simuler_digest([14, 31, 13, 27], settings)
    assert [a.score for a in retenus] == [31, 27]


def test_selection_relative_publie_meme_avec_scores_moyens():
    """
    Le coeur du modèle : une journée sans actualité majeure publie quand
    même le meilleur du jour. Un seuil absolu aurait produit du silence.
    """
    settings = make_settings(daily_quota=4)
    retenus = _simuler_digest([11, 10, 9, 8, 7], settings)
    assert [a.score for a in retenus] == [11, 10, 9, 8]


def test_garantie_anti_silence_repeche_sous_le_plancher():
    """Journée très calme : on publie quand même DIGEST_MIN_ARTICLES."""
    settings = make_settings(daily_quota=4, digest_min_articles=2)
    retenus = _simuler_digest([5, 4, 3], settings)
    assert [a.score for a in retenus] == [5, 4]


def test_silence_possible_si_desactive():
    """Avec DIGEST_MIN_ARTICLES=0, le silence reste possible."""
    settings = make_settings(daily_quota=4, digest_min_articles=0)
    assert _simuler_digest([5, 4, 3], settings) == []


def test_file_vide_ne_publie_rien():
    """Seul cas de silence par défaut : rien n'a été collecté."""
    assert _simuler_digest([], make_settings()) == []


def test_quota_prime_sur_la_garantie():
    """DIGEST_MIN_ARTICLES ne peut pas faire dépasser DAILY_QUOTA."""
    settings = make_settings(daily_quota=1, digest_min_articles=3)
    assert len(_simuler_digest([30, 28, 25], settings)) == 1


@pytest.mark.parametrize("quota,plancher,mini,scores,attendu", [
    (4, 7, 2, [40, 35, 30, 25, 20], 4),   # journée chargée : plafonné
    (4, 7, 2, [40], 1),                   # une seule actualité : pas de remplissage
    (4, 7, 2, [11, 10], 2),               # scores moyens : publie quand même
    (4, 7, 2, [5, 4], 2),                 # sous le plancher : repêchage
    (4, 7, 0, [5, 4], 0),                 # repêchage désactivé : silence
    (2, 7, 2, [25, 22, 21], 2),           # quota serré
])
def test_volume_quotidien_borne(quota, plancher, mini, scores, attendu):
    settings = make_settings(
        daily_quota=quota, digest_floor_score=plancher, digest_min_articles=mini
    )
    assert len(_simuler_digest(scores, settings)) == attendu
