"""Tests du pipeline de filtrage : exclusion, scoring, déduplication."""

import pytest

import filters
from sources import Article
from state import State, canonical_url, normalize_title


def article(**kwargs) -> Article:
    base = {"title": "Titre", "url": "https://example.test/a", "source": "Test"}
    base.update(kwargs)
    return Article(**base)


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "left,right",
    [
        ("https://ex.test/a/?utm_source=x&id=3", "https://EX.test/a?id=3#comments"),
        ("https://ex.test/b/", "https://ex.test/b"),
        ("https://ex.test/c?fbclid=abc", "https://ex.test/c"),
    ],
)
def test_urls_equivalentes(left, right):
    assert canonical_url(left) == canonical_url(right)


def test_urls_distinctes_restent_distinctes():
    assert canonical_url("https://ex.test/a?id=1") != canonical_url("https://ex.test/a?id=2")


def test_normalisation_titre_ignore_ponctuation_et_emoji():
    assert normalize_title("🔴 Faille  CRITIQUE, Fortinet !") == "faille critique fortinet"


# --------------------------------------------------------------------------- #
# Exclusions
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "titre",
    [
        "Get this VPN deal for Black Friday",
        "Sponsored: why you need our EDR",
        "Free webinar on zero trust",
        "Top 10 tools for pentesting",
    ],
)
def test_contenu_promo_exclu(titre):
    assert filters.is_excluded(article(title=titre)) is not None


@pytest.mark.parametrize(
    "titre",
    [
        "Fortinet warns of actively exploited RCE flaw",
        "New ransomware group targets hospitals",
        "CERT-FR : vulnérabilité critique dans Ivanti",
    ],
)
def test_article_legitime_conserve(titre):
    assert filters.is_excluded(article(title=titre)) is None


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def test_article_critique_score_plus_haut_que_generique():
    critique = article(
        title="Critical Fortinet zero-day actively exploited in the wild",
        source_weight=3,
        summary="CVE-2026-1234 allows remote code execution. CVSS: 9.8.",
        cves=["CVE-2026-1234"],
    )
    generique = article(
        title="Why security awareness matters in business",
        summary="Companies should train employees regularly about safety culture.",
    )
    assert filters.score_article(critique)[0] > filters.score_article(generique)[0] + 15


def test_kev_augmente_fortement_le_score():
    sans = article(title="Vulnerability in Acme Router", summary="A flaw was found." * 20,
                   cves=["CVE-2026-1111"])
    avec = article(title="Vulnerability in Acme Router", summary="A flaw was found." * 20,
                   cves=["CVE-2026-1111"], kev_cves=["CVE-2026-1111"])
    assert filters.score_article(avec)[0] >= filters.score_article(sans)[0] + 8


def test_epss_eleve_augmente_le_score():
    faible = article(title="Flaw in Acme", summary="details " * 40, cves=["CVE-2026-2222"],
                     epss_max=0.001)
    fort = article(title="Flaw in Acme", summary="details " * 40, cves=["CVE-2026-2222"],
                   epss_max=0.85)
    assert filters.score_article(fort)[0] > filters.score_article(faible)[0]


def test_mot_cle_dans_le_titre_compte_double():
    titre = article(title="Ransomware attack on hospital", summary="x " * 60)
    corps = article(title="Weekly roundup", summary="A ransomware attack occurred. " + "x " * 60)
    assert filters.score_article(titre)[0] > filters.score_article(corps)[0]


def test_cvss_aberrant_ignore():
    """Un « CVSS 99 » ne doit pas gonfler le score : la valeur est bornée."""
    a = article(title="Flaw", summary="Rated CVSS: 99 by the vendor. " + "x " * 60)
    score, reasons = filters.score_article(a)
    assert not any("CVSS" in r for r in reasons)


# --------------------------------------------------------------------------- #
# Déduplication
# --------------------------------------------------------------------------- #
def test_meme_news_deux_sources_publiee_une_fois():
    state = State(retention_days=7)
    a = article(
        title="Critical Fortinet zero-day actively exploited",
        url="https://cert.test/1", source="CERT-FR", source_weight=3,
        summary="CVE-2026-1234 remote code execution. CVSS: 9.8.", cves=["CVE-2026-1234"],
    )
    b = article(
        title="Critical Fortinet zero-day actively exploited!",
        url="https://thn.test/9", source="THN", source_weight=1,
        summary=a.summary, cves=["CVE-2026-1234"],
    )
    kept = filters.select_articles([a, b], state, min_score=5, similarity=0.72, limit=10)
    assert len(kept) == 1


def test_article_deja_publie_ignore():
    state = State(retention_days=7)
    a = article(
        title="Critical Fortinet zero-day actively exploited",
        url="https://cert.test/1?utm_source=rss", source_weight=3,
        summary="CVE-2026-1234 remote code execution. CVSS: 9.8.", cves=["CVE-2026-1234"],
    )
    state.mark_published(a.url, a.title)
    assert state.is_known("https://cert.test/1")          # même URL sans tracking
    assert filters.select_articles([a], state, 5, 0.72, 10) == []


def test_tri_par_score_decroissant():
    state = State(retention_days=7)
    fort = article(title="Zero-day actively exploited in Fortinet", url="https://t.test/1",
                   source_weight=3, summary="CVE-2026-1234 RCE. CVSS: 9.8.",
                   cves=["CVE-2026-1234"], kev_cves=["CVE-2026-1234"])
    moyen = article(title="Phishing campaign targets banks", url="https://t.test/2",
                    summary="A phishing campaign was observed. " + "x " * 60)
    kept = filters.select_articles([moyen, fort], state, 5, 0.72, 10)
    assert kept[0].url == fort.url


def test_purge_au_dela_de_la_retention():
    import time
    state = State(retention_days=1)
    state.mark_published("https://old.test/1", "Vieux titre")
    # Simule une publication d'il y a trois jours
    for key in list(state._seen):
        state._seen[key] = time.time() - 3 * 86400
    state._titles = type(state._titles)([(t, time.time() - 3 * 86400) for t, _ in state._titles])
    assert state.recent_titles() == []
    assert not state.is_known("https://old.test/1")
