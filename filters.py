"""
Pré-filtrage sans IA : exclusion des contenus promo, scoring, déduplication.

C'est ce qui garde le coût LLM à zéro — seuls les survivants seront résumés.
Barème et mécanismes : docs/ARCHITECTURE.md §1.
"""

from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher

from sources import Article
from state import State, normalize_title

log = logging.getLogger(__name__)

# --- 1. Exclusions ---
EXCLUDE_PATTERNS = [
    r"\bsponsor(ed|isé|ised)?\b",
    r"\bpartner content\b",
    r"\badvertorial\b",
    r"\bpromo(tion)?\b",
    r"\b(deal|deals|discount|coupon|sale)\b",
    r"\bblack friday\b|\bcyber monday\b",
    r"\bgiveaway\b|\bconcours\b",
    r"\bwebinar\b|\bwebinaire\b",
    r"\b(e-?book|whitepaper|livre blanc)\b",
    r"\bcertification bundle\b|\btraining bundle\b",
    r"\bbest \w+ (of|for) 20\d\d\b",
    r"\bhow to choose\b|\btop \d+ (tools|vendors)\b",
]
EXCLUDE_RE = [re.compile(p, re.IGNORECASE) for p in EXCLUDE_PATTERNS]

# --- 2. Scoring ---
# Noms de signaux STABLES : inscrits dans l'embed publié, ils servent à
# rattacher les votes (feedback.py). Renommer une clé invalide l'historique.
KEYWORD_SIGNALS: dict[str, tuple[str, int]] = {
    "exploitation-active": (r"\bactively exploited\b|\bexploited in the wild\b|\bexploitation active\b", 5),
    "zero-day":            (r"\bzero[- ]day\b|\b0[- ]day\b", 5),
    "ransomware":          (r"\bransomware\b|\brançongiciel\b", 4),
    "supply-chain":        (r"\bsupply[- ]chain\b|\bchaîne d'approvisionnement\b", 4),
    "vuln-critique":       (r"\bcritical vulnerability\b|\bvulnérabilité critique\b", 4),
    "rce":                 (r"\brce\b|\bremote code execution\b|\bexécution de code à distance\b", 4),
    "fuite-donnees":       (r"\bdata breach\b|\bfuite de données\b|\bviolation de données\b", 3),
    "elevation-privileges": (r"\bprivilege escalation\b|\bélévation de privilèges\b", 3),
    "backdoor":            (r"\bbackdoor\b|\bporte dérobée\b", 3),
    "malware":             (r"\bmalware\b|\bmaliciel\b|\btrojan\b|\bstealer\b|\bbotnet\b", 2),
    "threat-actor":        (r"\bapt\d*\b|\bthreat actor\b|\bgroupe d'attaquants\b", 2),
    "phishing":            (r"\bphishing\b|\bhameçonnage\b", 2),
    "correctif":           (r"\bpatch(ed|es)?\b|\bcorrectif\b|\bsecurity update\b|\bmise à jour de sécurité\b", 2),
    "exploit-poc":         (r"\bpoc\b|\bproof[- ]of[- ]concept\b|\bexploit\b", 2),
    "source-officielle":   (r"\bcisa\b|\bkev\b|\banssi\b|\bcert[- ]fr\b", 2),
    "produit-repandu":     (r"\b(windows|linux|vmware|fortinet|cisco|citrix|ivanti|sonicwall|palo alto|"
                            r"exchange|sharepoint|apache|openssh|kubernetes|docker|wordpress|chrome|"
                            r"firefox|android|ios|sap|oracle|jenkins|gitlab|atlassian)\b", 2),
}

# Signaux factuels, non soumis au feedback : ils décrivent la réalité technique
# (une CVE est au KEV ou elle n'y est pas), pas une préférence de lecture.
FACTUAL_SIGNALS = frozenset({"kev", "epss", "cve", "cvss"})

KEYWORD_RE = [
    (name, re.compile(pattern, re.IGNORECASE), weight)
    for name, (pattern, weight) in KEYWORD_SIGNALS.items()
]

CVSS_RE = re.compile(r"\bCVSS[^0-9]{0,12}(\d{1,2}(?:\.\d)?)", re.IGNORECASE)


def is_excluded(article: Article) -> str | None:
    """Retourne le motif d'exclusion si l'article doit être écarté, sinon None."""
    haystack = f"{article.title} {article.summary}"
    for pattern in EXCLUDE_RE:
        match = pattern.search(haystack)
        if match:
            return match.group(0)
    return None


def score_article(article: Article, feedback=None) -> tuple[int, list[str]]:
    """
    Calcule un score de pertinence et la liste des signaux détectés.

    Le titre compte double : un mot-clé dans le titre est bien plus
    significatif que le même mot perdu au milieu du corps de l'article.

    Les signaux *autoritatifs* (KEV, EPSS) pèsent plus lourd que les
    mots-clés, qui restent une approximation lexicale.

    `feedback` (optionnel) est un LearnedWeights issu des votes 👍/👎 :
    il ajuste les signaux lexicaux selon tes retours, sans jamais toucher
    aux signaux factuels — voir feedback.py.
    """
    title = article.title
    body = article.content[:6000]
    score = article.source_weight
    reasons: list[str] = []
    signals: list[str] = []

    for name, pattern, weight in KEYWORD_RE:
        in_title = bool(pattern.search(title))
        in_body = bool(pattern.search(body))
        if in_title:
            score += weight * 2
        elif in_body:
            score += weight
        if in_title or in_body:
            signals.append(name)
            reasons.append(name)

    # Identifiant CVE explicite = information technique concrète.
    if article.cves:
        score += 3
        signals.append("cve")
        reasons.append(f"{len(article.cves)} CVE")

    # KEV : exploitation avérée, confirmée par la CISA. Le signal le plus fort
    # dont on dispose — il ne dépend pas de la formulation de l'article.
    if article.kev_cves:
        score += 8
        signals.append("kev")
        reasons.append(f"KEV ({', '.join(article.kev_cves[:2])})")

    # EPSS : probabilité d'exploitation à 30 jours.
    if article.epss_max is not None:
        if article.epss_max >= 0.5:
            score += 5
        elif article.epss_max >= 0.1:
            score += 3
        elif article.epss_max >= 0.01:
            score += 1
        signals.append("epss")
        reasons.append(f"EPSS {article.epss_max:.0%}")

    # Score CVSS mentionné dans le texte.
    cvss = CVSS_RE.search(body)
    if cvss:
        try:
            value = float(cvss.group(1))
            if 0 <= value <= 10:
                if value >= 9.0:
                    score += 3
                elif value >= 7.0:
                    score += 2
                signals.append("cvss")
                reasons.append(f"CVSS {value}")
        except ValueError:
            pass

    # Un article sans contenu exploitable ne pourra pas être bien résumé.
    if len(article.content) < 200:
        score -= 2
        reasons.append("contenu très court")

    # Les signaux détectés sont conservés sur l'article : ils seront inscrits
    # dans l'embed publié, pour que le vote puisse ensuite leur être rattaché.
    article.signals = signals

    # Ajustement appris. Appliqué en dernier, et borné : le feedback module
    # le classement, il ne le pilote pas.
    if feedback is not None:
        delta, explained = feedback.adjustment(signals, article.source)
        if delta:
            score += delta
            reasons.append(f"feedback {delta:+d} ({explained})")

    return score, reasons


def _is_near_duplicate(title: str, known_titles: list[str], threshold: float) -> bool:
    """Détecte la même news reprise par une autre source."""
    norm = normalize_title(title)
    if not norm:
        return False
    for other in known_titles:
        matcher = SequenceMatcher(None, norm, other)
        # quick_ratio est peu coûteux : on s'en sert comme pré-test.
        if matcher.quick_ratio() < threshold:
            continue
        if matcher.ratio() >= threshold:
            return True
    return False


def select_articles(
    articles: list[Article],
    state: State,
    min_score: int,
    similarity: float,
    limit: int,
) -> list[Article]:
    """
    Applique tout le pipeline de filtrage et retourne les articles retenus,
    triés par score décroissant.
    """
    known_titles = state.recent_titles(days=5)
    kept: list[Article] = []
    stats = {"exclus": 0, "déjà vus": 0, "doublons": 0, "score faible": 0}

    for article in articles:
        motif = is_excluded(article)
        if motif:
            stats["exclus"] += 1
            log.debug("Exclu (%s) : %s", motif, article.title)
            continue

        if state.is_known(article.url):
            stats["déjà vus"] += 1
            continue

        if _is_near_duplicate(article.title, known_titles, similarity):
            stats["doublons"] += 1
            log.debug("Doublon : %s", article.title)
            continue

        article.score, article.reasons = score_article(article)
        if article.score < min_score:
            stats["score faible"] += 1
            continue

        kept.append(article)
        # Enrichissement au fil de l'eau : dédup aussi à l'intérieur du cycle
        # (deux sources publiant la même news en même temps).
        known_titles.append(normalize_title(article.title))

    kept.sort(key=lambda a: a.score, reverse=True)
    log.info(
        "Filtrage : %d retenus sur %d (%s)",
        len(kept),
        len(articles),
        ", ".join(f"{k}={v}" for k, v in stats.items()),
    )
    return kept[:limit]
