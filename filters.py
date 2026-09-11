"""
Pre-filtering without AI: promo exclusion, scoring, deduplication.

This is what keeps the LLM cost at zero — only survivors get summarized.
Scoring and mechanics: docs/ARCHITECTURE.md §1.
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
# STABLE signal names: written into the published embed, they're what a
# 👍/👎 vote gets attached to (feedback.py). Renaming a key invalidates
# vote history.
#
# Patterns intentionally match both English and French — feeds include
# English outlets (BleepingComputer, THN...) and French official sources
# (CERT-FR, ANSSI), and both need to score correctly.
KEYWORD_SIGNALS: dict[str, tuple[str, int]] = {
    "actively-exploited":  (r"\bactively exploited\b|\bexploited in the wild\b|\bexploitation active\b", 5),
    "zero-day":            (r"\bzero[- ]day\b|\b0[- ]day\b", 5),
    "ransomware":          (r"\bransomware\b|\brançongiciel\b", 4),
    "supply-chain":        (r"\bsupply[- ]chain\b|\bchaîne d'approvisionnement\b", 4),
    "critical-vuln":       (r"\bcritical vulnerability\b|\bvulnérabilité critique\b", 4),
    "rce":                 (r"\brce\b|\bremote code execution\b|\bexécution de code à distance\b", 4),
    "data-breach":         (r"\bdata breach\b|\bfuite de données\b|\bviolation de données\b", 3),
    "privilege-escalation": (r"\bprivilege escalation\b|\bélévation de privilèges\b", 3),
    "backdoor":            (r"\bbackdoor\b|\bporte dérobée\b", 3),
    "malware":             (r"\bmalware\b|\bmaliciel\b|\btrojan\b|\bstealer\b|\bbotnet\b", 2),
    "threat-actor":        (r"\bapt\d*\b|\bthreat actor\b|\bgroupe d'attaquants\b", 2),
    "phishing":            (r"\bphishing\b|\bhameçonnage\b", 2),
    "patch":               (r"\bpatch(ed|es)?\b|\bcorrectif\b|\bsecurity update\b|\bmise à jour de sécurité\b", 2),
    "exploit-poc":         (r"\bpoc\b|\bproof[- ]of[- ]concept\b|\bexploit\b", 2),
    "official-source":     (r"\bcisa\b|\bkev\b|\banssi\b|\bcert[- ]fr\b", 2),
    "widespread-product":  (r"\b(windows|linux|vmware|fortinet|cisco|citrix|ivanti|sonicwall|palo alto|"
                            r"exchange|sharepoint|apache|openssh|kubernetes|docker|wordpress|chrome|"
                            r"firefox|android|ios|sap|oracle|jenkins|gitlab|atlassian)\b", 2),
}

# Factual signals, not subject to feedback: they describe technical reality
# (a CVE is in KEV or it isn't), not a reading preference.
FACTUAL_SIGNALS = frozenset({"kev", "epss", "cve", "cvss"})

KEYWORD_RE = [
    (name, re.compile(pattern, re.IGNORECASE), weight)
    for name, (pattern, weight) in KEYWORD_SIGNALS.items()
]

CVSS_RE = re.compile(r"\bCVSS[^0-9]{0,12}(\d{1,2}(?:\.\d)?)", re.IGNORECASE)


def is_excluded(article: Article) -> str | None:
    """Returns the exclusion match if the article should be dropped, else None."""
    haystack = f"{article.title} {article.summary}"
    for pattern in EXCLUDE_RE:
        match = pattern.search(haystack)
        if match:
            return match.group(0)
    return None


def score_article(article: Article, feedback=None) -> tuple[int, list[str]]:
    """
    Computes a relevance score and the list of detected signals.

    The title counts double: a keyword in the title is far more significant
    than the same word buried in the article body.

    *Authoritative* signals (KEV, EPSS) carry more weight than keywords,
    which remain a lexical approximation.

    `feedback` (optional) is a LearnedWeights derived from 👍/👎 votes: it
    adjusts lexical signals based on your feedback, never touching factual
    signals — see feedback.py.
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

    # Explicit CVE identifier = concrete technical information.
    if article.cves:
        score += 3
        signals.append("cve")
        reasons.append(f"{len(article.cves)} CVE")

    # KEV: confirmed exploitation, verified by CISA. The strongest signal
    # available — it doesn't depend on how the article is worded.
    if article.kev_cves:
        score += 8
        signals.append("kev")
        reasons.append(f"KEV ({', '.join(article.kev_cves[:2])})")

    # EPSS: 30-day exploitation probability.
    if article.epss_max is not None:
        if article.epss_max >= 0.5:
            score += 5
        elif article.epss_max >= 0.1:
            score += 3
        elif article.epss_max >= 0.01:
            score += 1
        signals.append("epss")
        reasons.append(f"EPSS {article.epss_max:.0%}")

    # CVSS score mentioned in the text.
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

    # An article with no usable content can't be summarized well.
    if len(article.content) < 200:
        score -= 2
        reasons.append("very short content")

    # Detected signals are kept on the article: they get written into the
    # published embed, so a vote can later be attached to them.
    article.signals = signals

    # Learned adjustment. Applied last, and bounded: feedback shapes the
    # ranking, it doesn't drive it.
    if feedback is not None:
        delta, explained = feedback.adjustment(signals, article.source)
        if delta:
            score += delta
            reasons.append(f"feedback {delta:+d} ({explained})")

    return score, reasons


def _is_near_duplicate(title: str, known_titles: list[str], threshold: float) -> bool:
    """Detects the same story picked up by a different source."""
    norm = normalize_title(title)
    if not norm:
        return False
    for other in known_titles:
        matcher = SequenceMatcher(None, norm, other)
        # quick_ratio is cheap: used as a pre-check before the real ratio.
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
    Runs the full filtering pipeline and returns the retained articles,
    sorted by descending score.
    """
    known_titles = state.recent_titles(days=5)
    kept: list[Article] = []
    stats = {"excluded": 0, "already seen": 0, "duplicates": 0, "low score": 0}

    for article in articles:
        reason = is_excluded(article)
        if reason:
            stats["excluded"] += 1
            log.debug("Excluded (%s): %s", reason, article.title)
            continue

        if state.is_known(article.url):
            stats["already seen"] += 1
            continue

        if _is_near_duplicate(article.title, known_titles, similarity):
            stats["duplicates"] += 1
            log.debug("Duplicate: %s", article.title)
            continue

        article.score, article.reasons = score_article(article)
        if article.score < min_score:
            stats["low score"] += 1
            continue

        kept.append(article)
        # Enrich on the fly: also dedupes within the same cycle (two
        # sources publishing the same story at the same time).
        known_titles.append(normalize_title(article.title))

    kept.sort(key=lambda a: a.score, reverse=True)
    log.info(
        "Filtering: %d kept out of %d (%s)",
        len(kept),
        len(articles),
        ", ".join(f"{k}={v}" for k, v in stats.items()),
    )
    return kept[:limit]