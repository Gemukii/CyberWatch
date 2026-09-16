"""
Local cyber-news categorization.

No LLM calls are used here.
Classification is deterministic and based on weighted keywords.

An article receives:
- one primary category
- multiple secondary tags
"""

from __future__ import annotations

import re

from sources import Article


# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------

CATEGORY_RULES: dict[str, dict[str, int]] = {
    "Vulnerability": {
        r"\bcve-\d{4}-\d+\b": 8,
        r"\bvulnerability\b": 5,
        r"\bvulnérabilité\b": 5,
        r"\bzero[- ]day\b": 7,
        r"\b0[- ]day\b": 7,
        r"\bremote code execution\b": 7,
        r"\brce\b": 6,
        r"\bsecurity flaw\b": 4,
        r"\bsecurity update\b": 3,
        r"\bcorrectif\b": 3,
        r"\bpatch\b": 2,
    },

    "Malware": {
        r"\bmalware\b": 6,
        r"\bmaliciel\b": 6,
        r"\btrojan\b": 5,
        r"\bstealer\b": 5,
        r"\bbotnet\b": 5,
        r"\bbackdoor\b": 5,
        r"\bloader\b": 3,
        r"\bspyware\b": 4,
    },

    "Ransomware": {
        r"\bransomware\b": 8,
        r"\brançongiciel\b": 8,
        r"\bransom\b": 4,
        r"\bdouble extortion\b": 5,
        r"\bdata extortion\b": 4,
    },

    "Phishing": {
        r"\bphishing\b": 8,
        r"\bhameçonnage\b": 8,
        r"\bcredential theft\b": 6,
        r"\bcredential stealing\b": 6,
        r"\bcredential harvesting\b": 6,
        r"\bfake login\b": 5,
        r"\bmalicious link\b": 4,
        r"\bsocial engineering\b": 4,
    },

    "Data Breach": {
        r"\bdata breach\b": 8,
        r"\bdata leak\b": 7,
        r"\bdata exposure\b": 6,
        r"\bfuite de données\b": 8,
        r"\bviolation de données\b": 8,
        r"\bbreached\b": 5,
        r"\bexposed database\b": 6,
    },

    "Threat Actor / APT": {
        r"\bapt\d*\b": 6,
        r"\bthreat actor\b": 6,
        r"\bthreat group\b": 5,
        r"\battack group\b": 5,
        r"\bstate[- ]sponsored\b": 5,
        r"\bcyber espionage\b": 5,
        r"\bcyberespionage\b": 5,
    },

    "Cloud": {
        r"\bcloud\b": 3,
        r"\baws\b": 4,
        r"\bazure\b": 4,
        r"\bgcp\b": 4,
        r"\bkubernetes\b": 5,
        r"\bcontainer\b": 3,
        r"\bcontainers\b": 3,
    },

    "Network / Infrastructure": {
        r"\bnetwork\b": 3,
        r"\bfirewall\b": 5,
        r"\bvpn\b": 5,
        r"\brouter\b": 4,
        r"\bswitch\b": 3,
        r"\bdns\b": 3,
        r"\bfortinet\b": 4,
        r"\bcisco\b": 4,
        r"\bpalo alto\b": 4,
        r"\bsonicwall\b": 4,
        r"\bivanti\b": 4,
    },

    "Identity / Authentication": {
        r"\bidentity\b": 3,
        r"\bauthentication\b": 5,
        r"\bauthentication bypass\b": 7,
        r"\bpassword\b": 3,
        r"\bcredential\b": 3,
        r"\boauth\b": 4,
        r"\bsaml\b": 4,
        r"\bactive directory\b": 5,
        r"\bkerberos\b": 5,
        r"\biam\b": 5,
    },

    "AI Security": {
        r"\bartificial intelligence\b": 4,
        r"\bai security\b": 7,
        r"\bllm\b": 5,
        r"\blarge language model\b": 5,
        r"\bprompt injection\b": 7,
        r"\bjailbreak\b": 5,
        r"\bmachine learning\b": 3,
    },

    "Supply Chain": {
        r"\bsupply[- ]chain\b": 8,
        r"\bsoftware supply chain\b": 8,
        r"\bdependency confusion\b": 7,
        r"\bmalicious package\b": 7,
        r"\bcompromised package\b": 6,
        r"\bpackage repository\b": 4,
    },

    "OT / ICS": {
        r"\bindustrial control system\b": 8,
        r"\bics\b": 5,
        r"\bot security\b": 7,
        r"\boperational technology\b": 7,
        r"\bscada\b": 7,
        r"\bplc\b": 5,
        r"\bindustrial\b": 3,
    },

    "General Security": {
        r"\bcybersecurity\b": 2,
        r"\bcyber security\b": 2,
        r"\bcybersécurité\b": 2,
        r"\bsecurity\b": 1,
        r"\bsécurité\b": 1,
    },
}


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------

TAG_RULES: dict[str, str] = {
    "CVE": r"\bcve-\d{4}-\d+\b",
    "RCE": r"\bremote code execution\b|\brce\b",
    "Zero-Day": r"\bzero[- ]day\b|\b0[- ]day\b",
    "Active Exploitation": (
        r"\bactively exploited\b|"
        r"\bexploited in the wild\b|"
        r"\bactive exploitation\b|"
        r"\bexploitation active\b"
    ),
    "Proof of Concept": r"\bpoc\b|\bproof[- ]of[- ]concept\b",
    "Privilege Escalation": (
        r"\bprivilege escalation\b|"
        r"\bélévation de privilèges\b"
    ),
    "Credential Theft": (
    r"\bcredential(?:s)?\b",
    r"\bcredential theft\b",
    r"\bsteal(?:s|ing)?\b.{0,30}\bcredential(?:s)?\b",
    r"\bharvest(?:s|ing)?\b.{0,30}\bcredential(?:s)?\b",
    ),
    "Data Leak": (
    r"\bdata leak\b",
    r"\bdata leak(?:s)?\b",
    r"\bleak(?:s|ed|ing)?\b",
    r"\bexpos(?:e|ed|es|ing)\b.{0,30}\b(?:data|records|information)\b",
    r"\b(?:data|records|information)\b.{0,30}\bexpos(?:ed|ure)\b",
    ),
    "Backdoor": r"\bbackdoor\b|\bporte dérobée\b",
    "Botnet": r"\bbotnet\b",
    "APT": r"\bapt\d*\b|\badvanced persistent threat\b",
    "Phishing": r"\bphishing\b|\bhameçonnage\b",
    "Ransomware": r"\bransomware\b|\brançongiciel\b",
    "Supply Chain": r"\bsupply[- ]chain\b",
    "Prompt Injection": r"\bprompt injection\b",
    "Authentication": r"\bauthentication\b|\bauthentification\b",
    "VPN": r"\bvpn\b",
    "Firewall": r"\bfirewall\b|\bpare[- ]feu\b",
    "Cloud": r"\bcloud\b",
    "Kubernetes": r"\bkubernetes\b",
    "Docker": r"\bdocker\b",
    "Windows": r"\bwindows\b",
    "Linux": r"\blinux\b",
    "Fortinet": r"\bfortinet\b",
    "Cisco": r"\bcisco\b",
    "Microsoft": r"\bmicrosoft\b",
    "Apple": r"\bapple\b",
    "Google": r"\bgoogle\b",
    "VMware": r"\bvmware\b",
    "Citrix": r"\bcitrix\b",
    "Ivanti": r"\bivanti\b",
    "Apache": r"\bapache\b",
    "WordPress": r"\bwordpress\b",
}


_COMPILED_CATEGORIES = {
    category: [
        (re.compile(pattern, re.IGNORECASE), weight)
        for pattern, weight in rules.items()
    ]
    for category, rules in CATEGORY_RULES.items()
}

_COMPILED_TAGS = {
    tag: re.compile(pattern, re.IGNORECASE)
    for tag, pattern in TAG_RULES.items()
}


def _article_text(article: Article) -> str:
    """
    Text used for classification.

    Title is repeated conceptually by giving it a higher weight
    during category scoring.
    """
    return f"{article.title}\n{article.content[:8000]}"


def classify_article(article: Article) -> tuple[str, list[str]]:
    """
    Returns:
        (primary_category, tags)

    Classification is deterministic and requires no LLM.
    """

    title = article.title
    body = article.content[:8000]

    category_scores: dict[str, int] = {}

    for category, rules in _COMPILED_CATEGORIES.items():
        score = 0

        for pattern, weight in rules:
            if pattern.search(title):
                score += weight * 2
            elif pattern.search(body):
                score += weight

        category_scores[category] = score

    # Prefer General Security when absolutely nothing more specific matches.
    primary_category = max(
        category_scores,
        key=category_scores.get,
    )

    if category_scores[primary_category] == 0:
        primary_category = "General Security"

    tags: list[str] = []

    text = _article_text(article)

    for tag, pattern in _COMPILED_TAGS.items():
        if pattern.search(text):
            tags.append(tag)

    # CVE is technically a tag, but avoid duplicates if future logic adds it.
    tags = list(dict.fromkeys(tags))

    return primary_category, tags


def categorize_article(article: Article) -> Article:
    """Mutates and returns the article with its category and tags."""

    category, tags = classify_article(article)

    article.category = category
    article.category_tags = tags

    return article