import pytest

from categories import classify_article
from sources import Article


@pytest.mark.parametrize(
    "title, summary, category, tags",
    [
        (
            "New ransomware campaign targets hospitals",
            "Attackers encrypt systems and demand payment.",
            "Ransomware",
            {"Ransomware"},
        ),
        (
            "New phishing campaign steals Microsoft credentials",
            "Attackers use fake login pages to harvest credentials.",
            "Phishing",
            {"Phishing", "Credential Theft"},
        ),
        (
            "Company confirms massive data breach",
            "Millions of customer records were exposed.",
            "Data Breach",
            {"Data Leak"},
        ),
        (
            "Critical vulnerability allows remote code execution",
            "A new CVE affects enterprise systems.",
            "Vulnerability",
            {"CVE", "RCE"},
        ),
        (
            "Critical CVE actively exploited in the wild",
            "Security researchers observed exploitation of the vulnerability.",
            "Vulnerability",
            {"CVE", "Active Exploitation"},
        ),
        (
            "Critical Microsoft vulnerability exploited through VPN",
            "Attackers use a CVE to gain remote access.",
            "Vulnerability",
            {"CVE", "Microsoft", "VPN"},
        ),
        (
            "Cybersecurity researchers publish new report",
            "Researchers discuss recent security trends.",
            "General Security",
            set(),
        ),
    ],
)
def test_article_is_classified(title, summary, category, tags):
    article = Article(title=title, url="https://example.com/a", source="Test", summary=summary)

    found_category, found_tags = classify_article(article)

    assert found_category == category
    assert tags <= set(found_tags)
