from sources import Article
from categories import classify_article


def make_article(title: str, summary: str = "") -> Article:
    return Article(
        title=title,
        url="https://example.com/article",
        source="Test",
        summary=summary,
    )


def test_ransomware_category():
    article = make_article(
        "New ransomware campaign targets hospitals",
        "Attackers encrypt systems and demand payment.",
    )

    category, tags = classify_article(article)

    assert category == "Ransomware"
    assert "Ransomware" in tags


def test_phishing_category():
    article = make_article(
        "New phishing campaign steals Microsoft credentials",
        "Attackers use fake login pages to harvest credentials.",
    )

    category, tags = classify_article(article)

    assert category == "Phishing"
    assert "Phishing" in tags
    assert "Credential Theft" in tags


def test_data_breach_category():
    article = make_article(
        "Company confirms massive data breach",
        "Millions of customer records were exposed.",
    )

    category, tags = classify_article(article)

    assert category == "Data Breach"
    assert "Data Leak" in tags


def test_vulnerability_category():
    article = make_article(
        "Critical vulnerability allows remote code execution",
        "A new CVE affects enterprise systems.",
    )

    category, tags = classify_article(article)

    assert category == "Vulnerability"
    assert "CVE" in tags
    assert "RCE" in tags


def test_active_exploitation():
    article = make_article(
        "Critical CVE actively exploited in the wild",
        "Security researchers observed exploitation of the vulnerability.",
    )

    category, tags = classify_article(article)

    assert category == "Vulnerability"
    assert "CVE" in tags
    assert "Active Exploitation" in tags


def test_multiple_tags():
    article = make_article(
        "Critical Microsoft vulnerability exploited through VPN",
        "Attackers use a CVE to gain remote access.",
    )

    category, tags = classify_article(article)

    assert category == "Vulnerability"
    assert "CVE" in tags
    assert "Microsoft" in tags
    assert "VPN" in tags


def test_general_security_fallback():
    article = make_article(
        "Cybersecurity researchers publish new report",
        "Researchers discuss recent security trends.",
    )

    category, tags = classify_article(article)

    assert category == "General Security"