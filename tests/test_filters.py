from sources import Article
from filters import score_article, select_articles


def make_article(
    title: str,
    summary: str = "",
    url: str = "https://example.com/article",
) -> Article:
    return Article(
        title=title,
        url=url,
        source="Test",
        summary=summary,
    )


def test_score_article_returns_score_and_reasons():
    article = make_article(
        "Critical vulnerability allows remote code execution",
        "A CVE allows attackers to execute arbitrary code.",
    )

    score, reasons = score_article(article)

    assert isinstance(score, int)
    assert isinstance(reasons, list)
    assert score > 0


def test_excluded_article_is_not_selected():
    article = make_article(
        "Sponsored cybersecurity webinar",
        "Join our commercial webinar.",
    )

    selected = select_articles([article])

    assert article not in selected


def test_select_articles_returns_articles():
    article = make_article(
        "Critical security vulnerability discovered",
        "Researchers found a serious vulnerability.",
    )

    selected = select_articles([article])

    assert isinstance(selected, list)


def test_duplicate_urls_are_removed():
    article1 = make_article(
        "Critical vulnerability discovered",
        url="https://example.com/same",
    )

    article2 = make_article(
        "Same vulnerability reported again",
        url="https://example.com/same",
    )

    selected = select_articles([article1, article2])

    assert len(selected) <= 1