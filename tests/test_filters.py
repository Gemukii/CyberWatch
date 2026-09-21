from sources import Article
from filters import score_article, select_articles
from state import State


def make_article(
    title: str,
    summary: str = "",
    url: str = "https://example.com/article",
    fulltext: str = "",
) -> Article:
    return Article(
        title=title,
        url=url,
        source="Test",
        summary=summary,
        fulltext=fulltext,
    )

def make_state() -> State:
    return State()


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

    state = make_state()

    selected = select_articles(
        [article],
        state,
        min_score=0,
        similarity=0.85,
        limit=5,
    )

    assert article not in selected


def test_select_articles_returns_articles():
    article = make_article(
        "Critical security vulnerability discovered",
        "Researchers found a serious vulnerability.",
        fulltext=(
            "Researchers discovered a serious security vulnerability "
            "affecting several systems. The vulnerability could allow "
            "remote attackers to execute arbitrary code and compromise "
            "affected installations. Security teams are advised to "
            "apply the available security updates and review their logs."
        ),
    )

    state = make_state()

    selected = select_articles(
        [article],
        state,
        min_score=0,
        similarity=0.85,
        limit=5,
    )

    assert isinstance(selected, list)
    assert article in selected

def test_duplicate_urls_are_removed():
    article1 = make_article(
        "Critical vulnerability discovered",
        url="https://example.com/same",
    )

    article2 = make_article(
        "Same vulnerability reported again",
        url="https://example.com/same",
    )

    state = make_state()

    selected = select_articles(
        [article1, article2],
        state,
        min_score=0,
        similarity=0.85,
        limit=5,
    )

    assert len(selected) <= 1