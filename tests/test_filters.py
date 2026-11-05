from feedback import encode_signals
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

def test_watchlist_match_in_title_outscores_one_in_body():
    plain = make_article("Vendor patches flaw", summary="Nothing relevant here")
    in_body = make_article("Vendor patches flaw", summary="Affects Fortinet devices")
    in_title = make_article("Fortinet patches flaw", summary="Nothing relevant here")

    scores = [
        score_article(item, watchlist=["fortinet"], watchlist_weight=4)[0]
        for item in (plain, in_body, in_title)
    ]

    assert scores[1] == scores[0] + 4
    assert scores[2] == scores[0] + 8
    assert in_title.watch_matches == ["fortinet"]


def test_watchlist_matches_whole_terms_only():
    item = make_article("New attack scenarios described")

    score_article(item, watchlist=["ios"])

    assert item.watch_matches == []


def test_several_watchlist_matches_count_once():
    one = make_article("Fortinet patches flaw")
    two = make_article("Fortinet and Cisco patch flaws")

    first = score_article(one, watchlist=["fortinet"])[0]
    second = score_article(two, watchlist=["fortinet", "cisco"])[0]

    assert first == second
    assert two.watch_matches == ["fortinet", "cisco"]


def test_watchlist_is_not_learned_from_votes():
    item = make_article("Fortinet patches flaw")

    score_article(item, watchlist=["fortinet"])

    assert "watchlist" not in encode_signals(item.signals)
