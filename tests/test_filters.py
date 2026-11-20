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


# --- CVSS ---

def test_cvss_version_is_not_read_as_the_score():
    from filters import cvss_score

    assert cvss_score("with a CVSS v3.1 score of 8.1 and high complexity") == 8.1
    assert cvss_score("rated critical with a CVSS 4.0 score of 9.2, while") == 9.2
    assert cvss_score("a maximum CVSS 3.1 severity score of 8.1, according") == 8.1
    assert cvss_score("CVE-2026-1 (CVSS score: 9.8) refers to") == 9.8


def test_highest_cvss_wins_over_a_bare_version():
    from filters import cvss_score

    text = "CVSS 4.0 score of 9.2. Oracle rated it high using CVSS 3.1. Java4Shell affects"
    assert cvss_score(text) == 9.2


def test_critical_cvss_gets_its_bonus():
    plain = make_article("Vendor fixes flaw", "Details. " * 30)
    rated = make_article("Vendor fixes flaw", "Details. " * 30 + "CVSS v3.1 score of 9.8")

    assert score_article(rated)[0] - score_article(plain)[0] == 3


# --- New keywords ---

def test_critical_needs_to_describe_a_flaw():
    flaw = make_article("Critical Java4Shell flaw allows attacks")
    infra = make_article("Attack on critical infrastructure operator")

    score_article(flaw), score_article(infra)

    assert "critical-severity" in flaw.signals
    assert "critical-severity" not in infra.signals


def test_pre_auth_and_government_warning_count():
    item = make_article("CISA urges immediate patching of pre-auth RCE")
    score_article(item)

    assert {"unauthenticated", "patch-urged", "remote-code-execution"} <= set(item.signals)


def test_exploitation_in_attacks_counts_as_exploited():
    item = make_article("Critical Perforce Puppet RCE Exploited in Attacks")
    score_article(item)

    assert "actively-exploited" in item.signals


# --- Corroboration ---

def outlet(source: str, title: str, summary: str = "") -> Article:
    return Article(title=title, url=f"https://{source}.example/a", source=source, summary=summary)


def test_sources_sharing_a_cve_or_a_nickname_corroborate():
    from filters import corroborate

    items = [
        outlet("a", "CVE-2026-114938: critical OpenJDK RCE"),
        outlet("b", "Oracle patch", "Tracked as CVE-2026-114938, the flaw..."),
        outlet("c", "Critical Java4Shell flaw allows RCE"),
        outlet("d", "CISA warns of Java4Shell (CVE-2026-114938)"),
        outlet("a", "Another article from the same outlet on CVE-2026-114938"),
        outlet("e", "Unrelated story"),
    ]
    corroborate(items, items)

    assert items[0].corroboration == 3   # a, b, d: c names no CVE
    assert items[3].corroboration == 4   # a, b, d by CVE, c by nickname
    assert items[5].corroboration == 1


def test_a_cve_does_not_match_a_longer_one():
    from filters import corroborate

    items = [outlet("a", "CVE-2026-1111 fixed"), outlet("b", "CVE-2026-11112 fixed")]
    corroborate(items, items)

    assert items[0].corroboration == 1


def test_a_list_of_cves_corroborates_nothing():
    from filters import corroborate

    roundup = outlet("r", "Patch Tuesday", " ".join(f"CVE-2026-{n}" for n in range(1000, 1010)))
    item = outlet("a", "CVE-2026-1001 exploited")
    corroborate([item], [item, roundup])

    assert item.corroboration == 1


def test_corroboration_is_factual_and_scored():
    item = make_article("Vendor fixes flaw", "Details. " * 30)
    base = score_article(item)[0]
    item.corroboration = 5

    assert score_article(item)[0] - base == 6
    assert "corroborated" not in encode_signals(item.signals)


def test_named_flaws_skip_common_words():
    from filters import named_flaws

    assert named_flaws("Java4Shell and Heartbleed, not PowerShell or a webshell") == {
        "java4shell", "heartbleed"
    }
