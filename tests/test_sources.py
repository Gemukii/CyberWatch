import asyncio

import pytest
from aiohttp import web

import sources

RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>t</title>
<item><title>Fresh</title><link>https://example.com/a</link>
<description>&lt;p&gt;Body&lt;/p&gt;</description></item>
</channel></rss>"""


def feed(url, name="feed"):
    return {"name": name, "url": url, "weight": 5}


def fetch_from(handler, timeout=5):
    """Runs fetch_all_feeds against a local server."""
    async def scenario():
        app = web.Application()
        app.router.add_get("/rss", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            return await sources.fetch_all_feeds(
                [feed(f"http://127.0.0.1:{port}/rss")], 24, "TestAgent/1.0", timeout
            )
        finally:
            await runner.cleanup()

    return asyncio.run(scenario())


def test_feed_is_parsed_and_html_stripped():
    async def handler(request):
        return web.Response(body=RSS, content_type="application/rss+xml")

    articles, results = fetch_from(handler)

    assert results[0].error is None
    assert [a.title for a in articles] == ["Fresh"]
    assert articles[0].summary == "Body"


def test_declared_user_agent_is_sent():
    seen = {}

    async def handler(request):
        seen["agent"] = request.headers.get("User-Agent")
        return web.Response(body=RSS)

    fetch_from(handler)

    assert seen["agent"] == "TestAgent/1.0"


def test_http_error_is_reported_per_feed():
    async def handler(request):
        return web.Response(status=403)

    articles, results = fetch_from(handler)

    assert articles == []
    assert results[0].error == "HTTP 403"


def test_stalled_server_times_out_instead_of_hanging():
    async def handler(request):
        await asyncio.sleep(3)
        return web.Response(body=RSS)

    articles, results = fetch_from(handler, timeout=1)

    assert articles == []
    assert "Timeout" in results[0].error


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "http://localhost:8080/admin",
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://[::1]/",
    ],
)
def test_feed_links_cannot_reach_internal_addresses(url):
    assert not sources.is_public_http_url(url)


def test_ordinary_article_links_are_accepted():
    assert sources.is_public_http_url("https://www.bleepingcomputer.com/news/a/")
