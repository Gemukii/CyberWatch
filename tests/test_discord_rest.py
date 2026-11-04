"""
run_once.py against a local stand-in for the Discord REST API.

Exercises the real discord.py client: login, channel lookup, history, send
and reactions, with no gateway. The payloads are hand-written, so this shows
the code path works without one, not that Discord answers exactly like this.
"""

import asyncio
import json
import time
from datetime import datetime, timezone

import discord
import pytest
from aiohttp import web
from discord.http import Route

import run_once
import sources
from sources import Article, FeedResult

from helpers import make_settings

CHANNEL_ID = 123456789012345678
GUILD_ID = 223456789012345678
BOT = {"id": "323456789012345678", "username": "cyberwatch", "discriminator": "0",
       "avatar": None, "bot": True, "global_name": None}


def json_response(data, status=200):
    # discord.py only decodes this exact Content-Type, without a charset.
    return web.Response(
        body=json.dumps(data).encode(), status=status,
        headers={"Content-Type": "application/json"},
    )


class FakeDiscord:
    def __init__(self):
        self.messages: list[dict] = []
        self.reactions: list[str] = []
        self.requests: list[str] = []
        self.auth: set[str] = set()
        self.history_status = 200

    def app(self) -> web.Application:
        app = web.Application(middlewares=[self.track])
        app.router.add_get("/users/@me", self.me)
        app.router.add_get("/oauth2/applications/@me", self.application)
        app.router.add_get(f"/channels/{CHANNEL_ID}", self.channel)
        app.router.add_get(f"/channels/{CHANNEL_ID}/messages", self.history)
        app.router.add_post(f"/channels/{CHANNEL_ID}/messages", self.create)
        app.router.add_put(
            f"/channels/{CHANNEL_ID}/messages/{{mid}}/reactions/{{emoji}}/@me", self.react
        )
        return app

    @web.middleware
    async def track(self, request, handler):
        self.requests.append(f"{request.method} {request.path}")
        self.auth.add(request.headers.get("Authorization", ""))
        return await handler(request)

    async def me(self, request):
        return json_response(BOT)

    async def application(self, request):
        return json_response({
            "id": BOT["id"], "name": "CyberWatch", "icon": None, "description": "",
            "bot_public": False, "bot_require_code_grant": False, "owner": BOT,
            "verify_key": "0" * 64, "team": None, "flags": 0,
        })

    async def channel(self, request):
        return json_response({
            "id": str(CHANNEL_ID), "type": 0, "guild_id": str(GUILD_ID), "name": "veille",
            "position": 0, "permission_overwrites": [], "nsfw": False, "parent_id": None,
        })

    async def history(self, request):
        if self.history_status != 200:
            return json_response(
                {"message": "Missing Access", "code": 50001}, status=self.history_status
            )
        return json_response(list(reversed(self.messages)))

    async def create(self, request):
        body = await request.json()
        now = datetime.now(tz=timezone.utc)
        snowflake = discord.utils.time_snowflake(now) + len(self.messages)
        message = {
            "id": str(snowflake), "channel_id": str(CHANNEL_ID), "author": BOT,
            "content": body.get("content") or "", "timestamp": now.isoformat(),
            "edited_timestamp": None, "tts": False, "mention_everyone": False,
            "mentions": [], "mention_roles": [], "attachments": [],
            "embeds": body.get("embeds") or [], "pinned": False, "type": 0,
        }
        self.messages.append(message)
        return json_response(message)

    async def react(self, request):
        self.reactions.append(request.match_info["emoji"])
        return web.Response(status=204)


@pytest.fixture
def scenario(monkeypatch):
    """Runs `run_once.run` N times against the fake API, returns the fake."""
    item = Article(
        title="Vendor patches flaw in product",
        url="https://example.com/a",
        source="Test",
        source_weight=10,
        summary="A long enough description of the vulnerability. " * 8,
        published_ts=time.time(),
    )

    async def fetch(*args, **kwargs):
        return [item], [FeedResult(name="feed", articles=[item])]

    monkeypatch.setattr(sources, "fetch_all_feeds", fetch)
    monkeypatch.setattr(run_once, "settings", make_settings(
        discord_token="test-token",
        channel_id=CHANNEL_ID,
        digest_hour=0,
        enable_feedback=True,
        feedback_ttl_hours=0,
    ))

    def play(fake: FakeDiscord, runs: int = 1, dry_run: bool = False) -> list[int]:
        async def main():
            runner = web.AppRunner(fake.app())
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            monkeypatch.setattr(Route, "BASE", f"http://127.0.0.1:{port}")
            try:
                return [
                    await run_once.run(dry_run=dry_run, force_digest=False)
                    for _ in range(runs)
                ]
            finally:
                await runner.cleanup()

        return asyncio.run(main())

    return play


def embeds_sent(fake: FakeDiscord) -> list[dict]:
    return [embed for m in fake.messages for embed in m["embeds"]]


def test_digest_is_published_over_rest_with_reactions(scenario):
    fake = FakeDiscord()

    assert scenario(fake) == [0]

    assert any(e.get("url") == "https://example.com/a" for e in embeds_sent(fake))
    assert len(fake.reactions) == 2
    assert fake.auth == {"Bot test-token"}


def test_gateway_is_never_requested(scenario):
    fake = FakeDiscord()

    scenario(fake)

    assert not [r for r in fake.requests if "gateway" in r]


def test_second_run_rebuilds_state_and_repeats_nothing(scenario):
    fake = FakeDiscord()

    assert scenario(fake, runs=2) == [0, 0]

    urls = [e["url"] for e in embeds_sent(fake) if e.get("url")]
    assert urls == ["https://example.com/a"]
    headers = [e for e in embeds_sent(fake) if "#digest" in e.get("footer", {}).get("text", "")]
    assert len(headers) == 1


def test_missing_history_permission_fails_and_publishes_nothing(scenario):
    fake = FakeDiscord()
    fake.history_status = 403

    assert scenario(fake) == [1]

    assert fake.messages == []


def test_dry_run_reads_history_but_posts_nothing(scenario):
    fake = FakeDiscord()

    assert scenario(fake, dry_run=True) == [0]

    assert any(r.startswith("GET") and r.endswith("/messages") for r in fake.requests)
    assert not [r for r in fake.requests if r.startswith(("POST", "PUT"))]
