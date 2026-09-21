"""
Configuration: environment variables (.env) and RSS sources (feeds.yaml).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env", override=False)

def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "y", "on", "oui"}


@dataclass
class Settings:
    # --- Discord ---
    discord_token: str = os.getenv("DISCORD_TOKEN", "")
    channel_id: int = _env_int("DISCORD_CHANNEL_ID", 0)
    # If set, slash commands sync instantly on this server. Otherwise sync
    # is global and can take up to 1 hour.
    guild_id: int = _env_int("DISCORD_GUILD_ID", 0)

    # --- Scheduling ---
    # COLLECTION frequency (free). Publishing is arbitrated once a day:
    # see the daily budget below.
    interval_minutes: int = _env_int("INTERVAL_MINUTES", 60)
    max_age_hours: int = _env_int("MAX_AGE_HOURS", 24)
    # Lifetime of a candidate in the queue.
    candidate_ttl_hours: int = _env_int("CANDIDATE_TTL_HOURS", 36)
    # Number of articles pushed through text extraction + enrichment per
    # collection cycle. Free in tokens, but network-costly.
    shortlist_limit: int = _env_int("SHORTLIST_LIMIT", 15)

    # --- Daily publishing budget ---
    # Relative selection: the top N of the day, not a fixed threshold.
    daily_quota: int = _env_int("DAILY_QUOTA", 4)
    # Minimum number of articles published, even on a quiet day. Set to 0
    # to allow fully silent days.
    digest_min_articles: int = _env_int("DIGEST_MIN_ARTICLES", 2)
    # Local hour the digest is sent (0-23).
    digest_hour: int = _env_int("DIGEST_HOUR", 8)
    timezone_name: str = os.getenv("TIMEZONE", "Europe/Paris")
    # Relevance floor, not an excellence bar. To be more selective, lower
    # DAILY_QUOTA rather than raising this number.
    digest_floor_score: int = _env_int("DIGEST_FLOOR_SCORE", 7)

    # --- Feedback loop (👍 / 👎 votes) ---
    # The bot learns from your reactions. Weights are recomputed from
    # Discord history, never stored on disk.
    enable_feedback: bool = _env_bool("ENABLE_FEEDBACK", True)
    # Sliding window: beyond it, votes no longer count. Interests from six
    # months ago shouldn't freeze today's watch.
    feedback_lookback_days: int = _env_int("FEEDBACK_LOOKBACK_DAYS", 30)
    # Votes required on a signal before any adjustment applies.
    feedback_min_votes: int = _env_int("FEEDBACK_MIN_VOTES", 3)
    # Maximum adjustment per signal. Deliberately modest: feedback shapes
    # the ranking, it doesn't drive it.
    feedback_max_adjustment: int = _env_int("FEEDBACK_MAX_ADJUSTMENT", 4)
    # How often history is re-read (costly in API calls).
    feedback_ttl_hours: int = _env_int("FEEDBACK_TTL_HOURS", 6)
    feedback_message_limit: int = _env_int("FEEDBACK_MESSAGE_LIMIT", 500)

    # --- Urgent alerts (published immediately, outside the quota) ---
    enable_urgent: bool = _env_bool("ENABLE_URGENT", True)
    # EPSS score above which an article becomes urgent (0-1).
    urgent_epss_threshold: float = _env_float("URGENT_EPSS_THRESHOLD", 0.7)
    # Safety net for CVE-less stories (major compromise, etc.).
    urgent_score_threshold: int = _env_int("URGENT_SCORE_THRESHOLD", 30)
    # Anti-flood guard: even a catastrophic day stays bounded.
    urgent_daily_max: int = _env_int("URGENT_DAILY_MAX", 2)
    # Mention sent with an urgent alert: "none", "here", or a role ID.
    urgent_mention: str = os.getenv("URGENT_MENTION", "none").strip()

    # --- Filtering ---
    min_score: int = _env_int("MIN_SCORE", 5)
    dedup_similarity: float = _env_float("DEDUP_SIMILARITY", 0.72)

    # --- Enrichment (free public sources, no key required) ---
    # CISA KEV: official catalog of exploited vulnerabilities.
    enable_kev: bool = _env_bool("ENABLE_KEV", True)
    kev_url: str = os.getenv(
        "KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )

    # EPSS: 30-day exploitation probability (FIRST.org).
    enable_epss: bool = _env_bool("ENABLE_EPSS", True)
    epss_url: str = os.getenv("EPSS_URL", "https://api.first.org/data/v1/epss")

    # NVD: CVE descriptions, CVSS scores and references.
    nvd_url: str = os.getenv(
        "NVD_URL",
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
    )
    nvd_api_key: str = os.getenv("NVD_API_KEY", "").strip()

    enrichment_ttl_hours: int = _env_int("ENRICHMENT_TTL_HOURS", 12)

    # --- AI summarization ---
    ai_provider: str = os.getenv("AI_PROVIDER", "gemini").strip().lower()
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    gemini_disable_thinking: bool = _env_bool("GEMINI_DISABLE_THINKING", True)
    # Headroom for the JSON payload itself (title + up to 4 points + CVEs
    # + tags). Only matters once thinking no longer eats the budget.
    gemini_max_output_tokens: int = _env_int("GEMINI_MAX_OUTPUT_TOKENS", 1536)
    ollama_url: str = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:3b-instruct")
    ai_delay_seconds: float = _env_float("AI_DELAY_SECONDS", 7)
    # Backoff: number of retries and initial wait on a 429 error.
    ai_max_retries: int = _env_int("AI_MAX_RETRIES", 2)
    ai_backoff_seconds: float = _env_float("AI_BACKOFF_SECONDS", 30)
    # If the quota is exhausted: True = publish a degraded heuristic
    # summary, False (default) = defer the article to the next cycle.
    degrade_on_quota: bool = _env_bool("DEGRADE_ON_QUOTA", False)

    # --- Text retrieval ---
    fetch_fulltext: bool = _env_bool("FETCH_FULLTEXT", True)
    fulltext_max_chars: int = _env_int("FULLTEXT_MAX_CHARS", 4000)
    http_timeout: int = _env_int("HTTP_TIMEOUT", 20)
    user_agent: str = os.getenv(
        "USER_AGENT", "CyberWatchBot/2.0 (+personal cyber watch)"
    )

    # --- State (no disk writes) ---
    # Anti-duplicate window, in days. The index is rebuilt on startup by
    # re-reading the Discord channel's history.
    retention_days: int = _env_int("RETENTION_DAYS", 7)
    # Safety cap on the number of messages re-read. 0 = no cap, only
    # RETENTION_DAYS bounds the read (recommended).
    history_limit: int = _env_int("HISTORY_LIMIT", 0)
    # Alert if a feed returns nothing for N consecutive cycles.
    feed_failure_threshold: int = _env_int("FEED_FAILURE_THRESHOLD", 3)

    # --- KEV retrospective check ---
    # A CVE can take days or weeks to reach the KEV catalog after its
    # article was already published as a routine Medium/High. This
    # re-checks previously published CVEs on every cycle and escalates
    # the ones that later get listed — see docs/ARCHITECTURE.md §1.
    enable_kev_retro_check: bool = _env_bool("ENABLE_KEV_RETRO_CHECK", True)
    # Longer than RETENTION_DAYS on purpose: KEV listings lag disclosure.
    kev_retro_days: int = _env_int("KEV_RETRO_DAYS", 14)
    # Anti-flood guard, same rationale as URGENT_DAILY_MAX: a bulk KEV
    # catalog update shouldn't dump a wall of escalations at once.
    kev_retro_max_per_day: int = _env_int("KEV_RETRO_MAX_PER_DAY", 3)

    feeds_path: Path = BASE_DIR / os.getenv("FEEDS_FILE", "feeds.yaml")
    feeds: list[dict] = field(default_factory=list)

    def validate(self) -> list[str]:
        """Returns the list of blocking problems (empty if all is well)."""
        problems = []
        if not self.discord_token:
            problems.append("DISCORD_TOKEN is empty.")
        if not self.channel_id:
            problems.append("DISCORD_CHANNEL_ID is empty or invalid.")
        if self.ai_provider not in {"gemini", "ollama", "none"}:
            problems.append(f"Unknown AI_PROVIDER: {self.ai_provider!r}")
        if self.ai_provider == "gemini" and not self.gemini_api_key:
            problems.append(
                "AI_PROVIDER=gemini but GEMINI_API_KEY is empty "
                "(use AI_PROVIDER=none to test without AI)."
            )
        if not self.feeds:
            problems.append("No active RSS feed in feeds.yaml.")
        if not 0 < self.dedup_similarity <= 1:
            problems.append("DEDUP_SIMILARITY must be in ]0, 1].")
        if not 0 <= self.digest_hour <= 23:
            problems.append("DIGEST_HOUR must be between 0 and 23.")
        if self.daily_quota < 1:
            problems.append("DAILY_QUOTA must be at least 1.")
        if not 0 < self.urgent_epss_threshold <= 1:
            problems.append("URGENT_EPSS_THRESHOLD must be in ]0, 1].")
        return problems

    def warnings(self) -> list[str]:
        """Non-blocking issues, reported at startup."""
        warns = []
        # Max daily message volume: digest (quota + header) + urgent alerts.
        est_messages = (
            self.daily_quota + 1 + self.urgent_daily_max
        ) * self.retention_days
        if 0 < self.history_limit < est_messages:
            warns.append(
                f"HISTORY_LIMIT={self.history_limit} is below the estimated volume "
                f"({est_messages:.0f} messages over {self.retention_days}d): "
                "the anti-duplicate index could be incomplete. Use 0 (unlimited)."
            )
        if self.enable_kev_retro_check and self.kev_retro_days < self.retention_days:
            warns.append(
                f"KEV_RETRO_DAYS ({self.kev_retro_days}) is shorter than "
                f"RETENTION_DAYS ({self.retention_days}): CVEs would be forgotten "
                "before the retrospective check gets a chance to catch a late "
                "KEV listing. Set it at least as high as RETENTION_DAYS."
            )
        if self.feedback_max_adjustment > self.min_score:
            warns.append(
                f"FEEDBACK_MAX_ADJUSTMENT ({self.feedback_max_adjustment}) is high "
                f"relative to MIN_SCORE ({self.min_score}): feedback could dominate "
                "the factual scoring."
            )
        if self.digest_min_articles > self.daily_quota:
            warns.append(
                f"DIGEST_MIN_ARTICLES ({self.digest_min_articles}) exceeds "
                f"DAILY_QUOTA ({self.daily_quota}): the cap will win."
            )
        if self.urgent_score_threshold <= self.digest_floor_score:
            warns.append(
                "URGENT_SCORE_THRESHOLD is at or below DIGEST_FLOOR_SCORE: nearly "
                "everything would become urgent, defeating the point of the alert."
            )
        return warns


def load_feeds(path: Path) -> list[dict]:
    """
    Loads feeds.yaml.

        feeds:
          - name: BleepingComputer
            url: https://www.bleepingcomputer.com/feed/
            enabled: true
            weight: 2
    """
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    feeds = []
    for entry in data.get("feeds", []):
        if not entry.get("enabled", True) or not entry.get("url"):
            continue
        feeds.append(
            {
                "name": entry.get("name") or entry["url"],
                "url": entry["url"],
                "weight": int(entry.get("weight", 0)),
            }
        )
    return feeds


settings = Settings()
settings.feeds = load_feeds(settings.feeds_path)