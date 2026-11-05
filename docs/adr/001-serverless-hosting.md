# ADR-001: Run without a VPS

**Status:** Accepted
**Date:** 2026-11-04

## Context

The bot stopped when its VPS went away, so nothing was being collected.

The bot only works for a moment each hour. Only slash commands need a permanent connection to Discord: publishing, reading history and reading reactions all work over REST.

## Decision

GitHub Actions runs `run_once.py` every hour. It rebuilds its state from Discord history, runs one cycle over REST, then exits.

Discord stays the only storage, as it was on the VPS. `bot.py` still works for anyone who has a server and wants the slash commands. Both entry points share `pipeline.py`.

A web interface was built, then dropped: Discord already covers the need.

## Options considered

| | GitHub Actions (chosen) | VPS or free VM | Vercel |
|---|---|---|---|
| Code change | One new entry point | None | Orchestration rewritten |
| Cost | Free on a public repository | Free (Oracle) or a small paid VPS | Free, but too limited |
| Slash commands | Lost | Kept | Rewritten |
| Upkeep | Very low | A server to maintain | Medium |
| Main limit | Scheduled runs can be late | Oracle signup and capacity | Hobby cron runs once a day |

Vercel can't host `bot.py`: a gateway client needs a permanent connection, and a Vercel function stops after 300 seconds at most on Hobby.

## Consequences

- No server to maintain.
- Slash commands are gone in this mode. A manual workflow run replaces `/cyber-now` and `/cyber-digest`.
- The bot shows as offline in Discord.
- GitHub delays and skips scheduled runs under load: the first day got 2 runs out of about 17, so urgent alerts can arrive hours late. An external scheduler calling the workflow API closes that gap, with a token limited to starting workflows. The README has the steps.
- Each run starts from nothing, so state that Discord doesn't hold is lost between runs:
  - Consecutive feed failures aren't counted. A failing feed only shows as a warning in the run's log.
  - An empty digest isn't remembered, so the digest goes out on the first later run that has an article.
- GitHub disables scheduled workflows after 60 days without repository activity, and this setup commits nothing on its own. An automated keepalive was rejected: nothing confirms that re-enabling a workflow resets the count, and the best-known keepalive action was disabled by GitHub for a terms of service violation. A digest that stops arriving is the signal, and the workflow can be re-enabled from the Actions tab.

## Revisit if

- Slash commands become necessary: add a Discord interactions endpoint, or go back to `bot.py` on a server.
- The 60-day limit becomes a nuisance: go back to a server.
