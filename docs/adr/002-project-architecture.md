# ADR-002: Project architecture

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii (project owner)

## Context

CyberWatch turns a stream of security news into 2 to 4 useful articles a day, with immediate alerts when something can't wait. This record covers the design of the whole project. [ADR-001](001-serverless-hosting.md) covers where it runs.

The design has to work within these constraints:

- **One maintainer:** anything that needs regular care eventually stops running.
- **No budget:** hosting and AI must fit free tiers, and the free AI tier limits requests per minute.
- **Hostile input:** articles and feeds are written by strangers, and the project's subject attracts people who test this kind of system.
- **Trustworthy ranking:** an alert that fires too often gets ignored, and press wording exaggerates.
- **Short-lived runs:** each run starts with nothing in memory.

## Decision

CyberWatch is a stateless pipeline with four rules:

1. **Fixed stages.** Each cycle collects, filters, enriches, selects, summarizes and publishes. `pipeline.py` owns the cycle and doesn't care how it was launched.
2. **Code decides, the model writes.** Ranking and publication use rules and public data: CISA KEV, EPSS, source weights and the watchlist. The model only summarizes articles that are already chosen.
3. **Discord is the only storage.** Published messages are the record of what went out. Each run rebuilds its state from channel history, and votes are read back from reactions.
4. **Fail closed.** If the history can't be read, nothing is published. An article only counts as published once Discord has accepted it.

## Options Considered

### Option A: Stateless pipeline, rule-based ranking (chosen)

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low: one process and no storage to run |
| Cost | Free: only the selected articles use AI |
| Scalability | Low: one channel, one set of rules |
| Team familiarity | High: plain Python and REST calls |

**Pros:** nothing to host or back up, rankings can be explained and tested, and the system still works with no AI at all.

**Cons:** state depends on the format of Discord messages, data can't be queried, and rules need tuning by hand.

### Option B: Service with a database

| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium: schema, migrations and backups |
| Cost | Low to medium: a hosted database or a server |
| Scalability | Medium to high: several channels, teams or outputs |
| Team familiarity | High |

**Pros:** history can be queried, feed health survives between runs, and state no longer depends on Discord.

**Cons:** a second system to keep alive, and a second record that can disagree with what was really published.

### Option C: The model ranks and decides

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low in code, high to test |
| Cost | High: every article becomes an AI call, beyond the free tier |
| Scalability | Limited by AI quotas |
| Team familiarity | Medium |

**Pros:** understands context that keywords miss, and needs fewer hand-written rules.

**Cons:** an article could argue its way into an alert, results vary between runs, and an AI outage stops the watch.

## Trade-off Analysis

**Storage.** Option B solves problems this project doesn't have yet. At a few messages a day, re-reading a 7-day history is cheap, and the channel can't disagree with itself. The price is coupling: footer markers such as `#digest` are now a data format, and changing them breaks state. `tests/test_discord_rest.py` guards that format.

**Ranking.** Option C gives hostile text a say in what gets published. With Option A, a successful prompt injection can at worst distort one summary, because the choice to publish was made before the model saw the article. The price is a cruder ranking: keywords can be stuffed into a title, and `URGENT_DAILY_MAX` is what limits that. See [SECURITY.md](../SECURITY.md).

**Availability.** Publishing nothing is preferred to publishing wrongly. A missed run costs an hour, while a run with empty state would repost a week of articles. When the AI is down, articles wait for the next cycle by default rather than going out with a weaker summary.

## Consequences

- **Easier:** running it, since there is no server or database. Testing it, since the decisions are plain functions. Explaining any ranking, since each embed records its score and signals.
- **Easier:** swapping the AI provider, or removing it with `AI_PROVIDER=none`.
- **Harder:** answering questions about past data, as there is no search or statistics.
- **Harder:** supporting several channels or teams, which would need separate state and rules for each.
- **Harder:** changing the embed format, because state is read back from it.
- **To revisit:** feed failures aren't counted across runs, because Discord doesn't hold them.

## Revisit if

- A second channel, team or output such as Slack or Teams is needed: move to Option B.
- History or statistics become a real need: move to Option B.
- Rule-based ranking keeps missing relevant articles: let the model suggest a ranking, while KEV and the daily limits keep the final say.

## Action Items

1. [ ] Set up the external scheduler, so hourly runs don't depend on GitHub's schedule.
2. [ ] Add the `WATCHLIST` secret.
3. [ ] Confirm a live digest published by the current code.
4. [ ] Pin dependencies and GitHub Actions versions.
5. [ ] Add a real digest screenshot to the README.
