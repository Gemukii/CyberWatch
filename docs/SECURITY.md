# Security

CyberWatch reads text written by strangers, sends it to a language model, and posts the result to Discord. This page covers what an attacker can do through that path, and what stops them.

## Threat model

The attacker controls an article, or a feed. They can write anything in a title, a body or a link. They can't reach the repository, the secrets or the Discord server.

The model has no tools. It can't call anything, read anything or act: it returns text, and that text is checked before it goes anywhere. The worst outcome of a successful prompt injection is therefore a misleading summary, not a compromised system. Most of the design follows from that.

## Controls

| Risk | Control | Where |
| --- | --- | --- |
| Hidden instructions in invisible characters | Unicode normalization, invisible and control characters removed | `sanitize_content()` |
| Article text read as instructions | Text sits between markers built from a random nonce, so an article can't close the block | `_summarize_one()` |
| Injection attempt goes unnoticed | Known patterns are flagged, and the published embed warns the reader | `INJECTION_PATTERNS`, `build_embed()` |
| Feed-controlled values in the trusted part of the prompt | Only the configured feed name and values computed by the bot go there | `USER_PROMPT` |
| Mass mentions | Removed from the text, and every article is sent with `AllowedMentions.none()` | `_neutralize()`, `publisher.py` |
| Phishing links in a summary | Markdown links, bare URLs and Discord invites are removed. Only the article link stays | `_neutralize()` |
| Invented or planted CVE | A CVE is kept only if it appears in the source text | `validate_summary()` |
| A real threat played down | A CVE in CISA KEV forces at least High, whatever the model says | `validate_summary()` |
| Malformed model output | Unexpected types and values are rejected or corrected | `validate_summary()` |
| Feed link pointing at an internal address | Links must be `http(s)` and can't target localhost or a private IP | `is_public_http_url()` |
| Injection through the fallback path | Summaries made without AI go through the same cleaning and flagging | `heuristic_summary()` |
| Third-party install code reading secrets | Secrets are only set on the step that runs the bot | `watch.yml` |
| Secret in a URL or a log | The Gemini key travels in a header, and GitHub masks secrets in logs | `_call_gemini()` |

The tests in `tests/test_summarizer.py` and `tests/test_sources.py` cover these controls.

## Known limits

- **Pattern detection is a warning, not a barrier.** A reworded attempt gets past the patterns. Containment comes from the checks on the output, and an article about prompt injection can trigger a false alarm.
- **A summary can still be wrong.** Nothing checks that a bullet point is true. The severity can also be pushed up, since only KEV sets a lower limit. Each embed links to the source for that reason.
- **Scoring reads article text.** Stuffing a title with keywords raises its score, and can reach the urgent threshold. `URGENT_DAILY_MAX` caps the damage, and feeds are chosen by hand in `feeds.yaml`.
- **The address check doesn't follow redirects or DNS.** A public hostname can still redirect to, or resolve to, a private address. On a GitHub runner there is little to reach. On your own server, restrict outbound traffic.
- **Dependencies and actions aren't pinned.** `requirements.txt` sets minimum versions and workflows use version tags. A compromised release would run in the step that holds the secrets.
