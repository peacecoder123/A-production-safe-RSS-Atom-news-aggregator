# Safe RSS News Ingestor

A lightweight, **SSRF-hardened RSS/Atom news aggregator** for any topic (tech, AI, security advisories, engineering blogs, finance, world news).

Built because naive RSS scrapers silently break or create vulnerabilities in production:
- **Blocks SSRF:** Rejects non-HTTP(S) URLs, resolves DNS before connecting to block loopback/private/cloud-metadata IPs (`127.0.0.1`, `169.254.169.254`, RFC1918), and verifies every `3xx` redirect hop against `allowed_domains`.
- **Handles Real-World Feed Quirks:** Skips external CDN image thumbnail `<enclosure>` tags (like `image/jpeg`) that break strict parsers, while tracking real document attachments (`.pdf`, `.xlsx`, `.csv`) on approved hosts.
- **Clean Text & True Chronological Sorting:** Strips HTML tags (`<p>`, `<img>`), decodes entities, normalizes timestamps to UTC ISO-8601, and sorts stories newest-first across all feeds.
- **Zero Database Required:** Deduplicates stories across runs using a portable local JSON store (`--store`) and exports clean JSON or Markdown digests.
- **Agent Skill Ready:** Includes [`SKILL.md`](./SKILL.md) at repo root.

## Installation

```bash
pip install -r requirements.txt
```

*(Uses `feedparser`, `httpx`, and `beautifulsoup4`.)*

## Quick Start

```bash
# Fetch & deduplicate feeds into a local JSON cache
python scripts/fetch_rss.py --feeds examples/feeds.json --limit 10 --store ./data/news.json

# Print a clean Markdown news briefing
python scripts/fetch_rss.py --feeds examples/feeds.json --limit 15 --markdown

# Ad-hoc single feed check with keyword filter
python scripts/fetch_rss.py --url https://blog.python.org/feeds/posts/default --search "Python" --json
```

### Install as an Agent Skill

```bash
git clone https://github.com/<your-username>/safe-rss-news-ingestor.git .agents/skills/safe-rss-news-ingestor
```

## Running Tests

```bash
pytest -v
```

## License

MIT
