---
name: safe-rss-news-ingestor
description: >-
  Fetch, clean, deduplicate, and normalize RSS/Atom news feeds with strict SSRF protection,
  HTML stripping, UTC timestamp ordering, and media-enclosure filtering. Use when the user wants
  to aggregate live news, track releases/articles across multiple RSS feeds, or build a clean JSON/Markdown digest.
---

# Safe RSS News Ingestor

Safely poll multiple RSS/Atom feeds with domain allowlisting, DNS/IP SSRF blocking, redirect validation, HTML cleanup, UTC timestamp sorting, and automatic deduplication.

## Workflow Steps

1. **Configure Feeds**
   - Use an existing JSON feed list like [examples/feeds.json](./examples/feeds.json), or pass URLs directly with `--url`.
   - Every feed defines explicit `allowed_domains` (required for redirect safety).

2. **Run Safe Collection**
   ```bash
   python scripts/fetch_rss.py --feeds examples/feeds.json --limit 10 --store news_cache.json
   ```
   - To output a crisp Markdown briefing sorted newest-first:
     ```bash
     python scripts/fetch_rss.py --feeds examples/feeds.json --limit 15 --markdown
     ```
   - Or search cached stories:
     ```bash
     python scripts/fetch_rss.py --feeds examples/feeds.json --search "AI" --json
     ```

3. **Handle Document vs Media Enclosures**
   - Thumbnail image enclosures (e.g. `image/jpeg` on external CDNs) are ignored cleanly so news items still ingest.
   - Document enclosures (`.pdf`, `.csv`, `.xlsx`) are recorded under `document_url` only if their host is in `allowed_domains`.

## Verification
- Confirm `fetch_rss.py` prints clean articles without HTML tags and exits `0`.
- Run `pytest -v` in the repo root to verify SSRF blocking (private IPs, unapproved redirects), HTML stripping, UTC ordering, and JSON store deduplication.
