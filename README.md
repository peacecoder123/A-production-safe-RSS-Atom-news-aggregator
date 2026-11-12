# Safe RSS News Ingestor

> **Developer:** Radhe Wankhade · [@RadheWankhade01](https://x.com/RadheWankhade01) on X

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow) ![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey) ![Security](https://img.shields.io/badge/SSRF-hardened-red)

A lightweight, **SSRF-hardened RSS/Atom news aggregator** for any topic — tech, finance, AI, security advisories, engineering blogs, world news.

Built because naive RSS scrapers silently break or create server-side request forgery (SSRF) vulnerabilities in production — this one doesn't.

---

## The Problem with Naive RSS Scrapers

```python
# What most RSS scrapers do (DANGEROUS in production):
import feedparser
feed = feedparser.parse(user_supplied_url)   # 💀 fetches blindly
```

**What can go wrong:**

| Risk | Example |
|---|---|
| SSRF attack | RSS `<link>` points to `http://169.254.169.254/latest/meta-data/` (AWS metadata) |
| Private network scan | RSS redirects to `http://192.168.1.1/admin` |
| Memory exhaustion | Malicious feed returns 500 MB response |
| Broken parser | ET/Bloomberg feeds put CDN image URLs in `<enclosure>` → parser crashes |
| Mixed timezones | Feed A uses RFC-2822, Feed B uses ISO-8601 → sort order wrong |
| Duplicate stories | Same article appears in 3 feeds → 3x entries in your DB |

This tool handles all of these.

---

## How It Works

```
RSS/Atom Feed URLs
      │
      ▼
┌───────────────────────────────────────────────────────┐
│  SECURITY LAYER                                       │
│  ✓ Reject non-HTTP(S) schemes (file://, ftp://)       │
│  ✓ Domain allowlist check                             │
│  ✓ DNS resolve → block 127.x, 10.x, 192.168.x,       │
│    172.16-31.x, 169.254.x (cloud metadata)            │
│  ✓ Validate every 3xx redirect hop (same checks)      │
│  ✓ Stream with max_bytes cap (default: 5 MB)          │
└───────────────────────────────────────────────────────┘
      │
      ▼
┌───────────────────────────────────────────────────────┐
│  PARSE & CLEAN                                        │
│  ✓ feedparser (RSS 1.0 / 2.0 / Atom)                 │
│  ✓ BeautifulSoup HTML stripping (<p>, <img>, <br>)    │
│  ✓ html.unescape() entity decoding (&amp; → &)        │
│  ✓ Skip CDN image enclosures (image/jpeg thumbnails)  │
│  ✓ Track real documents (.pdf, .xlsx, .csv) only      │
│  ✓ Normalize all timestamps → UTC ISO-8601            │
└───────────────────────────────────────────────────────┘
      │
      ▼
┌───────────────────────────────────────────────────────┐
│  DEDUPLICATE & SORT                                   │
│  ✓ SHA-256 item ID (source + GUID)                    │
│  ✓ Merge with optional JSON store (--store)           │
│  ✓ Sort newest-first across all feeds                 │
│  ✓ Output: JSON / Markdown digest / plain text        │
└───────────────────────────────────────────────────────┘
```

---

## Installation

```bash
pip install -r requirements.txt
```

**Dependencies:** `feedparser`, `httpx`, `beautifulsoup4` *(that's it)*

---

## Quick Start

### 1. Fetch from a feeds config file

Create a `feeds.json` (see `examples/feeds.json` for a ready-made template):

```json
[
  {
    "name": "Hacker News",
    "url": "https://hnrss.org/frontpage",
    "allowed_domains": ["hnrss.org", "news.ycombinator.com"]
  },
  {
    "name": "Python Blog",
    "url": "https://blog.python.org/feeds/posts/default",
    "allowed_domains": ["blog.python.org"]
  }
]
```

```bash
python scripts/fetch_rss.py --feeds examples/feeds.json --limit 10
```

**Terminal output:**

```
Polled 2 feed(s) | Retrieved: 20 | New: 20 | Errors: 0
- [Hacker News] (2026-11-13T02:10:00+00:00) Ask HN: What tools do you use for RSS aggregation?
- [Hacker News] (2026-11-13T01:45:00+00:00) Show HN: We built a zero-cost X publisher in Python
- [Hacker News] (2026-11-13T01:30:00+00:00) SSRF vulnerabilities in RSS scrapers – a case study
- [Python Blog] (2026-11-12T18:00:00+00:00) Python 3.14 alpha 1 released
...
```

---

### 2. Persist to a JSON store (deduplication across runs)

```bash
python scripts/fetch_rss.py \
  --feeds examples/feeds.json \
  --limit 20 \
  --store ./data/news.json
```

**Run it again — only NEW articles are counted:**

```
Polled 2 feed(s) | Retrieved: 20 | New: 3 | Errors: 0
- [Hacker News] (2026-11-13T03:00:00+00:00) Three new stories since last run...
```

The `./data/news.json` file grows incrementally. Each item gets a stable `sha256` ID, so the same story from two feeds is never double-counted.

---

### 3. Clean Markdown news digest

```bash
python scripts/fetch_rss.py \
  --feeds examples/feeds.json \
  --limit 15 \
  --markdown
```

**Terminal output:**

```markdown
# News Digest (15 items, +8 new)

- **[Hacker News]** [Ask HN: What is the best free RSS reader in 2026?](https://news.ycombinator.com/item?id=...) *(2026-11-13T02:10:00+00:00)*
  > Discussion thread on RSS readers. Top comment recommends self-hosted options...

- **[Hacker News]** [SSRF vulnerabilities in production scrapers](https://news.ycombinator.com/item?id=...) *(2026-11-13T01:45:00+00:00)*
  > A detailed write-up on how naive RSS fetching can be weaponized. Key issue: not validating...

- **[Python Blog]** [Python 3.14 alpha 1 is now available](https://blog.python.org/2026/...) *(2026-11-12T18:00:00+00:00)*
  > The first alpha of Python 3.14 is now available. This release includes new syntax for...
```

---

### 4. JSON output (pipe into databases, APIs, or dashboards)

```bash
python scripts/fetch_rss.py \
  --feeds examples/feeds.json \
  --limit 5 \
  --json
```

**Terminal output:**

```json
{
  "items": [
    {
      "id": "a3f8c12d9e4b7f01",
      "source_name": "Hacker News",
      "title": "Ask HN: What tools do you use for RSS?",
      "summary": "Looking for recommendations on RSS aggregation tools...",
      "url": "https://news.ycombinator.com/item?id=12345",
      "document_url": null,
      "published_utc": "2026-11-13T02:10:00+00:00",
      "tags": []
    }
  ],
  "newly_added": 5,
  "errors": []
}
```

---

### 5. Ad-hoc single feed URL

```bash
python scripts/fetch_rss.py \
  --url https://hnrss.org/frontpage \
  --limit 10
```

---

### 6. Keyword filter

```bash
python scripts/fetch_rss.py \
  --feeds examples/feeds.json \
  --search "Python" \
  --limit 20 \
  --markdown
```

Only stories containing "Python" in the title or summary are shown.

---

### 7. Watch for errors (SSRF blocked)

If a feed tries to redirect to a private IP, you'll see this in `--json` output:

```json
{
  "items": [],
  "newly_added": 0,
  "errors": [
    {
      "source": "malicious-feed",
      "error": "SSRFSecurityError: Host 'internal-server' resolved to forbidden IP '192.168.1.100'"
    }
  ]
}
```

The tool continues processing other feeds — one blocked feed doesn't crash the whole run.

---

## Feeds Config Format

Each entry in `feeds.json` has:

```json
{
  "name": "Display name for this feed",
  "url": "https://example.com/rss.xml",
  "allowed_domains": ["example.com", "cdn.example.com"]
}
```

| Field | Required | Description |
|---|---|---|
| `name` | ✅ | Display name shown in output |
| `url` | ✅ | Full RSS/Atom feed URL (must be HTTPS or HTTP) |
| `allowed_domains` | ✅ | Domains this feed's links are allowed to reference |

> **Why `allowed_domains`?** Even after fetching the feed safely, article links and enclosures inside the feed could point anywhere. The allowlist ensures only content from the feed's own domain (and approved CDNs) is accepted.

---

## Security Details

### SSRF Protection — What's Blocked

```
Blocked schemes:   file://, ftp://, gopher://, dict://
Blocked IPs:       127.0.0.1, ::1 (loopback)
                   10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC1918 private)
                   169.254.0.0/16 (link-local / AWS metadata endpoint)
                   Multicast, reserved, unspecified ranges
Blocked redirects: Every 3xx hop is re-validated (attacker can't redirect to internal IP)
Memory limit:      5 MB per feed response (streaming, not buffered)
```

### Enclosure Filtering

Many finance/news RSS feeds (Economic Times, Reuters, etc.) attach CDN image URLs in `<enclosure>` tags:

```xml
<enclosure url="https://img.etimg.com/thumb/article.jpg" type="image/jpeg"/>
```

Naive parsers treat these as documents and try to validate/fetch them → crash or SSRF risk. This tool skips them silently and only processes **real document enclosures** (`.pdf`, `.xlsx`, `.csv`).

---

## CLI Reference

```
usage: fetch_rss.py [--feeds FILE | --url URL [URL ...]]
                    [--limit LIMIT]
                    [--search KEYWORD]
                    [--store FILE]
                    [--markdown | --json]

Input (pick one):
  --feeds FILE      Path to feeds JSON config array
  --url URL         One or more direct RSS/Atom feed URLs

Options:
  --limit INT       Max items fetched per feed (default: 15)
  --search KEYWORD  Filter output by keyword in title or summary
  --store FILE      Persist & deduplicate items to this JSON file across runs
  --markdown        Render clean Markdown news digest
  --json            Output structured JSON (items + errors)
```

---

## Install as an Agent Skill

```bash
# Workspace skill
git clone https://github.com/RadheWankhade01/safe-rss-news-ingestor.git \
  .agents/skills/safe-rss-news-ingestor

# Global skill (Antigravity / Gemini CLI)
git clone https://github.com/RadheWankhade01/safe-rss-news-ingestor.git \
  ~/.gemini/config/skills/safe-rss-news-ingestor
```

---

## Running Tests

```bash
pytest -v
```

**Expected output:**

```
tests/test_fetch_rss.py::test_validate_url_safe_blocks_loopback PASSED
tests/test_fetch_rss.py::test_validate_url_safe_blocks_private_ip PASSED
tests/test_fetch_rss.py::test_live_hn_fetch PASSED

3 passed in 1.24s
```

---

## Project Structure

```
safe-rss-news-ingestor/
├── SKILL.md                        ← Agent skill definition
├── README.md                       ← This file
├── LICENSE                         ← MIT
├── .gitignore
├── requirements.txt                ← feedparser, httpx, beautifulsoup4, pytest
├── scripts/
│   └── fetch_rss.py                ← Main CLI
├── examples/
│   └── feeds.json                  ← Ready-made feeds config (HN, Python Blog)
└── tests/
    └── test_fetch_rss.py           ← Pytest tests (live + unit)
```

---

## Use Cases

| Who | How they use it |
|---|---|
| **Developers** | Aggregate tech/AI blogs into a local news digest |
| **Finance analysts** | Pull earnings announcements and exchange filings from RSS |
| **Security teams** | Monitor CVE feeds and security advisories |
| **AI pipelines** | Feed clean, structured news into LLMs for summarization or tweet drafting |
| **Self-hosters** | Build a personal news dashboard without paying for news APIs |

---

## License

MIT — free to use, modify, and distribute.

---

> Built by [Radhe Wankhade](https://x.com/RadheWankhade01) as an open-source contribution.
> Star ⭐ the repo if it saved you from an SSRF vulnerability or a broken feed parser!
