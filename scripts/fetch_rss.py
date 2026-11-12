#!/usr/bin/env python3
"""
SSRF-Hardened RSS / Atom News Ingestor & Normalizer.

Features:
- Validates URL schemes (HTTPS/HTTP) and domain allowlists before fetching
- Blocks loopback, private RFC1918, link-local (169.254.x.x), and reserved IPs via DNS resolution
- Validates every HTTP 3xx redirect target manually
- Enforces bounded response size streaming to prevent memory exhaustion
- Skips non-document thumbnail enclosures (e.g., image/jpeg CDN links)
- Strips HTML tags/entities and normalizes timestamps to UTC ISO-8601
- Sorts chronologically across feeds and deduplicates into an optional JSON store
"""

from __future__ import annotations

import argparse
import hashlib
import html
import ipaddress
import json
import os
import re
import socket
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import feedparser
import httpx
from bs4 import BeautifulSoup

DOCUMENT_ENCLOSURE_EXTS = ("pdf", "xlsx", "csv")
DOCUMENT_ENCLOSURE_TYPES = {
    "application/pdf",
    "text/csv",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats",
}


class SSRFSecurityError(ValueError):
    """Raised when a URL fails scheme, domain allowlist, DNS IP, or redirect checks."""


def validate_domain_match(hostname: str, allowed_domains: List[str]) -> bool:
    """Case-insensitive exact or subdomain match against allowlisted domains."""
    host = (hostname or "").lower().rstrip(".")
    if not host or not allowed_domains:
        return False
    for domain in allowed_domains:
        d = (domain or "").lower().lstrip(".").rstrip(".")
        if not d:
            continue
        if host == d or host.endswith(f".{d}"):
            return True
    return False


def _is_forbidden_ip(ip_obj: ipaddress._BaseAddress) -> bool:
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def validate_url_safe(url: str, allowed_domains: Optional[List[str]] = None) -> str:
    """Validate URL syntax, scheme, optional domain allowlist, and resolved IP addresses."""
    parsed = urlparse((url or "").strip())
    scheme = parsed.scheme.lower()
    if scheme not in ("https", "http"):
        raise SSRFSecurityError(f"Unsupported URL scheme '{parsed.scheme}'")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise SSRFSecurityError("URL missing hostname")

    if allowed_domains and not validate_domain_match(hostname, allowed_domains):
        raise SSRFSecurityError(f"Host '{hostname}' is not in allowed_domains {allowed_domains}")

    # Direct IP literal check
    try:
        ip_literal = ipaddress.ip_address(hostname)
    except ValueError:
        ip_literal = None

    if ip_literal is not None:
        if _is_forbidden_ip(ip_literal):
            raise SSRFSecurityError(f"Forbidden IP literal '{hostname}'")
        return url

    # Resolve DNS and block any private/loopback/link-local addresses
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if scheme == "https" else 80))
    except socket.gaierror as exc:
        raise SSRFSecurityError(f"DNS resolution failed for '{hostname}': {exc}") from exc

    for _, _, _, _, sockaddr in addr_info:
        resolved_ip = sockaddr[0].split("%")[0]
        try:
            ip_obj = ipaddress.ip_address(resolved_ip)
        except ValueError:
            continue
        if _is_forbidden_ip(ip_obj):
            raise SSRFSecurityError(f"Host '{hostname}' resolved to forbidden IP '{resolved_ip}'")

    return url


def safe_fetch_bytes(
    url: str,
    allowed_domains: List[str],
    timeout_seconds: float = 15.0,
    max_bytes: int = 5 * 1024 * 1024,
    max_redirects: int = 5,
) -> Tuple[str, bytes]:
    """Fetch URL safely with redirect-hop SSRF validation and bounded memory streaming."""
    current_url = url
    headers = {"User-Agent": "safe-rss-news-ingestor/1.0"}

    with httpx.Client(timeout=timeout_seconds, follow_redirects=False, headers=headers) as client:
        for _ in range(max_redirects + 1):
            validate_url_safe(current_url, allowed_domains=allowed_domains)
            with client.stream("GET", current_url) as resp:
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location")
                    if not location:
                        raise SSRFSecurityError(f"Redirect {resp.status_code} missing Location header")
                    current_url = urljoin(current_url, location)
                    continue

                resp.raise_for_status()
                chunks: List[bytes] = []
                total = 0
                for chunk in resp.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(f"Response exceeds max_bytes limit ({max_bytes})")
                    chunks.append(chunk)
                return str(resp.url), b"".join(chunks)

    raise SSRFSecurityError(f"Exceeded max redirects ({max_redirects})")


def clean_html_text(raw: str) -> str:
    """Strip HTML tags cleanly and unescape HTML entities."""
    if not raw:
        return ""
    text = str(raw)
    if "<" in text and ">" in text:
        text = BeautifulSoup(text, "html.parser").get_text(" ")
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def normalize_utc_iso(raw_date: Optional[str]) -> Optional[str]:
    """Parse RFC-2822 / ISO-8601 dates to normalized UTC ISO-8601 string."""
    if not raw_date or not str(raw_date).strip():
        return None
    s = str(raw_date).strip()

    try:
        dt = parsedate_to_datetime(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        pass

    try:
        iso = s[:-1] + "+00:00" if s.endswith("Z") else s
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return None


def parse_feed_bytes(
    feed_bytes: bytes,
    source_name: str,
    effective_url: str,
    allowed_domains: List[str],
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """Parse RSS/Atom bytes into normalized article dictionaries."""
    parsed = feedparser.parse(feed_bytes.decode("utf-8", errors="ignore"))
    items: List[Dict[str, Any]] = []

    for entry in parsed.entries[:limit]:
        title = clean_html_text(entry.get("title") or "") or "Untitled"
        link = (entry.get("link") or "").strip() or None
        guid = str(entry.get("id") or link or title).strip()
        summary = clean_html_text(entry.get("summary") or entry.get("description") or "")
        published_raw = entry.get("published") or entry.get("updated")
        published_utc = normalize_utc_iso(published_raw)

        # Skip thumbnail images/media; only attach documents on approved domains
        document_url = None
        for enc in entry.get("enclosures", []):
            href = enc.get("href") or enc.get("url")
            if not href:
                continue
            full_enc = urljoin(effective_url, str(href).strip())
            ext = os.path.splitext(full_enc.split("?")[0])[1].lower().lstrip(".")
            enc_type = str(enc.get("type") or "").lower().split(";")[0].strip()
            if ext not in DOCUMENT_ENCLOSURE_EXTS and enc_type not in DOCUMENT_ENCLOSURE_TYPES:
                continue
            enc_host = (urlparse(full_enc).hostname or "").lower()
            if enc_host and validate_domain_match(enc_host, allowed_domains):
                document_url = full_enc
                break

        key_raw = f"{source_name}::{guid}"
        item_id = hashlib.sha256(key_raw.encode("utf-8")).hexdigest()[:16]

        items.append({
            "id": item_id,
            "source_name": source_name,
            "title": title,
            "summary": summary,
            "url": link,
            "document_url": document_url,
            "published_utc": published_utc,
            "tags": [t.get("term") for t in (entry.get("tags") or []) if t.get("term")],
        })

    return items


def merge_and_deduplicate(store_path: Optional[str], new_items: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Merge new items with optional JSON store and return sorted newest-first list + newly added count."""
    existing_by_id: Dict[str, Dict[str, Any]] = {}
    if store_path:
        p = Path(store_path).expanduser()
        if p.exists():
            try:
                loaded = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    for row in loaded:
                        if isinstance(row, dict) and row.get("id"):
                            existing_by_id[row["id"]] = row
            except Exception:
                pass

    added = 0
    for item in new_items:
        if item["id"] not in existing_by_id:
            added += 1
        existing_by_id[item["id"]] = item

    merged = sorted(
        existing_by_id.values(),
        key=lambda x: x.get("published_utc") or "",
        reverse=True,
    )

    if store_path:
        p = Path(store_path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")

    return merged, added


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SSRF-safe RSS/Atom news aggregator and cleaner.")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--feeds", help="Path to feeds JSON array ([{name, url, allowed_domains}]).")
    src.add_argument("--url", action="append", help="One or more direct RSS/Atom feed URLs.")

    parser.add_argument("--limit", type=int, default=15, help="Max items fetched per feed (default: 15).")
    parser.add_argument("--search", help="Filter output items by keyword in title/summary.")
    parser.add_argument("--store", help="Optional JSON file path to persist & deduplicate items across runs.")
    parser.add_argument("--markdown", action="store_true", help="Render clean Markdown news digest.")
    parser.add_argument("--json", action="store_true", help="Output structured JSON.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    feeds_cfg: List[Dict[str, Any]] = []
    if args.feeds:
        feeds_cfg = json.loads(Path(args.feeds).expanduser().read_text(encoding="utf-8"))
    elif args.url:
        for u in args.url:
            host = urlparse(u).hostname or ""
            feeds_cfg.append({"name": host or u, "url": u, "allowed_domains": [host] if host else []})

    collected: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []

    for cfg in feeds_cfg:
        name = cfg.get("name") or cfg["url"]
        url = cfg["url"]
        domains = cfg.get("allowed_domains") or [urlparse(url).hostname or ""]
        try:
            eff_url, raw_bytes = safe_fetch_bytes(url, allowed_domains=domains)
            items = parse_feed_bytes(raw_bytes, source_name=name, effective_url=eff_url, allowed_domains=domains, limit=args.limit)
            collected.extend(items)
        except Exception as exc:
            errors.append({"source": name, "error": f"{type(exc).__name__}: {exc}"})

    merged, added = merge_and_deduplicate(args.store, collected)

    if args.search:
        q = args.search.strip().lower()
        display_items = [
            it for it in merged
            if q in (it.get("title") or "").lower() or q in (it.get("summary") or "").lower()
        ]
    else:
        display_items = merged

    display_items = display_items[: max(args.limit, len(feeds_cfg) * args.limit)]

    if args.json:
        print(json.dumps({"items": display_items, "newly_added": added, "errors": errors}, indent=2, ensure_ascii=False))
    elif args.markdown:
        print(f"# News Digest ({len(display_items)} items, +{added} new)\n")
        for it in display_items[: args.limit]:
            dt = it.get("published_utc") or "Recent"
            print(f"- **[{it['source_name']}]** [{it['title']}]({it.get('url') or '#'}) *({dt})*")
            if it.get("summary"):
                print(f"  > {it['summary'][:220]}")
        if errors:
            print("\n## Errors")
            for err in errors:
                print(f"- `{err['source']}`: {err['error']}")
    else:
        print(f"Polled {len(feeds_cfg)} feed(s) | Retrieved: {len(collected)} | New: {added} | Errors: {len(errors)}")
        for it in display_items[: args.limit]:
            print(f"- [{it['source_name']}] ({it.get('published_utc') or 'N/A'}) {it['title']}")
        for err in errors:
            print(f"[WARN] {err['source']}: {err['error']}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
