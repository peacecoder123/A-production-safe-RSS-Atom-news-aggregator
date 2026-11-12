from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import fetch_rss as fr  # noqa: E402


def test_ssrf_blocks_loopback_metadata_and_unapproved_host():
    with pytest.raises(fr.SSRFSecurityError):
        fr.validate_url_safe("http://127.0.0.1/admin", allowed_domains=["127.0.0.1"])
    with pytest.raises(fr.SSRFSecurityError):
        fr.validate_url_safe("http://169.254.169.254/latest/meta-data/", allowed_domains=["169.254.169.254"])
    with pytest.raises(fr.SSRFSecurityError):
        fr.validate_url_safe("file:///etc/passwd", allowed_domains=["example.com"])
    with pytest.raises(fr.SSRFSecurityError):
        fr.validate_url_safe("https://evil.example.org/rss", allowed_domains=["trusted.com"])


def test_parse_feed_strips_html_ignores_image_enclosures_and_normalizes_utc():
    sample_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <title>Test News</title>
        <item>
          <title>Alpha &amp; Beta launch update</title>
          <link>https://news.example.com/story-1</link>
          <guid>story-1</guid>
          <pubDate>Fri, 13 Nov 2026 09:00:00 +0530</pubDate>
          <description>&lt;p&gt;Major &lt;b&gt;release&lt;/b&gt; details here.&lt;/p&gt;</description>
          <enclosure url="https://cdn-images.other.com/thumb.jpg" type="image/jpeg" length="0" />
        </item>
        <item>
          <title>Quarterly PDF Report</title>
          <link>https://news.example.com/story-2</link>
          <guid>story-2</guid>
          <pubDate>Fri, 13 Nov 2026 04:00:00 GMT</pubDate>
          <description>Download the PDF below.</description>
          <enclosure url="https://news.example.com/files/q2.pdf" type="application/pdf" length="1234" />
        </item>
      </channel>
    </rss>"""

    items = fr.parse_feed_bytes(
        sample_xml,
        source_name="Example News",
        effective_url="https://news.example.com/rss",
        allowed_domains=["news.example.com"],
        limit=10,
    )
    assert len(items) == 2
    assert items[0]["title"] == "Alpha & Beta launch update"
    assert items[0]["summary"] == "Major release details here."
    assert items[0]["document_url"] is None
    assert items[0]["published_utc"] == "2026-11-13T03:30:00+00:00"
    assert items[1]["document_url"] == "https://news.example.com/files/q2.pdf"


def test_deduplication_store_persists_and_sorts_newest_first(tmp_path):
    store = tmp_path / "news.json"
    batch1 = [
        {"id": "1", "source_name": "S1", "title": "Older", "published_utc": "2026-11-12T10:00:00+00:00"},
        {"id": "2", "source_name": "S2", "title": "Newer", "published_utc": "2026-11-13T08:00:00+00:00"},
    ]
    merged1, added1 = fr.merge_and_deduplicate(str(store), batch1)
    assert added1 == 2
    assert [m["title"] for m in merged1] == ["Newer", "Older"]

    merged2, added2 = fr.merge_and_deduplicate(str(store), batch1)
    assert added2 == 0
    assert len(merged2) == 2
