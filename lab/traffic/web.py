"""Web browsing generator (mvp.md §3.1).

Headless Chromium (Playwright) loads pages from the local Nginx mirror on
server-b, plus optional internet via NAT. Real browser behavior: many small
requests, TLS, images, and caching headers.

Usage: web.py <base_url> <duration_seconds>
"""
from __future__ import annotations

import os
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

PAGES = [
    "/index.html",
    "/shop/index.html",
    "/news/index.html",
    "/hls/stream.m3u8",  # manifest fetch as part of mixed browsing
]


def main(base_url: str, duration: int) -> None:
    end = time.monotonic() + duration
    with sync_playwright() as p:
        # Debian images ship /usr/bin/chromium; Playwright otherwise insists on
        # its own downloaded bundle (PLAYWRIGHT_CHROMIUM_EXECUTABLE is not a
        # recognized env var).
        chromium = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE") \
            or None
        browser = p.chromium.launch(headless=True,
                                    executable_path=chromium)
        page = browser.new_page()
        i = 0
        while time.monotonic() < end:
            path = PAGES[i % len(PAGES)]
            url = f"{base_url.rstrip('/')}{path}"
            try:
                page.goto(url, wait_until="load", timeout=10_000)
                page.wait_for_timeout(500 + (i % 5) * 400)  # human-ish dwell time
            except Exception as exc:  # noqa: BLE001 — keep generating on transient errors
                print(f"warn: {url}: {exc}", file=sys.stderr)
            i += 1
        browser.close()
    # Connectivity probe kept out of the measured loop.
    urllib.request.urlopen(base_url, timeout=5)


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
