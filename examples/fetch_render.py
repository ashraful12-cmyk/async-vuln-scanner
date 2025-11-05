# fetch_render.py
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

USAGE = "Usage: python fetch_render.py <url> [output-file]"

def main():
    if len(sys.argv) < 2:
        print(USAGE); sys.exit(1)
    url = sys.argv[1]
    out = Path(sys.argv[2]) if len(sys.argv) >= 3 else Path("rendered_response.html")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_extra_http_headers({"Accept-Language": "en-US,en;q=0.9"})
        try:
            page.goto(url, wait_until="networkidle", timeout=60000)
        except PWTimeout:
            page.wait_for_timeout(3000)
        page.wait_for_timeout(1000)
        content = page.content()
        out.write_text(content, encoding="utf-8")
        print(f"Saved rendered HTML to {out.resolve()}")
        browser.close()

if __name__ == "__main__":
    main()
