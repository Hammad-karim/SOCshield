#!/bin/sh
# SOCshield - capture dashboard screenshots for docs/screenshots/.
#
# Requires playwright (headless Chromium):
#   pip install playwright
#   playwright install chromium
#
# Usage:
#   bash scripts/capture_screenshots.sh
#   SOCSHIELD_HOST=http://localhost:5000 bash scripts/capture_screenshots.sh

set -eu

HOST="${SOCSHIELD_HOST:-http://127.0.0.1:5000}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$REPO_ROOT/docs/screenshots"

mkdir -p "$OUT_DIR"

command -v python >/dev/null || { echo "python not found" >&2; exit 1; }
python -c "import playwright" 2>/dev/null || {
    echo "playwright is not installed. Run: pip install playwright && playwright install chromium" >&2
    exit 1
}

# Pick the first incident id from /incidents, then capture every route.
python - "$HOST" "$OUT_DIR" <<'PYEOF'
import sys, asyncio
from pathlib import Path
from playwright.async_api import async_playwright

host, out_dir = sys.argv[1], Path(sys.argv[2])

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        ctx = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await ctx.new_page()

        targets = [
            ("dashboard",       "/"),
            ("alerts",          "/alerts"),
            ("incidents",       "/incidents"),
            ("threat_intel",    "/threat-intel"),
            ("mitre",           "/mitre"),
        ]
        for name, path in targets:
            url = host.rstrip("/") + path
            print(f"  -> {url}")
            await page.goto(url, wait_until="networkidle")
            await page.screenshot(path=str(out_dir / f"{name}.png"), full_page=True)

        # Find one incident and capture its detail view.
        await page.goto(host.rstrip("/") + "/incidents", wait_until="networkidle")
        href = await page.eval_on_selector(
            ".incident-card",
            "el => el.getAttribute('href')",
        )
        if href:
            print(f"  -> {host.rstrip('/')}{href}")
            await page.goto(host.rstrip("/") + href, wait_until="networkidle")
            await page.screenshot(
                path=str(out_dir / "incident_detail.png"), full_page=True
            )
        else:
            print("  (no incident found — skipping incident_detail.png)")

        await browser.close()

asyncio.run(main())
PYEOF

echo
echo "Wrote screenshots to $OUT_DIR"
ls -la "$OUT_DIR"
