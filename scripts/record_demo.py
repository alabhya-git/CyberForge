"""Record a short UI backup demo after the benchmark has finished.

Requires Playwright's Python package and an installed Chrome browser. The lab
must be running, and no other incident run may be active.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from playwright.async_api import async_playwright


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "artifacts"


async def main():
    OUTPUT.mkdir(exist_ok=True)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(channel="chrome", headless=True)
        context = await browser.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=1, record_video_dir=str(OUTPUT), record_video_size={"width": 1440, "height": 900})
        page = await context.new_page()
        await page.goto("http://127.0.0.1:8100/", wait_until="networkidle")
        await page.screenshot(path=str(OUTPUT / "twokey-overview.png"), full_page=True)
        await page.get_by_role("button", name="Run incident response").click()
        await page.get_by_text("Attack contained. Business running.").wait_for(timeout=90000)
        await page.get_by_text("Attack contained. Business running.").scroll_into_view_if_needed()
        await page.wait_for_timeout(1200)
        await page.evaluate("window.scrollTo(0, 0)")
        await page.screenshot(path=str(OUTPUT / "twokey-contained.png"), full_page=True)
        await page.get_by_role("button", name="Evidence & provenance").click()
        await page.get_by_role("button", name="Check authorization").click()
        await page.get_by_text("REJECTED", exact=False).wait_for(timeout=10000)
        await page.get_by_text("REJECTED", exact=False).scroll_into_view_if_needed()
        await page.wait_for_timeout(1000)
        await page.get_by_role("button", name="Replay results").click()
        await page.wait_for_timeout(1200)
        await page.get_by_role("button", name="Business impact").click()
        await page.get_by_role("button", name="Replay broader responses").click()
        await page.get_by_role("button", name="Replay again").wait_for(timeout=120000)
        await page.get_by_text("What broader responses actually break").scroll_into_view_if_needed()
        await page.wait_for_timeout(1800)
        await page.screenshot(path=str(OUTPUT / "twokey-impact.png"), full_page=True)
        await page.get_by_role("checkbox").last.check()
        await page.get_by_role("button", name="Re-evaluate with these rules").click()
        await page.get_by_text("Escalated: requirements conflict").wait_for(timeout=20000)
        await page.get_by_text("Escalated: requirements conflict").scroll_into_view_if_needed()
        await page.wait_for_timeout(1800)
        await page.screenshot(path=str(OUTPUT / "twokey-conflict.png"), full_page=True)
        await page.evaluate("window.scrollTo(0, 0)")
        await page.get_by_role("button", name="S2", exact=False).click()
        await page.get_by_role("button", name="Run incident response").click()
        await page.get_by_text("Attack contained. Business running.").wait_for(timeout=90000)
        await page.get_by_role("button", name="Replay results").click()
        await page.get_by_text("Counterexample:", exact=False).first.wait_for(timeout=10000)
        await page.get_by_text("Counterexample:", exact=False).first.scroll_into_view_if_needed()
        await page.wait_for_timeout(1800)
        await page.evaluate("window.scrollTo(0, 0)")
        await page.screenshot(path=str(OUTPUT / "twokey-replan.png"), full_page=True)
        video_path = await page.video.path() if page.video else None
        await context.close()
        await browser.close()
        if video_path:
            Path(video_path).replace(OUTPUT / "twokey-demo.webm")
    print("Screenshots and backup video saved in", OUTPUT)


if __name__ == "__main__":
    asyncio.run(main())
