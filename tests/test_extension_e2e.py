"""End-to-end test: the real extension in a real Chromium.

Every page request is answered locally, so no internet is needed. Skipped
unless Playwright and its Chromium are installed:

    pip install playwright && playwright install chromium
"""
import json
import time
from datetime import date, timedelta
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")

EXTENSION = Path(__file__).resolve().parent.parent / "extension"

PLAIN = "<!doctype html><title>page</title><h1>Hello</h1>"
LOGIN = (
    "<!doctype html><title>login</title><form action='/done' method='post'>"
    "<input name='user'><input type='password' name='pw'><button>Sign in</button></form>"
)


def serve(route):
    url = route.request.url
    if not url.startswith(("http://", "https://")):
        return route.continue_()  # the extension's own files
    if "raw.githubusercontent.com" in url:
        return route.abort()  # no feed downloads during the test
    body = LOGIN if "/login" in url else PLAIN
    route.fulfill(status=200, content_type="text/html", body=body)


@pytest.fixture(scope="module")
def browser(tmp_path_factory):
    with playwright.sync_playwright() as p:
        try:
            ctx = p.chromium.launch_persistent_context(
                str(tmp_path_factory.mktemp("profile")),
                channel="chromium",
                headless=True,
                args=[f"--disable-extensions-except={EXTENSION}", f"--load-extension={EXTENSION}"],
            )
        except Exception as exc:  # browser not installed
            pytest.skip(f"Chromium not available: {exc}")
        ctx.route("**/*", serve)
        workers = ctx.service_workers
        worker = workers[0] if workers else ctx.wait_for_event("serviceworker")
        yield ctx, worker
        ctx.close()


def visit(ctx, url, wait=2.0):
    page = ctx.new_page()
    page.goto(url)
    deadline = time.time() + wait
    while time.time() < deadline:
        text = alert_text(page)
        if text:
            return page, text
        time.sleep(0.1)
    return page, ""


def alert_text(page):
    return page.evaluate(
        "() => document.querySelector('lookalike-watch-alert')?.shadowRoot?.textContent ?? ''"
    )


def test_homoglyph_of_a_brand_gets_a_critical_notification(browser):
    ctx, _ = browser
    page, text = visit(ctx, "https://paypa1.com/")
    assert "CRITICAL" in text
    assert "This looks like a fake PayPal site" in text
    assert "looks identical to paypal.com" in text
    page.close()


def test_the_real_site_is_left_alone(browser):
    ctx, _ = browser
    page, text = visit(ctx, "https://www.paypal.com/login")
    assert text == ""
    page.close()


def test_toolbar_badge_marks_a_flagged_tab(browser):
    ctx, worker = browser
    page, _ = visit(ctx, "https://paypal-login.com/")
    # The extension doesn't ask for the "tabs" permission, so find the tab
    # through the verdict it saved for the popup.
    badge = worker.evaluate("""async () => {
        const saved = await chrome.storage.session.get(null);
        const key = Object.keys(saved).find((k) => saved[k].url.startsWith("https://paypal-login.com/"));
        return chrome.action.getBadgeText({ tabId: Number(key.split(":")[1]) });
    }""")
    assert badge == "!"
    page.close()


def test_known_phishing_site_from_the_feed(browser):
    ctx, worker = browser
    worker.evaluate("""() => new Promise((resolve, reject) => {
        const req = indexedDB.open("lookalike-watch", 1);
        req.onupgradeneeded = () => req.result.createObjectStore("phish");
        req.onsuccess = () => {
            const tx = req.result.transaction("phish", "readwrite");
            tx.objectStore("phish").put(1, "phishing-database\\tuk-toll-pay.top");
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        };
    })""")
    page, text = visit(ctx, "https://uk-toll-pay.top/pay")
    assert "Known phishing site" in text
    assert "Phishing.Database" in text
    page.close()


def test_trusting_a_site_silences_it(browser):
    ctx, _ = browser
    page, text = visit(ctx, "https://arnazon.co.uk/")
    assert "CRITICAL" in text
    page.evaluate("""() => [...document.querySelector('lookalike-watch-alert').shadowRoot
        .querySelectorAll('button')].find(b => b.textContent.includes('trust')).click()""")
    page.wait_for_timeout(500)
    assert alert_text(page) == ""
    page.reload()
    page.wait_for_timeout(1500)
    assert alert_text(page) == ""
    page.close()


def test_weaker_signs_only_show_on_login_pages(browser):
    ctx, _ = browser
    page, text = visit(ctx, "https://www.netflix.shop/")
    assert text == ""
    page.close()
    page, text = visit(ctx, "https://www.netflix.shop/login")
    assert "MEDIUM" in text
    page.close()


def test_home_router_login_is_quiet(browser):
    ctx, _ = browser
    page, text = visit(ctx, "http://192.168.1.1/login")
    assert text == ""
    page.close()


def test_imported_scan_report(browser, tmp_path):
    ctx, worker = browser
    ext_id = worker.url.split("/")[2]
    report = tmp_path / "report.json"
    report.write_text(json.dumps({
        "target": "example-bank.com",
        "findings": [
            {"ascii": "totally-unrelated.xyz", "score": 82, "level": "critical",
             "reasons": ["has a live web host"]},
            {"ascii": "harmless-low.com", "score": 10, "level": "low", "reasons": []},
        ],
    }))
    options = ctx.new_page()
    options.goto(f"chrome-extension://{ext_id}/options.html")
    options.set_input_files("#report", str(report))
    # The settings page's security policy blocks eval, so no wait_for_function here.
    playwright.expect(options.locator("#scan-msg")).to_contain_text("Imported 1 domains")
    options.close()

    page, text = visit(ctx, "https://shop.totally-unrelated.xyz/")
    assert "Flagged by your lookalike scan" in text
    page.close()


def test_sites_you_log_into_get_protected(browser):
    ctx, worker = browser
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    worker.evaluate(f"""() => chrome.storage.local.set({{
        loginSeen: {{ "leedsbuildingsociety.co.uk": ["{yesterday}"] }} }})""")

    page, _ = visit(ctx, "https://www.leedsbuildingsociety.co.uk/login", wait=1)
    page.fill("input[name=user]", "me")
    page.fill("input[type=password]", "not-a-real-password")
    page.click("button")
    page.wait_for_timeout(1000)
    page.close()

    mine = worker.evaluate("async () => (await chrome.storage.local.get('mySites')).mySites")
    assert "leedsbuildingsociety.co.uk" in mine

    page, text = visit(ctx, "https://leedsbuildingsociety-verify.co.uk/")
    assert "HIGH" in text
    page.close()
