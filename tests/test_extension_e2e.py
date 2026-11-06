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


# Fake feed downloads, filled in by the feed test. Empty means "offline".
FEED_FIXTURES = {}


def serve(route):
    url = route.request.url
    if not url.startswith(("http://", "https://")):
        return route.continue_()  # the extension's own files
    if "raw.githubusercontent.com" in url:
        for name, body in FEED_FIXTURES.items():
            if name in url:
                return route.fulfill(status=200, content_type="text/plain", body=body)
        return route.abort()
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


def _alert_nodes(page):
    """The notification lives in a closed shadow root, which page scripts (and
    Playwright selectors) can't see. DevTools can, so read it through that."""
    cdp = page.context.new_cdp_session(page)
    doc = cdp.send("DOM.getDocument", {"depth": -1, "pierce": True})["root"]
    stack = [doc]
    while stack:
        node = stack.pop()
        if node.get("nodeName") == "LOOKALIKE-WATCH-ALERT":
            return cdp, node["shadowRoots"][0]
        stack.extend(node.get("children", []) + node.get("shadowRoots", []))
    return cdp, None


def _walk(node):
    yield node
    for child in node.get("children", []):
        yield from _walk(child)


def alert_text(page):
    _, root = _alert_nodes(page)
    if root is None:
        return ""
    words = []
    for node in _walk(root):
        if node.get("nodeName") == "STYLE":
            node["children"] = []
        elif node.get("nodeType") == 3:
            words.append(node["nodeValue"])
    return " ".join(words)


def click_alert_button(page, text):
    """A real mouse click, like a person would make (isTrusted = true)."""
    cdp, root = _alert_nodes(page)
    for node in _walk(root):
        if node.get("nodeName") == "BUTTON" and any(
            text in c.get("nodeValue", "") for c in node.get("children", [])
        ):
            box = cdp.send("DOM.getBoxModel", {"backendNodeId": node["backendNodeId"]})
            quad = box["model"]["content"]
            page.mouse.click((quad[0] + quad[4]) / 2, (quad[1] + quad[5]) / 2)
            return
    raise AssertionError(f"no button containing {text!r}")


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
            tx.objectStore("phish").put(1, "phishing-database@1\\tuk-toll-pay.top");
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        };
    })""")
    worker.evaluate("""() => chrome.storage.local.set({ feedStatus: { "phishing-database": {
        generation: "phishing-database@1", count: 1, updatedAt: Date.now() } } })""")
    page, text = visit(ctx, "https://uk-toll-pay.top/pay")
    assert "Known phishing site" in text
    assert "Phishing.Database" in text
    page.close()


def test_trusting_a_site_silences_it(browser):
    ctx, _ = browser
    page, text = visit(ctx, "https://arnazon.co.uk/")
    assert "CRITICAL" in text
    click_alert_button(page, "trust")
    page.wait_for_timeout(500)
    assert alert_text(page) == ""
    page.reload()
    page.wait_for_timeout(1500)
    assert alert_text(page) == ""
    page.close()


def test_a_page_cannot_reach_into_the_notification(browser):
    ctx, worker = browser
    page, text = visit(ctx, "https://paypal-verify.com/")
    assert "HIGH" in text
    # What a phishing page's own script sees: no way in to click "trust"
    assert page.evaluate("document.querySelector('lookalike-watch-alert').shadowRoot") is None
    trusted = worker.evaluate("async () => (await chrome.storage.local.get({trusted: []})).trusted")
    assert "paypal-verify.com" not in trusted
    page.close()


def test_a_page_cannot_remove_the_notification(browser):
    ctx, _ = browser
    page, text = visit(ctx, "https://amazon-refund.co.uk/")
    assert "HIGH" in text
    page.evaluate("document.querySelector('lookalike-watch-alert').remove()")
    page.wait_for_timeout(300)
    assert "HIGH" in alert_text(page)
    page.close()


def test_dismissing_with_the_close_button_works(browser):
    ctx, _ = browser
    page, text = visit(ctx, "https://dpd-redelivery.com/")
    assert text
    click_alert_button(page, "\u00d7")
    page.wait_for_timeout(300)
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


def test_a_page_cannot_fake_a_login(browser):
    ctx, worker = browser
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    worker.evaluate(f"""() => chrome.storage.local.set({{
        loginSeen: {{ "sneaky-shop.com": ["{yesterday}"] }} }})""")
    page, _ = visit(ctx, "https://sneaky-shop.com/login", wait=1)
    page.evaluate("""() => {
        document.querySelector('input[type=password]').value = 'x';
        document.querySelector('form').requestSubmit();
    }""")
    page.wait_for_timeout(1000)
    page.close()
    mine = worker.evaluate("async () => (await chrome.storage.local.get('mySites')).mySites ?? []")
    assert "sneaky-shop.com" not in mine


def _stored_keys(worker):
    return worker.evaluate("""() => new Promise((resolve) => {
        const req = indexedDB.open("lookalike-watch", 1);
        req.onsuccess = () => {
            const all = req.result.transaction("phish").objectStore("phish").getAllKeys();
            all.onsuccess = () => resolve(all.result);
        };
    })""")


def test_feed_download_switches_to_the_new_list(browser):
    ctx, worker = browser
    ext_id = worker.url.split("/")[2]
    filler = "\n".join(f"filler-{i}.example" for i in range(1500))
    urls = "\n".join(f"https://openphish-{i}.example/login" for i in range(30))

    def refresh():
        options = ctx.new_page()
        options.goto(f"chrome-extension://{ext_id}/options.html")
        options.click("#refresh")
        playwright.expect(options.locator("#refresh-msg")).to_have_text("", timeout=20000)
        options.close()

    FEED_FIXTURES["phishing-domains-ACTIVE"] = f"first-list.example\n{filler}"
    FEED_FIXTURES["feed.txt"] = urls
    refresh()
    page, text = visit(ctx, "https://first-list.example/")
    assert "Known phishing site" in text
    page.close()

    # A new download replaces the old list completely
    FEED_FIXTURES["phishing-domains-ACTIVE"] = f"second-list.example\n{filler}"
    refresh()
    page, text = visit(ctx, "https://first-list.example/")
    assert text == ""
    page.close()
    page, text = visit(ctx, "https://second-list.example/")
    assert "Known phishing site" in text
    page.close()

    keys = _stored_keys(worker)
    generations = {k.split("\t")[0] for k in keys}
    assert len([g for g in generations if g.startswith("phishing-database@")]) == 1

    # A broken download keeps the list we have
    FEED_FIXTURES["phishing-domains-ACTIVE"] = "<html>rate limited</html>"
    refresh()
    page, text = visit(ctx, "https://second-list.example/")
    assert "Known phishing site" in text
    page.close()
    FEED_FIXTURES.clear()


def test_check_a_link_without_visiting_it(browser):
    ctx, worker = browser
    ext_id = worker.url.split("/")[2]
    popup = ctx.new_page()
    popup.goto(f"chrome-extension://{ext_id}/popup.html")
    popup.fill("#link", "paypa1.com/login")
    popup.click("#check-link")
    result = popup.locator("#link-result")
    playwright.expect(result).to_contain_text("CRITICAL")
    playwright.expect(result).to_contain_text("looks identical to paypal.com")

    popup.fill("#link", "https://www.paypal.com/")
    popup.click("#check-link")
    playwright.expect(popup.locator("#link-result")).to_contain_text("No warning signs")
    popup.close()
