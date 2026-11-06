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
# Pages with their own HTML, for the attack tests. Keyed by URL prefix.
PAGES = {}


def serve(route):
    url = route.request.url
    if not url.startswith(("http://", "https://")):
        return route.continue_()  # the extension's own files
    if "raw.githubusercontent.com" in url:
        for name, body in FEED_FIXTURES.items():
            if name in url:
                return route.fulfill(status=200, content_type="text/plain", body=body)
        return route.abort()
    body = next((html for prefix, html in PAGES.items() if url.startswith(prefix)), None)
    if body is None:
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
        if "data-lookalike-watch" in node.get("attributes", [])[::2] and node.get("shadowRoots"):
            return cdp, node, node["shadowRoots"][0]
        stack.extend(node.get("children", []) + node.get("shadowRoots", []))
    return cdp, None, None


def card_is_visible(page):
    """True if the card is on screen: laid out, not transparent, not hidden."""
    cdp, host, _ = _alert_nodes(page)
    if host is None:
        return False
    try:
        cdp.send("DOM.getBoxModel", {"nodeId": host["nodeId"]})
    except Exception:
        return False  # display: none has no box
    cdp.send("CSS.enable")
    computed = cdp.send("CSS.getComputedStyleForNode", {"nodeId": host["nodeId"]})
    style = {s["name"]: s["value"] for s in computed["computedStyle"]}
    return style["opacity"] == "1" and style["visibility"] == "visible"


def _walk(node):
    yield node
    for child in node.get("children", []):
        yield from _walk(child)


def alert_text(page):
    _, _, root = _alert_nodes(page)
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
    cdp, _, root = _alert_nodes(page)
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
    tab_id = _tab_id(worker, "https://paypal-login.com/")
    badge = worker.evaluate(f"chrome.action.getBadgeText({{ tabId: {tab_id} }})")
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


def _tab_id(worker, url_prefix):
    # The extension doesn't ask for the "tabs" permission, so find the tab
    # through the verdict it saved for the popup.
    return worker.evaluate(f"""async () => {{
        const saved = await chrome.storage.session.get(null);
        const key = Object.keys(saved).find((k) => k.startsWith("tab:")
            && saved[k].url.startsWith("{url_prefix}"));
        return Number(key.split(":")[1]);
    }}""")


def test_trusting_a_site_from_the_popup_silences_it(browser):
    ctx, worker = browser
    page, text = visit(ctx, "https://arnazon.co.uk/")
    assert "CRITICAL" in text
    tab_id = _tab_id(worker, "https://arnazon.co.uk/")
    # What the popup's "I trust this site" button sends
    options = ctx.new_page()
    options.goto(f"chrome-extension://{worker.url.split('/')[2]}/options.html")
    reply = options.evaluate(f"chrome.runtime.sendMessage({{ type: 'trustTab', tabId: {tab_id} }})")
    assert reply == {"ok": True}
    options.close()
    page.wait_for_timeout(500)
    assert alert_text(page) == ""
    page.reload()
    page.wait_for_timeout(1500)
    assert alert_text(page) == ""
    page.close()


def test_the_page_has_no_trust_button_to_click(browser):
    ctx, _ = browser
    page, text = visit(ctx, "https://paypal-verify.com/")
    assert "HIGH" in text
    assert "I trust this site" not in text
    assert "toolbar" in text
    # And what the page's own scripts see: no way into the card
    assert page.evaluate("document.querySelector('[data-lookalike-watch]').shadowRoot") is None
    page.close()


def test_a_page_cannot_hide_the_card_with_css(browser):
    PAGES["https://amazon-refund.co.uk/"] = (
        "<!doctype html><style>"
        "div { display: none !important; opacity: 0 !important; }"
        "[popover], :popover-open { visibility: hidden !important; }"
        "@layer x { div { display: none !important; } }"
        "</style><h1>Refund</h1>"
    )
    ctx, _ = browser
    page, text = visit(ctx, "https://amazon-refund.co.uk/")
    assert "HIGH" in text
    assert card_is_visible(page)
    page.close()


def test_a_page_cannot_hide_or_remove_the_card_with_script(browser):
    ctx, _ = browser
    page, text = visit(ctx, "https://amazon-verify.co.uk/")
    assert "HIGH" in text
    for attack in [
        "document.querySelector('[data-lookalike-watch]').remove()",
        "document.querySelector('[data-lookalike-watch]')"
        ".style.setProperty('display', 'none', 'important')",
        "document.querySelector('[data-lookalike-watch]').hidePopover()",
        "document.querySelector('[data-lookalike-watch]').removeAttribute('style')",
    ]:
        page.evaluate(attack)
        page.wait_for_timeout(300)
        assert card_is_visible(page), attack
    page.close()


def test_a_page_cannot_dodge_a_feed_listing_with_replace_state(browser):
    ctx, worker = browser
    worker.evaluate("""() => new Promise((resolve) => {
        const req = indexedDB.open("lookalike-watch", 1);
        req.onupgradeneeded = () => req.result.createObjectStore("phish");
        req.onsuccess = () => {
            const tx = req.result.transaction("phish", "readwrite");
            const key = "openphish@1\turl:storage.googleapis.com/evil-bucket/phish.html";
            tx.objectStore("phish").put(1, key);
            tx.oncomplete = () => resolve();
        };
    })""")
    worker.evaluate("""async () => {
        const { feedStatus } = await chrome.storage.local.get({ feedStatus: {} });
        feedStatus.openphish = { generation: "openphish@1", count: 1, updatedAt: Date.now() };
        await chrome.storage.local.set({ feedStatus });
    }""")
    PAGES["https://storage.googleapis.com/evil-bucket/phish.html"] = (
        "<!doctype html>"
        "<script>history.replaceState(null, '', '/innocent-bucket/menu.pdf')</script>"
        "<h1>Sign in</h1>"
    )
    page, text = visit(ctx, "https://storage.googleapis.com/evil-bucket/phish.html")
    assert page.url.endswith("/innocent-bucket/menu.pdf")
    assert "Known phishing site" in text
    page.close()


def test_high_warnings_also_raise_a_system_notification(browser):
    ctx, worker = browser
    page, _ = visit(ctx, "https://secure-barclays.co.uk/")
    titles = worker.evaluate("""async () => {
        const all = await chrome.notifications.getAll();
        return Object.keys(all);
    }""")
    tab_id = _tab_id(worker, "https://secure-barclays.co.uk/")
    assert f"tab-{tab_id}" in titles
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


def test_a_password_manager_login_still_counts(browser):
    # Password managers fill fields with script (untrusted events), but the
    # person still clicks "Sign in".
    ctx, worker = browser
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    worker.evaluate(f"""() => chrome.storage.local.set({{
        loginSeen: {{ "my-credit-union.org": ["{yesterday}"] }} }})""")
    page, _ = visit(ctx, "https://my-credit-union.org/login", wait=1)
    page.evaluate("document.querySelector('input[type=password]').value = 'filled-by-manager'")
    page.click("button")
    page.wait_for_timeout(1000)
    page.close()
    mine = worker.evaluate("async () => (await chrome.storage.local.get('mySites')).mySites")
    assert "my-credit-union.org" in mine


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

    # Two refreshes at once (a double click, or the alarm firing at startup)
    # must not delete each other's list
    FEED_FIXTURES["phishing-domains-ACTIVE"] = f"third-list.example\n{filler}"
    options = ctx.new_page()
    options.goto(f"chrome-extension://{ext_id}/options.html")
    options.evaluate("""Promise.all([
        chrome.runtime.sendMessage({ type: "refreshFeeds" }),
        chrome.runtime.sendMessage({ type: "refreshFeeds" }),
    ])""")
    options.close()
    page, text = visit(ctx, "https://third-list.example/")
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
