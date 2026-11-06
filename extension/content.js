// Runs on every page. Asks the background worker whether this site looks
// fake and, if so, shows a small notification in the corner.
(() => {
  if (window.top !== window) return;

  const LOGIN_FIELDS = [
    "input[type=password]",
    "input[autocomplete~='cc-number']",
    "input[autocomplete~='current-password']",
    "input[name*='card' i][inputmode='numeric']",
  ].join(",");

  const SEVERITY_TEXT = {
    critical: "Very likely a scam. Don't enter any details here.",
    high: "Probably a fake. Don't log in or pay on this site.",
    medium: "Some signs of a fake site. Check the address carefully before logging in.",
    low: "A few warning signs. Be careful what you type here.",
  };

  let shown = false;
  let dismissed = false;
  let removeCard = () => {};
  let reportedLogin = false;
  let typedPassword = false;
  let touchedForm = null;

  const hasLogin = () => document.querySelector(LOGIN_FIELDS) !== null;

  function ask(message) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(message, (reply) => {
          resolve(chrome.runtime.lastError ? null : reply);
        });
      } catch {
        resolve(null); // extension was reloaded or removed
      }
    });
  }

  // The first check is sent before any of the page's own scripts run, so a
  // page can't change its address with history.replaceState() first.
  const firstCheck = ask({ type: "check", hasLogin: false });

  async function check() {
    const verdict = await ask({ type: "check", hasLogin: hasLogin() });
    if (verdict?.show && !shown) {
      shown = true;
      render(verdict);
    }
  }

  // --- the notification ---------------------------------------------------------------

  const STYLE = `
    :host { all: initial; }
    .card {
      --bg: #ffffff; --fg: #1f2328; --muted: #57606a; --line: #d0d7de; --btn: #1f2328; --btn-fg: #ffffff;
      position: relative; width: 100%; box-sizing: border-box;
      background: var(--bg); color: var(--fg);
      border: 1px solid var(--line); border-left: 5px solid var(--sev);
      border-radius: 10px; box-shadow: 0 8px 28px rgba(0,0,0,.18);
      padding: 14px 14px 12px; font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif;
      animation: in .18s ease-out;
    }
    @media (prefers-color-scheme: dark) {
      .card { --bg: #1c2128; --fg: #e6edf3; --muted: #9da7b3; --line: #373e47; --btn: #e6edf3; --btn-fg: #1c2128; }
    }
    @keyframes in { from { opacity: 0; transform: translateY(-6px); } }
    .top { display: flex; align-items: center; gap: 8px; }
    .pill {
      background: var(--sev); color: #fff; font-weight: 700; font-size: 11px;
      letter-spacing: .04em; padding: 2px 8px; border-radius: 999px;
    }
    .who { color: var(--muted); font-size: 12px; flex: 1; }
    .close {
      all: unset; cursor: pointer; color: var(--muted); font-size: 18px; line-height: 1;
      padding: 0 4px; border-radius: 4px;
    }
    .close:hover, .close:focus-visible { color: var(--fg); outline: 2px solid var(--line); }
    h2 { margin: 8px 0 2px; font-size: 15px; line-height: 1.3; }
    .what { margin: 0 0 8px; color: var(--muted); }
    ul { margin: 0 0 8px; padding-left: 18px; }
    li { margin: 2px 0; overflow-wrap: anywhere; }
    .real { margin: 0 0 10px; }
    .real b { overflow-wrap: anywhere; }
    .actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    .leave {
      all: unset; cursor: pointer; background: var(--btn); color: var(--btn-fg);
      font-weight: 600; padding: 7px 12px; border-radius: 6px;
    }
    .hint { color: var(--muted); font-size: 12px; margin: 10px 0 0; }
    .leave:focus-visible { outline: 2px solid var(--sev); outline-offset: 2px; }
  `;

  const COLOURS = { critical: "#b3261e", high: "#c2410c", medium: "#a16207", low: "#475569" };

  function el(tag, attrs = {}, text) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // Only real clicks count: a page can't press the buttons with .click().
  function onRealClick(node, handler) {
    node.addEventListener("click", (event) => {
      if (event.isTrusted) handler(event);
    });
  }

  // The card sits inside the scam page, so the page will try to hide it.
  // It's a plain <div> (a page can pre-define a custom element's name and get
  // inside it), in a closed shadow root, shown in the browser's top layer so
  // z-index tricks can't cover it, and styled inline with !important, which
  // beats any stylesheet. If the page changes or removes it, it goes back.
  const HOST_STYLE = [
    "all: initial", "position: fixed", "inset: 16px 16px auto auto", "margin: 0", "padding: 0",
    "border: 0", "background: transparent", "width: min(360px, calc(100vw - 32px))",
    "height: auto", "max-height: calc(100vh - 32px)", "overflow: visible", "display: block",
    "visibility: visible", "opacity: 1", "z-index: 2147483647", "transform: none", "filter: none",
    "clip-path: none", "pointer-events: auto",
  ].map((rule) => `${rule} !important`).join("; ");

  function pin(host) {
    host.setAttribute("style", HOST_STYLE);
    host.setAttribute("popover", "manual");
    if (!host.isConnected) document.documentElement.append(host);
    try {
      if (!host.matches(":popover-open")) host.showPopover();
    } catch {
      // older browser: the fixed position and z-index still apply
    }
  }

  function keepOnPage(host) {
    let restores = 0;
    const intact = () => host.isConnected && host.getAttribute("style") === HOST_STYLE
      && host.getAttribute("popover") === "manual" && host.matches(":popover-open");
    // Only repair real damage, or our own repairs would trigger more repairs.
    const restore = () => {
      if (!dismissed && !intact() && restores++ < 50) pin(host);
    };
    new MutationObserver(restore).observe(document.documentElement, { childList: true, subtree: true });
    new MutationObserver(restore).observe(host, { attributes: true });
    host.addEventListener("toggle", (event) => {
      if (event.newState === "closed") restore();
    });
  }

  function render(verdict) {
    const host = el("div", { "data-lookalike-watch": "" });
    const root = host.attachShadow({ mode: "closed" });
    const style = el("style");
    style.textContent = STYLE;

    const card = el("div", { class: "card", role: "alertdialog", "aria-labelledby": "lw-title", "aria-describedby": "lw-what" });
    card.style.setProperty("--sev", COLOURS[verdict.severity]);

    const top = el("div", { class: "top" });
    top.append(
      el("span", { class: "pill" }, verdict.severity.toUpperCase()),
      el("span", { class: "who" }, "lookalike-watch"),
    );
    const close = el("button", { class: "close", "aria-label": "Dismiss" }, "×");
    removeCard = () => {
      dismissed = true;
      host.remove();
    };
    onRealClick(close, () => removeCard());
    top.append(close);

    const reasons = el("ul");
    const list = verdict.reasons.slice(0, 4);
    for (const r of list) reasons.append(el("li", {}, r));
    if (verdict.reasons.length > list.length) {
      reasons.append(el("li", {}, `and ${verdict.reasons.length - list.length} more`));
    }

    const actions = el("div", { class: "actions" });
    const leave = el("button", { class: "leave" }, verdict.realDomain ? `Go to ${verdict.realDomain}` : "Leave this site");
    onRealClick(leave, () => {
      if (verdict.realDomain) location.href = `https://${verdict.realDomain}`;
      else ask({ type: "leave" });
    });
    actions.append(leave);

    card.append(
      top,
      el("h2", { id: "lw-title" }, verdict.title),
      el("p", { class: "what", id: "lw-what" }, SEVERITY_TEXT[verdict.severity]),
      reasons,
    );
    if (verdict.realDomain) {
      const real = el("p", { class: "real" }, "The real site is ");
      real.append(el("b", {}, verdict.realDomain));
      card.append(real);
    }
    // "I trust this site" lives in the toolbar popup, where a page can't
    // trick you into clicking it.
    card.append(actions, el("p", { class: "hint" }, "Think this is wrong? Click the lookalike-watch icon in your toolbar."));
    root.append(style, card);
    pin(host);
    keepOnPage(host);
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type === "trusted") removeCard();
  });

  // --- login forms --------------------------------------------------------------------

  // Many sites add their login form after the page loads. Re-check once a
  // form shows up, because some warnings only apply to login pages.
  function watchForLogin() {
    if (hasLogin() || !document.documentElement) return;
    const observer = new MutationObserver(() => {
      if (hasLogin()) {
        observer.disconnect();
        check();
      }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => observer.disconnect(), 15_000);
  }

  // A site only counts as one you log into if a real person was involved:
  // they typed the password, or (for password managers, whose filling looks
  // scripted) clicked or pressed a key in the form. A page can't fake that
  // with requestSubmit().
  document.addEventListener("input", (event) => {
    if (event.isTrusted && event.target instanceof HTMLInputElement && event.target.type === "password") {
      typedPassword = true;
    }
  }, true);
  for (const type of ["pointerdown", "keydown"]) {
    document.addEventListener(type, (event) => {
      if (event.isTrusted) touchedForm = event.target?.closest?.("form") ?? touchedForm;
    }, true);
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (reportedLogin || !(form instanceof HTMLFormElement)) return;
    const password = form.querySelector("input[type=password]");
    if (!password?.value || !(typedPassword || touchedForm === form)) return;
    reportedLogin = true;
    ask({ type: "loggedIn" });
  }, true);

  function whenReady(fn) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fn, { once: true });
    else fn();
  }

  whenReady(async () => {
    const verdict = await firstCheck;
    if (verdict?.show && !shown) {
      shown = true;
      render(verdict);
    }
    check();
    watchForLogin();
  });
})();
