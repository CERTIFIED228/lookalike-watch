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
  let reportedLogin = false;

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

  async function check() {
    const verdict = await ask({ type: "check", url: location.href, hasLogin: hasLogin() });
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
      position: fixed; top: 16px; right: 16px; z-index: 2147483647;
      width: min(360px, calc(100vw - 32px)); box-sizing: border-box;
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
    .trust { all: unset; cursor: pointer; color: var(--muted); text-decoration: underline; font-size: 12px; }
    .leave:focus-visible, .trust:focus-visible { outline: 2px solid var(--sev); outline-offset: 2px; }
  `;

  const COLOURS = { critical: "#b3261e", high: "#c2410c", medium: "#a16207", low: "#475569" };

  function el(tag, attrs = {}, text) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function render(verdict) {
    const host = el("lookalike-watch-alert");
    const root = host.attachShadow({ mode: "open" });
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
    close.addEventListener("click", () => host.remove());
    top.append(close);

    const reasons = el("ul");
    const list = verdict.reasons.slice(0, 4);
    for (const r of list) reasons.append(el("li", {}, r));
    if (verdict.reasons.length > list.length) {
      reasons.append(el("li", {}, `and ${verdict.reasons.length - list.length} more`));
    }

    const actions = el("div", { class: "actions" });
    const leave = el("button", { class: "leave" }, verdict.realDomain ? `Go to ${verdict.realDomain}` : "Leave this site");
    leave.addEventListener("click", () => {
      if (verdict.realDomain) location.href = `https://${verdict.realDomain}`;
      else ask({ type: "leave" });
    });
    const trust = el("button", { class: "trust" }, "I trust this site");
    trust.addEventListener("click", async () => {
      await ask({ type: "trust", url: location.href });
      host.remove();
    });
    actions.append(leave, trust);

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
    card.append(actions);
    root.append(style, card);
    document.documentElement.append(host);
  }

  // --- login forms --------------------------------------------------------------------

  // Many sites add their login form after the page loads. Re-check once a
  // form shows up, because some warnings only apply to login pages.
  function watchForLogin() {
    if (hasLogin()) return;
    const observer = new MutationObserver(() => {
      if (hasLogin()) {
        observer.disconnect();
        check();
      }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => observer.disconnect(), 15_000);
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (reportedLogin || !(form instanceof HTMLFormElement)) return;
    if (form.querySelector("input[type=password]")) {
      reportedLogin = true;
      ask({ type: "loggedIn", url: location.href });
    }
  }, true);

  check();
  watchForLogin();
})();
