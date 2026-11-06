const box = document.getElementById("verdict");

function line(tag, text, cls) {
  const el = document.createElement(tag);
  el.textContent = text;
  if (cls) el.className = cls;
  return el;
}

function describe(target, verdict) {
  target.replaceChildren();
  if (!verdict.severity) {
    target.append(line("p", "No warning signs.", "good"));
    return;
  }
  target.append(line("span", verdict.severity.toUpperCase(), `sev ${verdict.severity}`), line("h2", verdict.title));
  const ul = document.createElement("ul");
  verdict.reasons.forEach((r) => ul.append(line("li", r)));
  target.append(ul);
  if (verdict.realDomain) target.append(line("p", `The real site is ${verdict.realDomain}`));
}

document.getElementById("link-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = document.getElementById("link-result");
  const reply = await chrome.runtime.sendMessage({ type: "preview", url: document.getElementById("link").value });
  if (reply.error) result.replaceChildren(line("p", reply.error, "bad"));
  else describe(result, reply);
});

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const saved = tab ? (await chrome.storage.session.get(`tab:${tab.id}`))[`tab:${tab.id}`] : null;
box.replaceChildren();

if (!saved || saved.url !== tab.url) {
  box.append(line("p", "This page hasn't been checked (only websites are).", "muted"));
} else if (!saved.verdict.severity) {
  box.append(line("p", "No warning signs on this site.", "good"));
} else if (!saved.verdict.show) {
  box.append(line("p", "Only minor signs, so no warning was shown. You'd get one if this page asked for a password:", "muted"));
  const ul = document.createElement("ul");
  saved.verdict.reasons.forEach((r) => ul.append(line("li", r)));
  box.append(ul);
} else {
  describe(box, saved.verdict);
}

const status = await chrome.runtime.sendMessage({ type: "status" });
const counts = status.feeds.map((f) => status.feedStatus[f.id]?.count ?? 0);
const total = counts.reduce((a, b) => a + b, 0);
document.getElementById("feeds").textContent = total
  ? `${total.toLocaleString()} known phishing sites in the local list.`
  : "Phishing lists haven't downloaded yet.";
document.getElementById("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
