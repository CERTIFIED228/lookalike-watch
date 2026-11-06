const box = document.getElementById("verdict");

function line(tag, text, cls) {
  const el = document.createElement(tag);
  el.textContent = text;
  if (cls) el.className = cls;
  return el;
}

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const saved = tab ? (await chrome.storage.session.get(`tab:${tab.id}`))[`tab:${tab.id}`] : null;
box.replaceChildren();

if (!saved || saved.url !== tab.url) {
  box.append(line("p", "This page hasn't been checked (only websites are).", "muted"));
} else if (!saved.verdict.severity || !saved.verdict.show) {
  box.append(line("p", "No warning signs on this site.", "good"));
} else {
  const v = saved.verdict;
  box.append(line("span", v.severity.toUpperCase(), `sev ${v.severity}`), line("h2", v.title));
  const ul = document.createElement("ul");
  v.reasons.forEach((r) => ul.append(line("li", r)));
  box.append(ul);
}

const status = await chrome.runtime.sendMessage({ type: "status" });
const counts = status.feeds.map((f) => status.feedStatus[f.id]?.count ?? 0);
const total = counts.reduce((a, b) => a + b, 0);
document.getElementById("feeds").textContent = total
  ? `${total.toLocaleString()} known phishing sites in the local list.`
  : "Phishing lists haven't downloaded yet.";
document.getElementById("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
