# lookalike-watch

Finds registered domains that imitate yours (`paypa1.com`, `pаypal.com` with a Cyrillic "а", `paypal-login.com`) and keeps watching for new ones.

Most phishing starts with a domain that looks right at a glance. Brands usually find out about these after customers have already been hit. This tool tries to close that gap using only public data: DNS and Certificate Transparency logs.

## What it does

1. **Generates lookalikes** of a domain using 12 techniques (typos, homoglyphs, bit flips, TLD swaps, brand + keyword combos...).
2. **Checks which ones exist** with parallel DNS lookups (NS, A/AAAA, MX).
3. **Searches Certificate Transparency logs** (via [crt.sh](https://crt.sh)) for any certificate with the brand name in it. This catches things like `paypal-account-review.com` that no typo generator would ever come up with.
4. **Scores each registered domain 0-100** and lists the reasons behind the score.
5. **Watch mode** re-scans on a schedule and posts *new* findings to Slack or Discord.
6. **A browser extension** warns you while browsing when a site is a lookalike or a known phishing site (see [Browser extension](#browser-extension)).

It never visits the suspicious sites. Everything comes from DNS and public certificate logs.

## Install

Needs Python 3.10+.

```bash
git clone https://github.com/CERTIFIED228/lookalike-watch.git
cd lookalike-watch
python -m venv .venv
```

Activate the venv: `.venv\Scripts\activate` on Windows, `source .venv/bin/activate` on macOS/Linux. Then:

```bash
pip install -e .
```

## Usage

### List possible lookalikes (offline)

```console
$ lookalike-watch generate paypal.com
paypl.com           omission
paypall.com         repetition
papyal.com          transposition
paypel.com          vowel-swap
pay-pal.com         hyphenation
pay0al.com          replacement
paqypal.com         insertion
qaypal.com          bitsquatting
paypals.com         addition
pаypal.com          homoglyph  (xn--pypal-4ve.com)
paypal-login.com    combosquat
paypal.net          tld-swap
...
267 candidates
```

### Scan for the ones that are registered

```bash
lookalike-watch scan paypal.com
lookalike-watch scan paypal.com --ct                # also search CT logs
lookalike-watch scan paypal.com --ct -o report.json # save as JSON (or .csv)
lookalike-watch scan paypal.com --min-score 50      # only high/critical
lookalike-watch scan paypal.com -t homoglyph -t combosquat
```

Example output (from the local test DNS zone in `tests/`, not live data):

```
SCORE  LEVEL     DOMAIN                          TECHNIQUE   TOP REASON
85     critical  pаypal.com (xn--pypal-4ve.com)  homoglyph   looks identical to 'paypal' at a glance
75     critical  paypa1.com                      homoglyph   looks identical to 'paypal' at a glance
55     high      paypal-login.com                combosquat  contains the brand name 'paypal'
28     low       paypl.com                       omission    looks parked (for sale or ad page) - keep an eye on it
10     low       paypal.net                      tld-swap    uses the same nameservers as paypal.com, probably owned by the brand
```

The full list of reasons for each domain is in the JSON/CSV output.

### Watch for new ones

```bash
cp .env.example .env        # then paste your Slack/Discord webhook into .env
lookalike-watch watch paypal.com --ct --baseline --once   # record what already exists
lookalike-watch watch paypal.com --ct                      # re-scan every hour
```

Only domains it hasn't seen before trigger an alert. Seen domains are stored in `.lookalike-watch/<domain>.json`. If an alert fails to send, those domains aren't marked as seen, so the next run tries again.

To run it on a schedule instead of leaving it open, use `--once` with cron:

```cron
0 * * * * cd /path/to/lookalike-watch && .venv/bin/lookalike-watch watch paypal.com --ct --once
```

or with Windows Task Scheduler, using the program `.venv\Scripts\lookalike-watch.exe` and the arguments `watch paypal.com --ct --once`.

## Browser extension

The `extension/` folder is a Chrome/Edge extension that does the protecting side: while you browse, it shows a small notification when a site looks like a fake copy of a real one, or is a known phishing site. The notification gives a severity and the reasons.

### Install

1. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
2. Click **Load unpacked** and pick the `extension` folder.

Then browse as normal. Nothing shows up unless a site looks wrong.

### What it checks

Every page is checked in the browser itself. The sites you visit are never sent anywhere.

1. **Lookalikes of sites worth protecting**: 43 often-phished brands (Microsoft, PayPal, Amazon, UK banks, Royal Mail, Evri, HMRC, DVLA, NHS...), the 10,000 most visited sites in Chrome, and any site you've logged into on two different days. It catches:
   - homoglyphs (`pаypal.com` with a Cyrillic а, `paypa1.com`)
   - one-letter typos (`paypl.com`)
   - brand + scam word (`paypal-login.com`, `hmrc-tax-refund.com`, `royalmail-redelivery.com`)
   - a real domain used as a fake subdomain (`paypal.com.secure-check.bid`)
   - brand names on free hosting (`royalmail-redelivery.vercel.app`)
2. **Known phishing sites**: [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (about 390,000 active domains) and the [OpenPhish](https://github.com/openphish/public_feed) public feed. Both are downloaded every 6 hours, stored in IndexedDB and looked up locally. Shared platforms like Google Docs are only ever matched on the exact page, never the whole service.
3. **Warning signs on login pages**: a raw IP address, a password form over `http://`, mixed alphabets in one name, endings heavily used for phishing (`.zip`, `.top`, `.xin`...).

Plus anything from a `lookalike-watch scan` report you import on the settings page.

| Severity | When | Shown |
|---|---|---|
| Critical | on a phishing list, or looks identical to a protected brand or one of your sites | always |
| High | typo of a brand, brand + scam word, fake subdomain | always |
| Medium | weaker signs, e.g. a popular site's name on free hosting | only on pages asking for a password or card |
| Low | warning signs only | only on login pages |

The notification has a **Go to the real site** / **Leave this site** button and an **I trust this site** link for false alarms.

### How accurate it is

Measured with `extension/scripts/benchmark.mjs` on sites it has never seen: 100,000 sites from the Chrome UX Report ranked below the top 100k, and 50,000 domains from Phishing.Database (feed lookups switched off, so only the pattern checks count).

| | Warned |
|---|---|
| Legitimate sites, normal pages | 5 in 100,000 (0.005%) |
| Legitimate sites, login pages | 97 in 100,000 (0.1%), mostly medium/low |
| Real phishing domains, pattern checks alone | 11% |

The 11% is expected: most phishing domains have random names (`xk2-secure.top`) that look like nothing, and that's what the feeds are for. An earlier version also matched one-letter typos against all 10,000 top sites, but the benchmark showed it raised about 7 false alarms for every phishing site it caught, so that check now only applies to the protected brands and your own sites.

Checking a page takes about 0.04 ms.

### What it can't do

- A brand-new scam with an innocent-looking name and no warning signs gets through until a feed lists it. Chrome's own Safe Browsing is still worth keeping on.
- It only looks at the address, not the page content.
- Hacked legitimate sites are only caught once they're on a feed.

### Data

- `data/top-sites.json` and `data/known-sites.json`: [Chrome UX Report](https://developer.chrome.com/docs/crux) top sites via [zakird/crux-top-lists](https://github.com/zakird/crux-top-lists) (CC BY 4.0).
- `data/suffixes.json`: multi-part endings (`co.uk`, `com.au`) from the [Public Suffix List](https://publicsuffix.org/).
- Rebuild them with `python extension/scripts/build_data.py`.

## Techniques

| Technique | Example (paypal.com) | Idea |
|---|---|---|
| omission | paypl.com | missed a key |
| repetition | paypall.com | key pressed twice |
| transposition | papyal.com | two keys swapped |
| vowel-swap | paypel.com | wrong vowel |
| hyphenation | pay-pal.com | hyphen added |
| replacement | paypak.com | hit the key next door (QWERTY) |
| insertion | paqypal.com | hit two keys at once |
| bitsquatting | qaypal.com | one bit flipped in memory |
| addition | paypal1.com | extra character on the end |
| homoglyph | pаypal.com / paypa1.com | characters that look the same |
| combosquat | paypal-login.com | brand + scary word |
| tld-swap | paypal.net | same name, different TLD |
| ct-log | paypal-account-review.com | found in a real certificate |

## How scoring works

Points are added up and capped at 100:

| Signal | Points |
|---|---|
| Looks identical to the brand once homoglyphs are normalised | +45 |
| Within a few edits of the brand (scaled by similarity), or contains the brand name (+25), whichever is stronger | up to +40 |
| Contains a phishing word (login, verify, account...) | +15 |
| Can receive email (MX records) | +15 |
| Live web host (A/AAAA records) | +10 |
| Internationalised (punycode) domain | +10 |
| Has a certificate in CT logs | +10 |
| Registered | +5 |
| Parked (nameservers or mail belong to a parking company) | -10 |
| Probably owned by the brand: registered through a brand-protection registrar like MarkMonitor or CSC, DNS or mail run from the brand's domain, same nameservers, or the brand's own mail domain | -40 |

For parked and brand-owned domains, the web, mail and certificate points aren't added. Those servers belong to the parking company or the brand, so they don't make the domain more dangerous.

Levels: **critical** 70+, **high** 50+, **medium** 30+, **low** below that.

Mail counts for a lot because a lookalike with MX records can be used to send convincing phishing emails, and it can also quietly receive mail people misaddress to it.

## Keeping the webhook secret

A webhook URL is a credential, because anyone who has it can post to your channel. So:

- it's only read from the `LOOKALIKE_WEBHOOK_URL` environment variable or `.env`, never from a command-line flag (flags end up in shell history and process lists)
- `.env` is in `.gitignore`, and `.env.example` is what gets committed
- logs and error messages only ever show `https://hooks.slack.com/***`
- [gitleaks](https://github.com/gitleaks/gitleaks) runs as a pre-commit hook and in CI

To turn on the pre-commit hooks:

```bash
pip install pre-commit
pre-commit install
```

## DNS gotchas

- Some ISP resolvers answer for domains that don't exist (to show you an ad page), which would make every candidate look registered. The tool checks for this before every scan and stops if it spots it. Use `--nameserver 1.1.1.1` to get around it.
- Some filters only lie about names that look like a well-known brand. The check tests a made-up brand name too (`paypal-<random>.com`). And because every registered domain has NS records, any answer without them is treated as made up by the resolver: it's left out of the results and you get a warning.
- Lookups that time out are counted and reported at the end rather than silently treated as "not registered".

## What a real scan looks like

The first live scan of paypal.com (from a home connection in the UK) found 217 of 267 candidates "registered". Digging into the results showed:

- 88 of them had no NS records and all pointed at the same address on the ISP's network. That was the ISP's DNS filter answering for brand-like names, not real domains. The no-NS check and the brand-name resolver test came out of this.
- Most of the rest used MarkMonitor nameservers, meaning PayPal had registered them defensively. That's why brand-protection registrars now count as "probably owned".
- Parked domains were getting points for the parking company's web and mail servers.

After the fixes, the same data gives 2 critical and 12 high instead of 43 and 78. The top ones were worth a human look.

## Limitations

- Registered does not mean malicious. Plenty of lookalikes are owned by the brand, parked, or just someone's unrelated project. The score is there to help you prioritise, not to give a verdict.
- Ownership detection is heuristic. A brand's country sites (like `paypal.cn`) can use completely different DNS and mail and still be legitimate. Add those with `--allow`.
- crt.sh is free and often slow. Big brands can time out, so the tool retries with backoff.
- The homoglyph list covers the common cases, not all of Unicode's confusables.
- There's no WHOIS/RDAP lookup yet, so domain age isn't part of the score. Newly registered domains are a strong signal, and that's the next thing I'd add.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .

cd extension && npm test     # extension unit tests (Node 20+, no dependencies)
```

The tests don't need internet access. DNS and crt.sh are faked, and one test file spins up a small DNS server on localhost to check the real dnspython parsing.

`tests/test_extension_e2e.py` loads the extension into a real Chromium and visits fake sites. It's skipped unless Playwright is installed (`pip install playwright && playwright install chromium`).

## Responsible use

This only reads public DNS and certificate data, but please use it to protect domains you own or are authorised to monitor.

## License

MIT
