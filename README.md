# lookalike-watch

Finds registered domains that imitate yours (`paypa1.com`, `pаypal.com` with a Cyrillic "а", `paypal-login.com`) and keeps watching for new ones.

Most phishing starts with a domain that looks right at a glance. Brands usually find out about these after customers have already been hit. This tool tries to close that gap using only public data: DNS and Certificate Transparency logs.

## What it does

1. **Generates lookalikes** of a domain using 12 techniques (typos, homoglyphs, bit flips, TLD swaps, brand + keyword combos...).
2. **Checks which ones exist** with parallel DNS lookups (NS, A/AAAA, MX).
3. **Searches Certificate Transparency logs** (via [crt.sh](https://crt.sh)) for any certificate with the brand name in it. This catches things like `paypal-account-review.com` that no typo generator would ever come up with.
4. **Scores each registered domain 0-100** and lists the reasons behind the score.
5. **Watch mode** re-scans on a schedule and posts *new* findings to Slack or Discord.

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
20     low       paypal.net                      tld-swap    uses the same nameservers as paypal.com, probably owned by the brand
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
| Within a few edits of the brand (scaled by similarity) | up to +40 |
| Contains the brand name | +25 |
| Contains a phishing word (login, verify, account...) | +15 |
| Can receive email (MX records) | +15 |
| Live web host (A/AAAA records) | +10 |
| Internationalised (punycode) domain | +10 |
| Has a certificate in CT logs | +10 |
| Registered | +5 |
| Parked (nameservers belong to a parking company) | -10 |
| Uses the same nameservers as the real domain (probably the brand's own) | -40 |

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
- Lookups that time out are counted and reported at the end rather than silently treated as "not registered".

## Limitations

- Registered does not mean malicious. Plenty of lookalikes are owned by the brand, parked, or just someone's unrelated project. The score is there to help you prioritise, not to give a verdict.
- The nameserver check only catches defensive registrations that share DNS with the main domain.
- crt.sh is free and often slow. Big brands can time out, so the tool retries with backoff.
- The homoglyph list covers the common cases, not all of Unicode's confusables.
- There's no WHOIS/RDAP lookup yet, so domain age isn't part of the score. Newly registered domains are a strong signal, and that's the next thing I'd add.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

The tests don't need internet access. DNS and crt.sh are faked, and one test file spins up a small DNS server on localhost to check the real dnspython parsing.

## Responsible use

This only reads public DNS and certificate data, but please use it to protect domains you own or are authorised to monitor.

## License

MIT
