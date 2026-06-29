# Changelog

All notable changes to **C0defusi0n SecurityScanner**. Each version ships as a git tag
(`vX.Y.Z`) plus a GitHub Release whose notes are the matching section below.

---

## v1.4.0 — Remote signatures & Magento vulnerability feed (2026-06-29)

> Rolls up the v1.3.0 security hardening listed below — 1.3.0 was not released separately, so 1.4.0
> is the first published build since 1.2.0. The two data sources are **optional and OFF by default**
> — nothing changes until you enable them and set a URL.

### Added — Remote signature database ("antivirus definitions" model)
- Fetch an **extra regex database** from an admin-configured **HTTPS JSON URL** before each scan.
  Patterns are **merged on top of** the built-in baseline and the admin custom patterns — they
  never replace them, so detection keeps working offline and a guaranteed baseline always ships.
- **Update detection without releasing the module**: push to the signatures repo and the next
  scan picks it up.
- Cached as a **flat, date-stamped file** under `var/securityscanner/`. A **conditional GET**
  (`ETag` / `If-Modified-Since`) means the body is **not re-downloaded while it has not changed**;
  an admin **update interval** throttles how often the network is touched.
- **Fail-safe**: unreachable source / non-2xx / invalid JSON falls back to the last good cache,
  then to the built-in baseline. A scan never breaks because the repo is down.
- **Hardened**: HTTPS-only, every remote regex is compile-validated before use, body size is
  capped, the on-disk filename never uses remote-controlled content, and the number of merged
  patterns is capped (1000).

### Added — Magento vulnerability feed in the admin
- Show the latest Magento / Adobe Commerce vulnerabilities from an admin-configured **HTTPS JSON
  feed**, rendered as the **system-message bar at the top of the admin** (next to the native
  system notifications) and pushed into the **notification inbox** (the bell), de-duplicated by id.
- Refreshed by a new **hourly cron**; admin pages read the cache only, so rendering never blocks
  on the network. All feed content is **escaped on output** (untrusted / possibly AI-generated)
  and every item links its **authoritative source** (APSB/CVE URL) for verification.
- The feed is produced **out-of-band** (e.g. a scheduled AI job aggregating Adobe APSB / NVD /
  Sansec). The module only **consumes** it — the producer is fully swappable.

### Changed — AI scanner efficiency
- The optional AI scanner is now only queried for items the **regex did not already flag** (A),
  content with **no markup or code-like tokens** is pre-filtered out before any request (B), and
  every verdict is **cached by content hash** (model + prompt + content) so unchanged content is
  never re-sent (C). Big win on repeat scans, especially against a one-request-at-a-time local model.
  Same findings, far fewer LLM round-trips. The cache uses the app cache (re-warms after `cache:flush`).

### Added — Configuration & scaffolding
- New config groups under *Stores ▸ Configuration ▸ C0DEFUSI0N ▸ Security Scanner*:
  **Remote Signatures** (enable / URL / update interval) and **Magento Vulnerability Feed**
  (enable / URL / update interval / max items). Both URLs are configurable, so you can **fork**
  the data repos and point the module at your own copy.
- New cron `c0defusi0n_security_scanner_feed` (hourly).
- Sample repo files and format spec in [`docs/remote-repos/`](docs/remote-repos/)
  (`signatures.sample.json`, `feed.sample.json`, `README.md`).
- French translations for the new labels; standalone parsing/validation tests in
  `Test/remote_test.php`.

### Notes
- Reviewed for security + Magento integration (SSRF, path traversal, XSS, supply-chain, DoS, and
  API correctness). No fatal/no-op issues; the low-severity findings (pattern-count cap, log
  sanitization, notify/display decoupling) were fixed before release.
- **Setup**: create the two repos from the samples, set the two raw URLs in admin, enable the
  features, then run `bin/magento c0defusi0n:security:scan` and `bin/magento cron:run` to verify.

---

## v1.3.0 — Security hardening (2026-06-27)

Hardens the scanner's own code against injection, SSRF and detection-evasion, and makes alert
delivery more reliable. No configuration changes required; existing settings are preserved.

### Security fixes
- **Alert e-mail HTML injection** — CMS block/page titles, identifiers and media file paths are
  now HTML-escaped before being rendered in the alert e-mail (`{{var details|raw}}`), so a crafted
  CMS title can no longer inject markup into the report read by an admin.
- **Detection evasion via the regex engine** — when a pattern makes PCRE hit its
  backtrack/recursion limit, the content is now flagged as suspicious instead of being silently
  skipped, closing an evasion path for crafted payloads.
- **Telegram & chat injection** — finding fields are escaped for Telegram Markdown, and Discord
  `@everyone`/`@here` mentions are disabled in webhook payloads.
- **Webhook SSRF hardening** — the webhook URL scheme is validated server-side (http/https only),
  and untrusted remote response bodies are no longer written to the logs.

### Reliability
- **No more lost alerts** — a finding is marked "already alerted" only after a notification
  actually goes out. If every enabled channel fails (mail/Telegram/webhook outage), the finding is
  retried on the next scan instead of being silenced forever. The in-admin notification is
  unchanged.

### Hardening
- Scanned content is capped (2 MB) to prevent an oversized CMS value from exhausting memory.
- AI endpoint error responses are length-capped and stripped of control characters before logging.

---

## v1.2.0 — Optional AI scanner

- Added an optional AI scanner: a configurable, hardened prompt sends scanned content to an
  OpenAI-compatible endpoint for a second opinion alongside the regex patterns.

## v1.1.0 — Security hardening, PolyShell detection and notifications

- Added PolyShell (APSB25-94) detection, the generic webhook channel, wider scan coverage, alert
  de-duplication and an ignore-list; encrypted the Telegram token.

## v1.0.0 — Initial release

- Initial security scanner: regex detection across CMS blocks, e-mail and Telegram notifications.

---

## Tagging & releases

Conventions: tags are `vX.Y.Z`; the tag subject is `vX.Y.Z — <short description>`; the GitHub
Release body is the matching section above. Remote `origin` pushes through the `gh-security` SSH
alias.

### v1.3.0 (commit already on `main`)
```bash
git tag -a v1.3.0 -m "v1.3.0 — Security hardening: injection, SSRF and detection-evasion fixes"
git push origin v1.3.0
gh release create v1.3.0 --title "v1.3.0 — Security hardening" \
  --notes "$(awk '/^## v1.3.0/{f=1} /^## v1.2.0/{f=0} f' CHANGELOG.md)"
```

### v1.4.0 (after committing the feature + bumping composer.json to 1.4.0)
```bash
git tag -a v1.4.0 -m "v1.4.0 — Remote signature DB + Magento vulnerability feed"
git push origin v1.4.0
gh release create v1.4.0 --title "v1.4.0 — Remote signatures & vulnerability feed" \
  --notes "$(awk '/^## v1.4.0/{f=1} /^## v1.3.0/{f=0} f' CHANGELOG.md)"
```
