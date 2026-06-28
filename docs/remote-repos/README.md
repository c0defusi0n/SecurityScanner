# Remote data repos for C0defusi0n SecurityScanner

The module can consume **two independent JSON documents** over HTTPS, each behind a
**configurable admin URL** (so you can fork these repos and point the module at your own copy).
Both are optional and **off by default** — the module works fully without them.

| Feature | Admin config | Sample file |
|---|---|---|
| Remote signature DB (extra regex patterns) | *Stores ▸ Configuration ▸ C0DEFUSI0N ▸ Security Scanner ▸ Remote Signatures* | [`signatures.sample.json`](signatures.sample.json) |
| Magento vulnerability watch feed | *…▸ Vulnerability Feed* | [`feed.sample.json`](feed.sample.json) |

## How the module consumes them

- **HTTPS only.** Use a raw, non-redirecting URL, e.g.
  `https://raw.githubusercontent.com/<you>/<repo>/main/signatures.json`.
- **Cached as flat dated files** under `var/securityscanner/`. A conditional `GET`
  (`ETag` / `If-Modified-Since`) means the body is **not re-downloaded while it has not changed**;
  an admin interval throttles how often the network is touched at all.
- **Fail-safe.** Unreachable source / non-2xx / invalid JSON → the module falls back to the last
  good cached copy, then to the built-in baseline. A scan never breaks because a repo is down.
- **Treated as data, never code.** Every regex is validated (must compile) before use; oversized
  documents are rejected; the on-disk filename never uses any value from the document.

## 1. Signature DB (`signatures.json`)

These patterns are **merged on top of** the module's built-in patterns (and the admin custom
patterns). Put only **new/extra** detections here — you do not need to copy the baseline.

```json
{
  "version": "2026-06-27",
  "patterns": [
    { "id": "magecart-atob-fetch", "severity": "critical",
      "regex": "/atob\\s*\\([^)]*\\)[^;]*fetch\\s*\\(/is",
      "description": "Base64 payload piped into fetch() — Magecart exfil" }
  ]
}
```

- `regex` is a **full PCRE** with delimiters and flags (`/.../i`). In JSON, backslashes must be
  doubled (`\\s`, `\\(`). An invalid pattern is logged and skipped — it cannot break the scan.
- Ship a new detection store-wide by committing here; **no module release needed**.

## 2. Vulnerability feed (`feed.json`)

The latest Magento / Adobe Commerce security items, shown in the admin as a **system-message bar**
at the top of every page and pushed into the **notification inbox** (the bell).

```json
{
  "updated": "2026-06-27T08:00:00Z",
  "items": [
    { "id": "APSB25-94", "severity": "critical",
      "title": "Adobe Commerce — unrestricted file upload (PolyShell)",
      "published": "2025-XX-XX",
      "url": "https://helpx.adobe.com/security/products/magento/apsb25-94.html",
      "summary": "Crafted upload → RCE. Apply the isolated patch." }
  ]
}
```

- `severity` ∈ `critical|high|medium|low` (defaults to `medium`). `url` must be http(s) or it is
  dropped. `id` dedupes inbox notices — keep it stable per vulnerability (use the APSB/CVE id).
- **Always include the authoritative `url`.** If this feed is AI-generated, the link lets an admin
  verify the summary; the module never presents AI text as authoritative on its own.

### Auto-generating the feed

The module does not care how `feed.json` is produced. A typical setup is a **scheduled job**
(GitHub Action or a scheduled Claude Code routine) that aggregates Adobe APSB + NVD/CVE + Sansec,
asks an LLM to extract the latest Magento items into the shape above, and commits the file. Pick a
cadence (e.g. hourly); the module refreshes its cache on its own interval and shows the latest.
