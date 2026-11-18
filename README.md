# header-sentinel

> A zero-dependency **HTTP security-headers auditor**. Point it at a URL (or a captured response) and get a clear **A–F grade**, a per-header breakdown, cookie-flag and information-disclosure findings, and exportable JSON / Markdown / HTML reports — ready to drop into CI.

[![License: MIT](https://img.shields.io/badge/License-MIT-informational.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.8%2B-3776ab)
![Dependencies](https://img.shields.io/badge/dependencies-none%20(stdlib)-brightgreen)
![Tests](https://img.shields.io/badge/tests-11%2F11%20passing-brightgreen)

## Why

Missing security headers are one of the most common — and most *fixable* — findings in any web security review. `header-sentinel` turns that check into a fast, repeatable, scriptable audit any company can run against its own sites, in a terminal or in a pipeline. It grew out of hands-on **security testing & remediation** work.

It is **pure Python standard library** — no `pip install`, nothing to vendor, easy to audit.

## What it checks

| Header | Weight | Notes |
|--------|:------:|-------|
| `Strict-Transport-Security` | 20 | rewards strong `max-age` + `includeSubDomains` |
| `Content-Security-Policy` | 20 | flags `unsafe-inline` / `unsafe-eval` |
| `X-Content-Type-Options` | 10 | expects `nosniff` |
| `X-Frame-Options` | 10 | `DENY` / `SAMEORIGIN` |
| `Referrer-Policy` | 10 | flags `unsafe-url` |
| `Permissions-Policy` | 10 | presence |
| `Cross-Origin-Opener-Policy` | 8 | `same-origin` |
| `Cross-Origin-Resource-Policy` | 7 | `same-origin` / `same-site` |
| `Cross-Origin-Embedder-Policy` | 5 | `require-corp` |

Plus, as findings (not scored): **information-disclosure** headers (`Server`, `X-Powered-By`, …) and **cookie flags** (`Secure`, `HttpOnly`, `SameSite`).

Score → grade: **A** ≥ 90, **B** ≥ 80, **C** ≥ 70, **D** ≥ 60, **F** < 60.

## Usage

```bash
# scan a live site
python -m headersentinel https://example.com

# audit a captured response offline (e.g. from `curl -I`)
python -m headersentinel --headers-file examples/weak-headers.txt

# export reports
python -m headersentinel example.com --md report.md --html report.html

# machine-readable
python -m headersentinel example.com --json

# CI gate: fail the build if the score is below a threshold
python -m headersentinel https://example.com --fail-under 70
```

Handy flags: `--insecure` (skip TLS verification), `--timeout`, `--no-color`, `--version`.

## Sample output

```
  Security headers report  -  examples/weak-headers.txt
  Score: 0/100   Grade: F
  (0 ok, 0 warnings, 9 missing)

  [x] strict-transport-security         0.0/20   Missing HSTS: connections can be downgraded to HTTP.
  [x] content-security-policy           0.0/20   No Content-Security-Policy: weak defense against XSS/injection.
  ...
  Information disclosure:
    - server: Apache/2.4.49 (Unix)
    - x-powered-by: PHP/7.4.3
  Cookie flags:
    - PHPSESSID: missing Secure, missing HttpOnly, missing SameSite
```

## Install (optional)

Runs straight from the repo with no install. To get a `header-sentinel` command on your PATH:

```bash
pip install .
header-sentinel https://example.com
```

## Testing

```bash
python -m unittest discover -s tests -v
# Ran 11 tests ... OK
```
The grading logic is a pure function of the headers, so it is tested entirely offline.

## Project structure

```
header-sentinel/
├── headersentinel/
│   ├── checks.py     # pure grading logic (the testable core)
│   ├── scanner.py    # fetch over HTTP(S) / parse a saved headers file
│   ├── report.py     # terminal / JSON / Markdown / HTML
│   └── __main__.py   # CLI
├── tests/test_checks.py
├── examples/         # sample header captures
└── pyproject.toml
```

---

<sub>Author: **Davide Alovisio** — Full-Stack Developer & IT / Security · [portfolio](https://davidealovisioportfolio.com) · [GitHub](https://github.com/DavideAlovisio13)</sub>
