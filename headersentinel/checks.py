"""
Pure, dependency-free grading logic for HTTP security headers.

`analyze()` takes a dict of response headers (and optional Set-Cookie list) and
returns a structured verdict with a 0-100 score and an A-F grade. It performs no
network I/O, which keeps it fully unit-testable.
"""

from __future__ import annotations

from typing import Callable, Optional

# status values
OK = "ok"
WARN = "warn"
MISSING = "missing"


class CheckResult:
    def __init__(self, name: str, status: str, points: float, maximum: float, note: str):
        self.name = name
        self.status = status
        self.points = points
        self.maximum = maximum
        self.note = note

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "points": round(self.points, 1),
            "max": self.maximum,
            "note": self.note,
        }


def _lower_keys(headers: dict) -> dict:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ----------------------------------------------------------------- per-header rules

def _hsts(v: Optional[str]) -> tuple:
    if not v:
        return MISSING, 0.0, "Missing HSTS: connections can be downgraded to HTTP."
    max_age = 0
    for part in v.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                max_age = 0
    if max_age < 15552000:  # 180 days
        return WARN, 0.6, f"HSTS present but max-age is low ({max_age}s); use >= 15552000."
    if "includesubdomains" not in v.lower():
        return WARN, 0.8, "HSTS present; consider adding includeSubDomains."
    return OK, 1.0, "Strong HSTS."


def _csp(v: Optional[str]) -> tuple:
    if not v:
        return MISSING, 0.0, "No Content-Security-Policy: weak defense against XSS/injection."
    low = v.lower()
    if "unsafe-inline" in low or "unsafe-eval" in low:
        return WARN, 0.6, "CSP present but allows 'unsafe-inline'/'unsafe-eval'."
    return OK, 1.0, "Content-Security-Policy present."


def _nosniff(v: Optional[str]) -> tuple:
    if not v:
        return MISSING, 0.0, "Missing X-Content-Type-Options: add 'nosniff'."
    if v.strip().lower() == "nosniff":
        return OK, 1.0, "nosniff set."
    return WARN, 0.5, f"Unexpected value '{v}'; should be 'nosniff'."


def _frame(v: Optional[str]) -> tuple:
    if not v:
        return MISSING, 0.0, "Missing X-Frame-Options (clickjacking); use DENY/SAMEORIGIN or CSP frame-ancestors."
    if v.strip().upper() in ("DENY", "SAMEORIGIN"):
        return OK, 1.0, f"{v.strip().upper()} set."
    return WARN, 0.5, f"Unusual value '{v}'."


def _referrer(v: Optional[str]) -> tuple:
    if not v:
        return MISSING, 0.0, "Missing Referrer-Policy: referrers may leak to third parties."
    safe = {
        "no-referrer", "no-referrer-when-downgrade", "same-origin",
        "strict-origin", "strict-origin-when-cross-origin",
    }
    val = v.strip().lower()
    if "unsafe-url" in val:
        return WARN, 0.3, "Referrer-Policy is 'unsafe-url' (leaks full URL)."
    if any(s in val for s in safe):
        return OK, 1.0, "Safe Referrer-Policy."
    return WARN, 0.6, f"Referrer-Policy '{v}' is permissive."


def _permissions(v: Optional[str]) -> tuple:
    if not v:
        return MISSING, 0.0, "Missing Permissions-Policy: browser features not restricted."
    return OK, 1.0, "Permissions-Policy present."


def _coop(v: Optional[str]) -> tuple:
    if not v:
        return MISSING, 0.0, "Missing Cross-Origin-Opener-Policy."
    if v.strip().lower() == "same-origin":
        return OK, 1.0, "COOP same-origin."
    return WARN, 0.6, f"COOP '{v}' weaker than same-origin."


def _corp(v: Optional[str]) -> tuple:
    if not v:
        return MISSING, 0.0, "Missing Cross-Origin-Resource-Policy."
    if v.strip().lower() in ("same-origin", "same-site"):
        return OK, 1.0, f"CORP {v.strip().lower()}."
    return WARN, 0.6, f"CORP '{v}' is permissive."


def _coep(v: Optional[str]) -> tuple:
    if not v:
        return MISSING, 0.0, "Missing Cross-Origin-Embedder-Policy (optional but hardening)."
    if v.strip().lower() == "require-corp":
        return OK, 1.0, "COEP require-corp."
    return WARN, 0.6, f"COEP '{v}'."


# header, weight, rule
_CHECKS: list[tuple[str, float, Callable[[Optional[str]], tuple]]] = [
    ("strict-transport-security", 20, _hsts),
    ("content-security-policy", 20, _csp),
    ("x-content-type-options", 10, _nosniff),
    ("x-frame-options", 10, _frame),
    ("referrer-policy", 10, _referrer),
    ("permissions-policy", 10, _permissions),
    ("cross-origin-opener-policy", 8, _coop),
    ("cross-origin-resource-policy", 7, _corp),
    ("cross-origin-embedder-policy", 5, _coep),
]

# Headers that disclose software/versions (reported, not scored).
_INFO_LEAK = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]


def grade_from_score(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def analyze(headers: dict, cookies: Optional[list] = None) -> dict:
    """Analyze headers and return a structured verdict."""
    h = _lower_keys(headers)
    results: list[CheckResult] = []
    earned = 0.0
    total = 0.0

    for name, weight, rule in _CHECKS:
        status, frac, note = rule(h.get(name))
        pts = weight * frac
        earned += pts
        total += weight
        results.append(CheckResult(name, status, pts, weight, note))

    score = round(earned / total * 100) if total else 0

    info_leaks = []
    for name in _INFO_LEAK:
        if name in h and h[name].strip():
            info_leaks.append({"header": name, "value": h[name], "note": "Reveals software/version; consider removing."})

    cookie_findings = _check_cookies(cookies or [])

    return {
        "score": score,
        "grade": grade_from_score(score),
        "max": 100,
        "checks": [r.as_dict() for r in results],
        "info_leaks": info_leaks,
        "cookies": cookie_findings,
        "summary": {
            "ok": sum(1 for r in results if r.status == OK),
            "warn": sum(1 for r in results if r.status == WARN),
            "missing": sum(1 for r in results if r.status == MISSING),
        },
    }


def _check_cookies(set_cookie_values: list) -> list:
    findings = []
    for raw in set_cookie_values:
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        issues = []
        if "secure" not in low:
            issues.append("missing Secure")
        if "httponly" not in low:
            issues.append("missing HttpOnly")
        if "samesite" not in low:
            issues.append("missing SameSite")
        if issues:
            findings.append({"cookie": name, "issues": issues})
    return findings
