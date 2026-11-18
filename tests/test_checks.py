import os
import tempfile
import unittest

from headersentinel.checks import analyze, grade_from_score
from headersentinel.scanner import parse_headers_file

HARDENED = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
}


class TestGrading(unittest.TestCase):
    def test_hardened_is_grade_a(self):
        r = analyze(HARDENED)
        self.assertEqual(r["grade"], "A")
        self.assertEqual(r["score"], 100)
        self.assertEqual(r["summary"]["missing"], 0)

    def test_empty_is_grade_f(self):
        r = analyze({})
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["grade"], "F")
        self.assertEqual(r["summary"]["missing"], 9)

    def test_case_insensitive_headers(self):
        lowered = {k.lower(): v for k, v in HARDENED.items()}
        self.assertEqual(analyze(lowered)["score"], 100)

    def test_hsts_low_max_age_warns(self):
        h = dict(HARDENED)
        h["Strict-Transport-Security"] = "max-age=3600"
        r = analyze(h)
        hsts = next(c for c in r["checks"] if c["name"] == "strict-transport-security")
        self.assertEqual(hsts["status"], "warn")
        self.assertLess(r["score"], 100)

    def test_csp_unsafe_inline_warns(self):
        h = dict(HARDENED)
        h["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline'"
        csp = next(c for c in analyze(h)["checks"] if c["name"] == "content-security-policy")
        self.assertEqual(csp["status"], "warn")

    def test_nosniff_wrong_value(self):
        h = dict(HARDENED)
        h["X-Content-Type-Options"] = "sniff"
        chk = next(c for c in analyze(h)["checks"] if c["name"] == "x-content-type-options")
        self.assertEqual(chk["status"], "warn")

    def test_info_leak_detected(self):
        h = dict(HARDENED)
        h["Server"] = "Apache/2.4.49"
        h["X-Powered-By"] = "PHP/8.1.0"
        leaks = analyze(h)["info_leaks"]
        names = {l["header"] for l in leaks}
        self.assertIn("server", names)
        self.assertIn("x-powered-by", names)

    def test_cookie_flags(self):
        r = analyze(HARDENED, cookies=["sid=abc; Path=/"])
        self.assertEqual(len(r["cookies"]), 1)
        self.assertIn("missing Secure", r["cookies"][0]["issues"])
        self.assertIn("missing HttpOnly", r["cookies"][0]["issues"])
        self.assertIn("missing SameSite", r["cookies"][0]["issues"])

    def test_secure_cookie_no_findings(self):
        r = analyze(HARDENED, cookies=["sid=abc; Secure; HttpOnly; SameSite=Strict"])
        self.assertEqual(r["cookies"], [])

    def test_grade_boundaries(self):
        self.assertEqual(grade_from_score(90), "A")
        self.assertEqual(grade_from_score(89), "B")
        self.assertEqual(grade_from_score(70), "C")
        self.assertEqual(grade_from_score(59), "F")


class TestHeadersFile(unittest.TestCase):
    def test_parse_headers_file(self):
        content = (
            "HTTP/2 200\n"
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
            "Set-Cookie: a=1; Secure; HttpOnly; SameSite=Lax\n"
        )
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
            data = parse_headers_file(path)
            self.assertEqual(data["status"], 200)
            self.assertIn("Strict-Transport-Security", data["headers"])
            self.assertEqual(len(data["cookies"]), 1)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
