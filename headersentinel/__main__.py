"""
header-sentinel CLI.

Examples:
  python -m headersentinel https://example.com
  python -m headersentinel example.com --md report.md --html report.html
  python -m headersentinel --headers-file captured.txt --json
  python -m headersentinel https://example.com --fail-under 70   # CI gate
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .checks import analyze
from .report import render_terminal, to_html, to_json, to_markdown
from .scanner import FetchError, fetch_headers, parse_headers_file


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="header-sentinel",
        description="Audit a website's HTTP security headers and grade them A-F.",
    )
    p.add_argument("url", nargs="?", help="Target URL (https:// assumed if omitted)")
    p.add_argument("--headers-file", help="Audit headers from a saved file instead of fetching")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument("--md", metavar="FILE", help="Write a Markdown report to FILE")
    p.add_argument("--html", metavar="FILE", help="Write an HTML report to FILE")
    p.add_argument("--timeout", type=float, default=10.0, help="Fetch timeout (s)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("--fail-under", type=int, metavar="N", help="Exit non-zero if score < N (for CI)")
    p.add_argument("--version", action="version", version=f"header-sentinel {__version__}")
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.url and not args.headers_file:
        build_parser().error("provide a URL or --headers-file")

    try:
        if args.headers_file:
            data = parse_headers_file(args.headers_file)
        else:
            data = fetch_headers(args.url, timeout=args.timeout, insecure=args.insecure)
    except FetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    target = data.get("final_url") or data.get("url") or "(input)"
    result = analyze(data["headers"], data.get("cookies"))

    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(result, target))
        print(f"Markdown report written to {args.md}", file=sys.stderr)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(result, target))
        print(f"HTML report written to {args.html}", file=sys.stderr)

    if args.json:
        print(to_json(result, target))
    else:
        print(render_terminal(result, target, color=not args.no_color))

    if args.fail_under is not None and result["score"] < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
