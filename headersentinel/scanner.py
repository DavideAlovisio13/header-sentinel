"""Network layer: fetch a URL's response headers (stdlib only)."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from typing import Optional

USER_AGENT = "header-sentinel/1.0 (+https://github.com/DavideAlovisio13)"


class FetchError(Exception):
    pass


def fetch_headers(url: str, timeout: float = 10.0, insecure: bool = False) -> dict:
    """
    Perform a GET and return:
      { 'url', 'final_url', 'status', 'headers': {name: value}, 'cookies': [raw,...] }
    Raises FetchError on failure.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return _collect(url, resp)
    except urllib.error.HTTPError as e:
        # An HTTP error response still carries headers worth auditing.
        return _collect(url, e)
    except urllib.error.URLError as e:
        raise FetchError(f"Could not reach {url}: {e.reason}") from e
    except (ValueError, OSError) as e:
        raise FetchError(f"Could not reach {url}: {e}") from e


def _collect(url: str, resp) -> dict:
    headers = {k: v for k, v in resp.headers.items()}
    try:
        cookies = resp.headers.get_all("Set-Cookie") or []
    except Exception:
        cookies = []
    return {
        "url": url,
        "final_url": resp.geturl() if hasattr(resp, "geturl") else url,
        "status": getattr(resp, "status", getattr(resp, "code", 0)),
        "headers": headers,
        "cookies": cookies,
    }


def parse_headers_file(path: str) -> dict:
    """
    Parse a saved raw-headers file (e.g. 'curl -I' output or 'Name: value' lines)
    so the tool can audit captured responses offline.
    """
    headers: dict = {}
    cookies: list = []
    status = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            if line.upper().startswith("HTTP/"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    status = int(parts[1])
                continue
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            name = name.strip()
            value = value.strip()
            if name.lower() == "set-cookie":
                cookies.append(value)
            else:
                headers[name] = value
    return {"url": path, "final_url": path, "status": status, "headers": headers, "cookies": cookies}
