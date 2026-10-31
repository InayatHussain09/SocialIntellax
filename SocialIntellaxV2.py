#!/usr/bin/env python3
"""
SOCIALINTELLAX  v2.1.0
OSINT · Attack-Surface Intelligence · Threat Reconnaissance

Author: Inayat Hussain — Red Team Operator, Penetration Tester & Offensive Security Engineer
License: MIT

Single-file build. Only hard dependency: requests. BeautifulSoup and Pillow are
used when present and degrade gracefully when absent.

    pip install requests
    python3 socialintellax.py
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as futures
import csv
import hashlib
import html as htmllib
import ipaddress
import json
import math
import os
import random
import re
import socket
import sys
import threading
import time
import webbrowser
import zipfile
from datetime import datetime, timezone
from urllib.parse import quote_plus, urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Missing dependency: requests\n  pip install requests")
    raise SystemExit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    from PIL import ExifTags, Image
except ImportError:
    Image = None

VERSION = "2.1.0"
AUTHOR = "Inayat Hussain"
ROLE = "Red Team Operator · Penetration Tester · Offensive Security Engineer"
OUTPUT_ROOT = "socialintellax_output"
WIDTH = 78

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
BLUE = "\033[34m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
GREY = "\033[90m"

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
SEV_COLOR = {"info": GREY, "low": BLUE, "medium": YELLOW, "high": RED}

KIND_USERNAME = "username"
KIND_EMAIL = "email"
KIND_DOMAIN = "domain"
KIND_IP = "ip"
KIND_URL = "url"
KIND_FILE = "file"
KIND_ORG = "org"
KIND_UNKNOWN = "unknown"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,40}$")


# --------------------------------------------------------------------------- #
# presentation
# --------------------------------------------------------------------------- #
def _ansi_ok() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.name == "nt":
        try:
            import ctypes

            k32 = ctypes.windll.kernel32
            k32.SetConsoleMode(k32.GetStdHandle(-11), 7)
        except Exception:  # noqa: BLE001
            return False
    return sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1"


COLOR = _ansi_ok()


def c(code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if COLOR else text


def rule(title: str = "") -> None:
    if not title:
        print(c(GREY, "─" * WIDTH))
        return
    print(c(CYAN, f"── {title} ") + c(GREY, "─" * max(0, WIDTH - len(title) - 5)))


def ok(msg: str) -> None:
    print(f"  {c(GREEN, '✓')} {msg}")


def no(msg: str) -> None:
    print(f"  {c(GREY, '✗')} {c(GREY, msg)}")


def info(msg: str) -> None:
    print(f"  {c(BLUE, '·')} {msg}")


def warn(msg: str) -> None:
    print(f"  {c(YELLOW, '!')} {msg}")


def err(msg: str) -> None:
    print(f"  {c(RED, '✗')} {msg}", file=sys.stderr)


def kv(key: str, value: str) -> None:
    print(f"  {c(GREY, key.ljust(22))} {value}")


def live(label: str, value: str = "") -> None:
    """Immediate result line, independent of the findings pipeline."""
    print(f"    {c(GREY, label.ljust(20))} {value}")


# --------------------------------------------------------------------------- #
# model
# --------------------------------------------------------------------------- #
def classify(raw: str):
    raw = raw.strip()
    if not raw:
        return KIND_UNKNOWN, ""
    low = raw.lower()
    if low.startswith(("http://", "https://")):
        return KIND_URL, raw
    if EMAIL_RE.match(raw):
        return KIND_EMAIL, low
    try:
        ipaddress.ip_address(raw)
        return KIND_IP, raw
    except ValueError:
        pass
    if DOMAIN_RE.match(low):
        return KIND_DOMAIN, low
    if os.path.exists(raw):
        return KIND_FILE, raw
    if USERNAME_RE.match(raw):
        return KIND_USERNAME, raw
    return KIND_UNKNOWN, raw


class Finding:
    __slots__ = ("module", "title", "severity", "confidence", "detail", "data", "refs", "created")

    def __init__(self, module, title, severity="info", confidence=80, detail="", data=None, refs=None):
        self.module = module
        self.title = title
        self.severity = severity
        self.confidence = confidence
        self.detail = detail
        self.data = data or {}
        self.refs = refs or []
        self.created = datetime.now(timezone.utc).isoformat(timespec="seconds")

    @property
    def fp(self) -> str:
        blob = f"{self.module}|{self.title}|{self.detail}|{sorted(self.data.items(), key=str)}"
        return hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def weight(self) -> int:
        return SEV_ORDER.get(self.severity, 0)

    def as_dict(self) -> dict:
        return {
            "id": self.fp,
            "module": self.module,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "detail": self.detail,
            "data": self.data,
            "refs": self.refs,
            "created": self.created,
        }


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #
class RateLimiter:
    def __init__(self, per_second: float):
        self.interval = 1.0 / per_second if per_second > 0 else 0.0
        self._last = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            delay = self.interval - (time.monotonic() - self._last.get(host, 0.0))
            if delay > 0:
                time.sleep(delay + random.uniform(0, 0.05))
            self._last[host] = time.monotonic()


class Response:
    __slots__ = ("status_code", "headers", "text", "url")

    def __init__(self, status, headers, text, url):
        self.status_code = status
        self.headers = headers
        self.text = text
        self.url = url

    def json(self):
        return json.loads(self.text or "{}")

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400


UA_POOL = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]


class HttpClient:
    def __init__(self, settings):
        self.settings = settings
        self.limiter = RateLimiter(settings["rate"])
        self.cache = {}
        self.stats = {"ok": 0, "fail": 0, "insecure": 0, "errors": []}
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": random.choice(UA_POOL),
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/json,*/*;q=0.8",
            }
        )
        retry = Retry(
            total=settings["retries"],
            connect=settings["retries"],
            read=settings["retries"],
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD", "POST"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.verify = not settings["insecure"]

    def _fail(self, url: str, exc: Exception) -> None:
        self.stats["fail"] += 1
        if len(self.stats["errors"]) < 25:
            self.stats["errors"].append(f"{urlparse(url).hostname}: {exc.__class__.__name__}")

    def get(self, url, use_cache=True, **kw):
        if not self.settings["cache"]:
            use_cache = False
        if use_cache:
            hit = self.cache.get(url)
            if hit and time.time() - hit[0] < self.settings["cache_ttl"]:
                return Response(hit[1], hit[2], hit[3], url)
        self.limiter.wait(urlparse(url).hostname or "")
        kw.setdefault("timeout", self.settings["timeout"])
        kw.setdefault("headers", {})
        kw["headers"].setdefault("User-Agent", random.choice(UA_POOL))
        try:
            resp = self.session.get(url, **kw)
        except requests.exceptions.SSLError:
            try:
                resp = self.session.get(url, verify=False, **kw)
                self.stats["insecure"] += 1
            except Exception as exc:  # noqa: BLE001
                self._fail(url, exc)
                return Response(0, {}, "", url)
        except Exception as exc:  # noqa: BLE001
            self._fail(url, exc)
            return Response(0, {}, "", url)
        self.stats["ok"] += 1
        wrapped = Response(resp.status_code, dict(resp.headers), resp.text, resp.url)
        if use_cache and wrapped.status_code < 400:
            self.cache[url] = (time.time(), wrapped.status_code, wrapped.headers, wrapped.text)
        return wrapped

    def close(self) -> None:
        self.session.close()


# --------------------------------------------------------------------------- #
# static data
# --------------------------------------------------------------------------- #
SOCIAL_PLATFORMS = {
    "GitHub": ("https://github.com/{u}", True),
    "GitLab": ("https://gitlab.com/{u}", True),
    "Reddit": ("https://www.reddit.com/user/{u}/about.json", True),
    "Keybase": ("https://keybase.io/_/api/1.0/user/lookup.json?username={u}", True),
    "HackerNews": ("https://hacker-news.firebaseio.com/v0/user/{u}.json", True),
    "Dev.to": ("https://dev.to/api/users/by_username?url={u}", True),
    "npm": ("https://registry.npmjs.org/-/user/org.couchdb.user:{u}", True),
    "PyPI": ("https://pypi.org/user/{u}/", False),
    "Telegram": ("https://t.me/{u}", False),
    "Mastodon": ("https://mastodon.social/api/v1/accounts/lookup?acct={u}", True),
    "Bitbucket": ("https://bitbucket.org/{u}/", False),
    "Codeberg": ("https://codeberg.org/{u}", False),
    "Docker Hub": ("https://hub.docker.com/v2/users/{u}/", True),
    "Medium": ("https://medium.com/@{u}", False),
    "Behance": ("https://www.behance.net/{u}", False),
    "Dribbble": ("https://dribbble.com/{u}", False),
    "Kaggle": ("https://www.kaggle.com/{u}", False),
    "HackerOne": ("https://hackerone.com/{u}", False),
    "Bugcrowd": ("https://bugcrowd.com/{u}", False),
    "Instagram": ("https://www.instagram.com/{u}/", False),
    "Pinterest": ("https://www.pinterest.com/{u}/", False),
    "Twitch": ("https://www.twitch.tv/{u}", False),
    "SoundCloud": ("https://soundcloud.com/{u}", False),
    "Vimeo": ("https://vimeo.com/{u}", False),
    "Flickr": ("https://www.flickr.com/people/{u}", False),
    "TikTok": ("https://www.tiktok.com/@{u}", False),
    "X": ("https://x.com/{u}", False),
    "LinkedIn": ("https://www.linkedin.com/in/{u}", False),
    "Pastebin": ("https://pastebin.com/u/{u}", False),
    "TryHackMe": ("https://tryhackme.com/p/{u}", False),
    "HackTheBox": ("https://app.hackthebox.com/profile/{u}", False),
    "CodePen": ("https://codepen.io/{u}", False),
}

SOFT_404 = ("not found", "page not found", "doesn't exist", "no such user", "user not found")

SECURITY_HEADERS = {
    "strict-transport-security": ("high", "HSTS not set — TLS downgrade possible"),
    "content-security-policy": ("medium", "CSP absent — weaker XSS containment"),
    "x-frame-options": ("medium", "Clickjacking protection missing"),
    "x-content-type-options": ("low", "MIME sniffing protection missing"),
    "referrer-policy": ("low", "Referrer policy missing"),
    "permissions-policy": ("low", "Permissions policy missing"),
}

TECH_SIGNATURES = {
    "wp-content": "WordPress", "wordpress": "WordPress", "drupal": "Drupal",
    "joomla": "Joomla", "shopify": "Shopify", "cloudflare": "Cloudflare",
    "_next": "Next.js", "react": "React", "angular": "Angular", "vue": "Vue",
    "nginx": "nginx", "apache": "Apache", "laravel": "Laravel", "django": "Django",
    "graphql": "GraphQL", "swagger": "Swagger",
}

DISCLOSURE = [
    (re.compile(r"Index of /"), "Directory listing enabled"),
    (re.compile(r"<title>\s*Apache2? .*Test Page", re.I), "Apache default page"),
    (re.compile(r"Welcome to nginx", re.I), "nginx default page"),
    (re.compile(r"phpMyAdmin", re.I), "phpMyAdmin exposed"),
    (re.compile(r"Swagger UI", re.I), "Swagger UI exposed"),
    (re.compile(r"Whitelabel Error Page", re.I), "Spring Boot error page"),
]

DORK_SETS = {
    KIND_DOMAIN: {
        "Exposed documents": 'site:{t} (ext:pdf OR ext:xls OR ext:xlsx OR ext:docx OR ext:pptx)',
        "Directory listings": 'site:{t} intitle:"index of"',
        "Config exposure": 'site:{t} (ext:env OR ext:ini OR ext:conf OR ext:yaml OR ext:yml)',
        "Backup archives": 'site:{t} (ext:bak OR ext:zip OR ext:tar OR ext:gz OR ext:sql)',
        "Login portals": 'site:{t} inurl:(login OR signin OR admin OR portal)',
        "Error messages": 'site:{t} intext:("stack trace" OR "SQL syntax")',
        "Password references": 'site:{t} intext:(password OR passwd OR credentials)',
        "Subdomain inventory": "site:*.{t}",
        "Exposed API docs": 'site:{t} (inurl:swagger OR inurl:api-docs OR inurl:graphql)',
    },
    KIND_EMAIL: {
        "Direct references": '"{t}"',
        "Paste dumps": '"{t}" (site:pastebin.com OR site:ghostbin.co OR site:rentry.co)',
        "Code references": '"{t}" site:github.com',
        "Document leaks": '"{t}" (ext:pdf OR ext:xlsx OR ext:csv)',
    },
    KIND_USERNAME: {
        "Profile mentions": '"{t}"',
        "Social presence": '"{t}" (site:twitter.com OR site:instagram.com OR site:facebook.com)',
        "Code presence": '"{t}" site:github.com',
        "Forum presence": '"{t}" (site:reddit.com OR site:stackoverflow.com)',
    },
    KIND_ORG: {
        "Employee profiles": 'site:linkedin.com/in "{t}"',
        "Document exposure": '"{t}" (ext:pdf OR ext:docx OR ext:xlsx)',
        "Job postings": '"{t}" (site:linkedin.com/jobs OR site:indeed.com)',
        "Infrastructure": '"{t}" (inurl:admin OR inurl:vpn OR inurl:portal)',
        "Code footprint": '"{t}" site:github.com',
    },
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy"}
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov", ".top", ".xyz", ".click"}
BRAND_TOKENS = ("google", "microsoft", "apple", "amazon", "paypal", "netflix", "facebook",
                "instagram", "whatsapp", "binance", "metamask", "docusign", "office365")

SERVICE_HINTS = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 110: "pop3",
                 143: "imap", 445: "smb", 1433: "mssql", 2375: "docker-api", 3306: "mysql",
                 3389: "rdp", 5432: "postgres", 5601: "kibana", 6379: "redis",
                 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"}
RISKY_PORTS = {23, 2375, 6379, 9200, 11211, 27017, 445}

BUCKET_SUFFIXES = ("", "-dev", "-prod", "-staging", "-backup", "-assets", "-static",
                   "-media", "-data", "-logs", "-archive", "-public", "-private")

PASTE_HOSTS = ("pastebin.com", "ghostbin.co", "rentry.co", "controlc.com", "paste.ee")

PDF_KEYS = ("Author", "Creator", "Producer", "Title", "CreationDate", "ModDate")
EXIF_TAGS = {271: "Make", 272: "Model", 305: "Software", 306: "DateTime",
             315: "Artist", 33432: "Copyright", 274: "Orientation"}
GPS_TAGS = {1: "GPSLatitudeRef", 2: "GPSLatitude", 3: "GPSLongitudeRef", 4: "GPSLongitude"}


def entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((text.count(ch) / n) * math.log2(text.count(ch) / n) for ch in set(text))


def murmur3_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length, h = len(data), seed
    rounded = length & ~3
    for i in range(0, rounded, 4):
        k = data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    k, tail = 0, length & 3
    if tail == 3:
        k ^= data[rounded + 2] << 16
    if tail >= 2:
        k ^= data[rounded + 1] << 8
    if tail >= 1:
        k ^= data[rounded]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h if h < 2**31 else h - 2**32


# --------------------------------------------------------------------------- #
# application
# --------------------------------------------------------------------------- #
class SocialIntellax:
    def __init__(self):
        self.settings = {
            "timeout": 12.0,
            "retries": 3,
            "rate": 3.0,
            "cache": True,
            "cache_ttl": 900,
            "concurrency": 10,
            "insecure": False,
            "min_severity": "info",
            "allow_active": False,
            "keys": {"hibp": os.environ.get("HIBP_API_KEY", ""),
                     "virustotal": os.environ.get("VT_API_KEY", ""),
                     "github": os.environ.get("GITHUB_TOKEN", "")},
        }
        self.http = HttpClient(self.settings)
        self.findings = []
        self.errors = []
        self.target = ""
        self.kind = KIND_UNKNOWN
        self.workspace = None
        self.raw_dir = None
        self._seen = set()

    # -- output ------------------------------------------------------------ #
    def banner(self) -> None:
        inner = WIDTH - 2
        print()
        print(c(CYAN, "┌" + "─" * inner + "┐"))
        print(c(CYAN, "│") + c(BOLD, " SOCIALINTELLAX".ljust(inner - 1)) + c(CYAN, "│"))
        print(c(CYAN, "│") + c(GREY, f" v{VERSION} · OSINT · ATTACK-SURFACE · THREAT RECON".ljust(inner - 1)) + c(CYAN, "│"))
        print(c(CYAN, "│") + c(GREY, f" {AUTHOR} · {ROLE}"[:inner - 1].ljust(inner - 1)) + c(CYAN, "│"))
        print(c(CYAN, "└" + "─" * inner + "┘"))
        print(c(GREY, "  authorised, lawful reconnaissance only"))

    def emit(self, module, title, severity="info", confidence=80, detail="", data=None, refs=None) -> None:
        if SEV_ORDER.get(severity, 0) < SEV_ORDER[self.settings["min_severity"]]:
            return
        finding = Finding(module, title, severity, confidence, detail, data, refs)
        if finding.fp in self._seen:
            return
        self._seen.add(finding.fp)
        self.findings.append(finding)
        tag = c(SEV_COLOR.get(severity, GREY), severity.upper().ljust(6))
        print(f"  {tag} {c(DIM, module.ljust(18))} {title}")
        if detail:
            print("  " + " " * 31 + c(DIM, detail))
        for ref in finding.refs[:3]:
            print("  " + " " * 31 + c(GREY, ref))

    def note(self, msg: str) -> None:
        info(msg)

    def record_error(self, module: str, exc: Exception) -> None:
        self.errors.append(f"{module}: {exc.__class__.__name__}: {exc}")
        warn(f"{module}: {exc.__class__.__name__}: {exc}")

    # -- workspace --------------------------------------------------------- #
    def open_workspace(self, target: str) -> None:
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:60] or "target"
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.workspace = os.path.join(OUTPUT_ROOT, f"{slug}_{stamp}")
        self.raw_dir = os.path.join(self.workspace, "raw")
        os.makedirs(self.raw_dir, exist_ok=True)

    def write_raw(self, name: str, content: str) -> None:
        if not self.raw_dir:
            return
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80]
        with open(os.path.join(self.raw_dir, safe + ".txt"), "w", encoding="utf-8", errors="replace") as fh:
            fh.write(content)

    def flush_jsonl(self) -> None:
        if not self.workspace:
            return
        with open(os.path.join(self.workspace, "findings.jsonl"), "w", encoding="utf-8") as fh:
            for finding in self.findings:
                fh.write(json.dumps(finding.as_dict()) + "\n")

    # -- reporting --------------------------------------------------------- #
    def export(self, formats=("json", "md", "html")) -> None:
        if not self.workspace:
            warn("no workspace — run a module first")
            return
        ordered = sorted(self.findings, key=lambda f: (-f.weight, f.module, f.title))
        payload = {
            "tool": "socialintellax",
            "version": VERSION,
            "target": self.target,
            "kind": self.kind,
            "generated": datetime.now().isoformat(timespec="seconds"),
            "counts": {s: sum(1 for f in ordered if f.severity == s) for s in SEV_ORDER},
            "http": {"ok": self.http.stats["ok"], "fail": self.http.stats["fail"]},
            "errors": self.errors,
            "findings": [f.as_dict() for f in ordered],
        }
        written = []
        if "json" in formats:
            path = os.path.join(self.workspace, "report.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, default=str)
            written.append(path)
        if "csv" in formats:
            path = os.path.join(self.workspace, "report.csv")
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["severity", "module", "confidence", "title", "detail", "data", "refs"])
                for f in ordered:
                    writer.writerow([f.severity, f.module, f.confidence, f.title,
                                     f.detail, json.dumps(f.data), " ".join(f.refs)])
            written.append(path)
        if "md" in formats:
            path = os.path.join(self.workspace, "report.md")
            lines = [f"# SocialIntellax — {self.target}", "",
                     f"- type: `{self.kind}`", f"- findings: {len(ordered)}",
                     f"- http ok/fail: {self.http.stats['ok']}/{self.http.stats['fail']}", ""]
            if self.errors:
                lines += ["## Module errors", ""] + [f"- {e}" for e in self.errors] + [""]
            lines += ["## Findings", ""]
            for f in ordered:
                lines += [f"### [{f.severity.upper()}] {f.title}",
                          f"- module: `{f.module}` · confidence: {f.confidence}%"]
                if f.detail:
                    lines.append(f"- {f.detail}")
                for key, value in f.data.items():
                    lines.append(f"- `{key}`: {value}")
                for ref in f.refs:
                    lines.append(f"- <{ref}>")
                lines.append("")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
            written.append(path)
        if "html" in formats:
            path = os.path.join(self.workspace, "report.html")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self._html(ordered, payload))
            written.append(path)
        self.flush_jsonl()
        for path in written:
            ok(f"report: {path}")

    def _html(self, ordered, payload) -> str:
        css = """
:root{color-scheme:light}*{box-sizing:border-box}
body{margin:0;font:14px/1.55 ui-monospace,Menlo,monospace;color:#14181f;background:#f7f8fa}
header{background:#0f1419;color:#e6edf3;padding:26px 38px;border-bottom:3px solid #2f81f7}
header h1{margin:0;font-size:18px;letter-spacing:.14em}
header p{margin:6px 0 0;color:#8b949e;font-size:12px}
main{padding:26px 38px;max-width:1100px}
.stats{display:flex;gap:12px;margin-bottom:22px}
.stat{border:1px solid #d8dee4;background:#fff;padding:10px 16px;border-radius:4px}
.stat b{display:block;font-size:19px}
.stat span{color:#57606a;font-size:10px;letter-spacing:.1em;text-transform:uppercase}
h2{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#57606a;
border-bottom:1px solid #d8dee4;padding-bottom:8px;margin-top:30px}
.f{border-left:3px solid #d0d7de;background:#fff;padding:11px 15px;margin:9px 0}
.f.high{border-color:#cf222e}.f.medium{border-color:#bf8700}
.f.low{border-color:#0969da}.f.info{border-color:#8c959f}
.f h3{margin:6px 0 0;font-size:13px}
.sev{font-size:10px;letter-spacing:.1em;padding:2px 6px;color:#fff;border-radius:3px}
.sev.high{background:#cf222e}.sev.medium{background:#bf8700}
.sev.low{background:#0969da}.sev.info{background:#8c959f}
.mod{color:#57606a;font-size:11px;margin-left:8px}
.detail{color:#24292f;margin:7px 0 0}
pre{background:#f6f8fa;border:1px solid #d8dee4;padding:9px;overflow:auto;font-size:12px;border-radius:4px}
a{color:#0969da}
footer{padding:18px 38px;color:#57606a;font-size:11px;border-top:1px solid #d8dee4}
"""
        blocks = []
        for f in ordered:
            data = htmllib.escape(json.dumps(f.data, indent=2, default=str)) if f.data else ""
            refs = " ".join(f'<a href="{htmllib.escape(r)}">{htmllib.escape(r)}</a>' for r in f.refs)
            blocks.append(
                f'<div class="f {f.severity}"><span class="sev {f.severity}">{f.severity.upper()}</span>'
                f'<span class="mod">{htmllib.escape(f.module)} · {f.confidence}%</span>'
                f"<h3>{htmllib.escape(f.title)}</h3>"
                + (f'<p class="detail">{htmllib.escape(f.detail)}</p>' if f.detail else "")
                + (f"<pre>{data}</pre>" if data else "")
                + (f'<p class="detail">{refs}</p>' if refs else "")
                + "</div>"
            )
        counts = payload["counts"]
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SocialIntellax — {htmllib.escape(self.target)}</title><style>{css}</style></head><body>
<header><h1>SOCIALINTELLAX — RECON REPORT</h1>
<p>target {htmllib.escape(self.target)} · type {self.kind} · {payload['generated']}</p></header><main>
<div class="stats"><div class="stat"><b>{len(ordered)}</b><span>findings</span></div>
<div class="stat"><b>{counts['high']}</b><span>high</span></div>
<div class="stat"><b>{counts['medium']}</b><span>medium</span></div>
<div class="stat"><b>{counts['low']}</b><span>low</span></div></div>
<h2>Findings</h2>{''.join(blocks) or '<p>No findings.</p>'}</main>
<footer>SocialIntellax v{VERSION} — {AUTHOR} — MIT</footer></body></html>"""

    # -- preflight --------------------------------------------------------- #
    def preflight(self) -> bool:
        targets = [("api.github.com", "https://api.github.com"),
                   ("cloudflare-dns", "https://cloudflare-dns.com/dns-query?name=example.com&type=A")]
        failures = 0
        for label, url in targets:
            try:
                resp = self.http.session.get(url, timeout=8,
                                             headers={"Accept": "application/dns-json"})
                live(label, f"HTTP {resp.status_code}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                live(label, exc.__class__.__name__)
        if failures == len(targets):
            warn("all outbound checks failed — DNS, proxy or system clock is the likely cause")
            warn("try: python3 socialintellax.py <target> --insecure")
            return False
        return True

    # -- search helper ----------------------------------------------------- #
    ENGINES = (
        ("ddg-lite", "https://lite.duckduckgo.com/lite/?q="),
        ("ddg", "https://html.duckduckgo.com/html/?q="),
        ("bing", "https://www.bing.com/search?q="),
    )

    def search(self, query: str, limit: int = 6) -> list:
        for engine, base in self.ENGINES:
            try:
                resp = self.http.get(base + quote_plus(query),
                                     headers={"Referer": "https://duckduckgo.com/"})
            except Exception:  # noqa: BLE001
                continue
            if not resp.ok or len(resp.text) < 400:
                continue
            results = []
            if BeautifulSoup is not None:
                soup = BeautifulSoup(resp.text, "html.parser")
                if engine.startswith("ddg-lite"):
                    for link in soup.select("a.result-link")[:limit]:
                        href = link.get("href", "")
                        if href.startswith("http"):
                            results.append({"title": link.get_text(" ", strip=True)[:130], "url": href})
                elif engine == "ddg":
                    for link in soup.select("a.result__a")[:limit]:
                        href = link.get("href", "")
                        if href.startswith("http"):
                            results.append({"title": link.get_text(" ", strip=True)[:130], "url": href})
                else:
                    for block in soup.select("li.b_algo")[:limit]:
                        anchor = block.find("a", href=True)
                        if anchor and anchor["href"].startswith("http"):
                            results.append({"title": anchor.get_text(" ", strip=True)[:130],
                                            "url": anchor["href"]})
            else:
                for match in re.finditer(r'href="(https?://[^"]+)"[^>]*>(.{0,140}?)</a>', resp.text):
                    url = match.group(1)
                    if "duckduckgo.com" in url or "bing.com" in url:
                        continue
                    results.append({"title": re.sub(r"<[^>]+>", "", match.group(2))[:130], "url": url})
                    if len(results) >= limit:
                        break
            results = [r for r in results if r["url"].startswith("http")]
            if results:
                return results[:limit]
        return []

    # ===================== modules: identity ============================== #
    def mod_profiles(self, target):
        def probe(platform, url, is_json):
            try:
                resp = self.http.get(url)
            except Exception as exc:  # noqa: BLE001
                return platform, "error", url, exc.__class__.__name__
            if resp.status_code == 0:
                return platform, "error", url, "unreachable"
            if resp.status_code == 404:
                return platform, "absent", url, "404"
            if resp.status_code == 429:
                return platform, "limited", url, "429"
            if resp.status_code >= 400:
                return platform, "unknown", url, f"HTTP {resp.status_code}"
            if is_json and resp.text.strip() in ("", "null", "{}", "[]"):
                return platform, "absent", url, "empty"
            if not is_json and any(m in resp.text[:4000].lower() for m in SOFT_404) \
                    and len(resp.text) < 8000:
                return platform, "absent", url, "soft-404"
            return platform, "present", url, "200"

        hits, absent, problems = [], [], []
        total = len(SOCIAL_PLATFORMS)
        with futures.ThreadPoolExecutor(max_workers=self.settings["concurrency"]) as pool:
            jobs = [pool.submit(probe, p, u.format(u=target), j)
                    for p, (u, j) in SOCIAL_PLATFORMS.items()]
            for job in futures.as_completed(jobs):
                platform, state, url, why = job.result()
                if state == "present":
                    hits.append((platform, url))
                    ok(f"{platform.ljust(14)} {url}")
                elif state == "absent":
                    absent.append(platform)
                    no(f"{platform.ljust(14)} absent")
                else:
                    problems.append(f"{platform}: {why}")
                    warn(f"{platform.ljust(14)} {why}")

        self.emit("identity.profiles", f"{len(hits)}/{total} platform(s) confirmed",
                  "medium" if hits else "info", 75,
                  data={"confirmed": dict(hits), "absent": absent, "problems": problems},
                  refs=[u for _, u in hits],
                  detail="coverage line — always emitted so the report is never empty")
        for platform, url in hits:
            if platform in {"GitHub", "GitLab", "LinkedIn", "HackerOne", "Keybase", "X"}:
                self.emit("identity.profiles", f"High-signal profile: {platform}", "low", 80,
                          refs=[url])
        if not hits:
            self.note("no confirmed profile — see per-platform lines above")

    def mod_github(self, target):
        headers = {"Authorization": f"Bearer {self.settings['keys']['github']}"} \
            if self.settings["keys"]["github"] else {}
        resp = self.http.get(f"https://api.github.com/users/{target}", headers=headers)
        if not resp.ok:
            self.note(f"GitHub HTTP {resp.status_code or 'unreachable'}")
            self.emit("github.account", "GitHub lookup inconclusive", "info", 50,
                      data={"status": resp.status_code})
            return
        data = resp.json()
        for key in ("name", "company", "location", "bio", "public_repos", "followers", "created_at"):
            if data.get(key) not in (None, ""):
                live(key, str(data[key]))
        self.emit("github.account", f"GitHub account: {data.get('login')}", "info", 95,
                  data={k: data.get(k) for k in ("name", "company", "blog", "location", "bio",
                                                 "public_repos", "public_gists", "followers")},
                  refs=[data.get("html_url", "")])
        if data.get("email"):
            self.emit("github.account", "Public email exposed", "medium", 95,
                      data={"email": data["email"]})
        repos = self.http.get(f"https://api.github.com/users/{target}/repos",
                              params={"per_page": 100, "sort": "updated"}, headers=headers)
        if repos.ok:
            items = repos.json()
            for repo in items[:10]:
                live("repo", repo.get("name", ""))
            self.emit("github.account", f"{len(items)} public repositories", "info", 95,
                      data={"languages": sorted({r.get("language") for r in items if r.get("language")}),
                            "recent": [r.get("name") for r in items[:10]]})
        gists = self.http.get(f"https://api.github.com/users/{target}/gists", headers=headers)
        if gists.ok and gists.json():
            for gist in gists.json()[:5]:
                live("gist", gist.get("html_url", ""))
            self.emit("github.account", f"{len(gists.json())} public gist(s)", "low", 90,
                      refs=[g.get("html_url", "") for g in gists.json()[:5]])

    def mod_github_activity(self, target):
        headers = {"Authorization": f"Bearer {self.settings['keys']['github']}"} \
            if self.settings["keys"]["github"] else {}
        resp = self.http.get(f"https://api.github.com/users/{target}/events/public", headers=headers)
        if not resp.ok:
            self.note(f"GitHub HTTP {resp.status_code or 'unreachable'}")
            return
        emails, repos = set(), set()
        for event in resp.json():
            if event.get("repo", {}).get("name"):
                repos.add(event["repo"]["name"])
            for commit in event.get("payload", {}).get("commits", []) or []:
                email = commit.get("author", {}).get("email")
                if email:
                    emails.add(email)
        for email in sorted(emails):
            live("commit email", email)
        if emails:
            self.emit("github.activity", f"{len(emails)} author email(s) in public commits",
                      "medium", 85, data={"emails": sorted(emails)})
        if repos:
            for repo in sorted(repos)[:10]:
                live("repo", repo)
            self.emit("github.activity", f"Activity across {len(repos)} repositories",
                      "info", 80, data={"repos": sorted(repos)[:15]})
        if not emails and not repos:
            self.note("no public activity")

    def mod_reddit(self, target):
        resp = self.http.get(f"https://www.reddit.com/user/{target}/about.json",
                             headers={"User-Agent": "socialintellax/2.1"})
        if resp.status_code != 200:
            self.note(f"Reddit HTTP {resp.status_code or 'unreachable'}")
            return
        try:
            data = resp.json().get("data", {})
        except ValueError:
            self.note("Reddit returned non-JSON")
            return
        if not data or data.get("is_suspended"):
            self.note("account suspended or absent")
            return
        live("link_karma", str(data.get("link_karma")))
        live("comment_karma", str(data.get("comment_karma")))
        self.emit("identity.reddit", f"Reddit account u/{data.get('name')}", "low", 90,
                  data={"link_karma": data.get("link_karma"),
                        "comment_karma": data.get("comment_karma"),
                        "created": data.get("created_utc")},
                  refs=[f"https://reddit.com/user/{target}"])

    def mod_telegram(self, target):
        resp = self.http.get(f"https://t.me/{target}")
        if resp.ok and "tgme_page_title" in resp.text:
            ok(f"https://t.me/{target}")
            self.emit("identity.telegram", "Telegram handle exists", "low", 85,
                      refs=[f"https://t.me/{target}"])
        else:
            self.note("no Telegram handle")

    def mod_keybase(self, target):
        resp = self.http.get("https://keybase.io/_/api/1.0/user/lookup.json",
                             params={"username": target, "fields": "basics,proofs_summary"})
        if not resp.ok:
            self.note(f"Keybase HTTP {resp.status_code or 'unreachable'}")
            return
        try:
            them = resp.json().get("them")
        except ValueError:
            return
        if not them:
            self.note("no Keybase account")
            return
        proofs = them.get("proofs_summary", {}).get("all", [])
        for proof in proofs:
            live(proof.get("proof_type", "?"), str(proof.get("nametag", "")))
        self.emit("identity.keybase", "Keybase identity with cryptographic proofs", "medium", 95,
                  data={"proofs": [f"{p.get('proof_type')}:{p.get('nametag')}" for p in proofs]},
                  refs=[f"https://keybase.io/{target}"])

    # ===================== modules: email ================================= #
    def mod_email(self, target):
        local, _, domain = target.partition("@")
        live("local part", local)
        live("domain", domain)
        variants = self._variants(local, domain)
        for variant in variants:
            live("variant", variant)
        self.emit("email.lookup", "Address decomposed", "info", 99,
                  data={"local": local, "domain": domain, "variants": variants})
        digest = hashlib.md5(target.lower().encode()).hexdigest()
        grav = self.http.get(f"https://www.gravatar.com/avatar/{digest}?d=404")
        if grav.ok:
            live("gravatar", f"https://gravatar.com/{digest}")
            self.emit("email.gravatar", "Gravatar profile exists", "low", 90,
                      data={"hash": digest}, refs=[f"https://gravatar.com/{digest}"])
        else:
            self.note("no Gravatar profile")
        mx = self._dns(domain, "MX")
        for host in mx:
            live("mx", host)
        if mx:
            self.emit("email.lookup", f"{len(mx)} MX host(s)", "info", 95, data={"mx": mx})
        else:
            self.emit("email.lookup", "No MX — domain cannot receive mail", "low", 85)
        self._dork_run(target, KIND_EMAIL)

    def _variants(self, local, domain):
        parts = [p for p in re.split(r"[._-]", local) if p]
        if len(parts) < 2:
            return [f"{local}@{domain}"]
        first, last = parts[0], parts[-1]
        return sorted({
            f"{first}.{last}@{domain}", f"{first}{last}@{domain}", f"{first[0]}{last}@{domain}",
            f"{first}_{last}@{domain}", f"{last}.{first}@{domain}", f"{first}@{domain}",
            f"{last}@{domain}", f"{first}{last[0]}@{domain}",
        })

    def mod_breaches(self, target):
        key = self.settings["keys"]["hibp"]
        if not key:
            warn("no HIBP key — set one in Settings (menu 32)")
            return
        resp = self.http.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": key, "User-Agent": "socialintellax"}, use_cache=False)
        if resp.status_code == 404:
            self.note("no breaches recorded")
            self.emit("email.breaches", "No breach exposure recorded", "info", 90)
            return
        if not resp.ok:
            self.note(f"HIBP HTTP {resp.status_code or 'unreachable'}")
            return
        records = resp.json()
        for record in records:
            live("breach", f"{record.get('Name')} ({record.get('BreachDate')})")
        self.emit("email.breaches", f"Appears in {len(records)} breach(es)", "high", 95,
                  data={"breaches": [r.get("Name") for r in records]})
        withpw = [r for r in records if any("password" in d.lower() for d in r.get("DataClasses", []))]
        if withpw:
            self.emit("email.breaches", f"{len(withpw)} breach(es) include password material",
                      "high", 90, data={"breaches": [r.get("Name") for r in withpw]})

    # ===================== modules: domain ================================ #
    def _dns(self, name, rtype):
        for resolver in ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"):
            try:
                resp = self.http.get(resolver, params={"name": name, "type": rtype},
                                     headers={"Accept": "application/dns-json"})
                if not resp.ok:
                    continue
                answers = [str(a.get("data", "")).strip() for a in resp.json().get("Answer", [])]
                if answers:
                    return answers
            except Exception:  # noqa: BLE001
                continue
        return []

    def mod_dns(self, target):
        collected = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"):
            records = self._dns(target, rtype)
            if not records:
                continue
            collected[rtype] = records
            for record in records:
                live(rtype, record[:100])
        if not collected:
            self.note("no DNS records resolved")
            self.emit("domain.dns", "No DNS records resolved", "low", 70)
            return
        self.emit("domain.dns", f"DNS records present ({', '.join(collected)})", "info", 95,
                  data=collected)
        if collected.get("NS"):
            self.emit("domain.dns", "Authoritative nameservers identified", "low", 90,
                      data={"ns": collected["NS"]})

    def mod_mail(self, target):
        spf = [t for t in self._dns(target, "TXT") if "v=spf1" in t.lower()]
        for record in spf:
            live("spf", record[:110])
        if spf:
            self.emit("domain.mail", "SPF record published", "info", 90, data={"spf": spf})
            if any("~all" in s for s in spf):
                self.emit("domain.mail", "SPF soft-fails (~all)", "low", 85)
        else:
            self.emit("domain.mail", "No SPF record", "medium", 90)
        dmarc = [t for t in self._dns("_dmarc." + target, "TXT") if "v=dmarc1" in t.lower()]
        for record in dmarc:
            live("dmarc", record[:110])
        if dmarc:
            self.emit("domain.mail", "DMARC record published", "info", 90, data={"dmarc": dmarc})
            if "p=none" in dmarc[0].lower():
                self.emit("domain.mail", "DMARC is p=none (monitor only)", "medium", 85)
        else:
            self.emit("domain.mail", "No DMARC record", "high", 90)

    def mod_rdap(self, target):
        kind = "ip" if self.kind == KIND_IP else "domain"
        resp = self.http.get(f"https://rdap.org/{kind}/{target}")
        if not resp.ok:
            self.note(f"RDAP HTTP {resp.status_code or 'unreachable'}")
            return
        payload = resp.json()
        events = [f"{e.get('eventAction')}={e.get('eventDate')}" for e in payload.get("events", [])]
        for event in events:
            live("event", event)
        contacts = []
        for entity in payload.get("entities", []) or []:
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and item[0] in ("email", "fn", "org"):
                        contacts.append(f"{item[0]}: {item[3]}")
                        live(item[0], str(item[3]))
        self.emit("domain.rdap", "Registration record retrieved", "info", 95,
                  data={"events": events, "contacts": contacts,
                        "nameservers": [n.get("ldhName") for n in payload.get("nameservers", [])]})
        if contacts:
            self.emit("domain.rdap", "Registrant contact data exposed", "low", 75,
                      data={"contacts": contacts})

    def mod_subdomains(self, target):
        found = {}
        try:
            resp = self.http.get(f"https://crt.sh/?q=%25.{target}&output=json")
            if resp.ok and resp.text.strip().startswith("["):
                for entry in resp.json():
                    for name in str(entry.get("name_value", "")).splitlines():
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(target):
                            found.setdefault(name, set()).add("crt.sh")
        except Exception:  # noqa: BLE001
            pass
        try:
            resp = self.http.get(f"https://api.hackertarget.com/hostsearch/?q={target}")
            if resp.ok and "error" not in resp.text[:60].lower():
                for line in resp.text.splitlines():
                    name = line.split(",")[0].strip().lower()
                    if name.endswith(target):
                        found.setdefault(name, set()).add("hackertarget")
        except Exception:  # noqa: BLE001
            pass
        found.pop(target, None)
        if not found:
            self.note("no subdomains discovered")
            self.emit("domain.subdomains", "No subdomains discovered", "low", 70)
            return
        for name, sources in sorted(found.items()):
            live("subdomain", f"{name}  [{','.join(sorted(sources))}]")
        self.emit("domain.subdomains", f"{len(found)} subdomain(s) discovered", "medium", 80,
                  data={n: sorted(s) for n, s in sorted(found.items())})
        interesting = ("dev", "staging", "test", "uat", "qa", "admin", "internal", "vpn",
                       "jenkins", "gitlab", "jira", "grafana", "kibana", "db")
        for name in found:
            if any(marker in name.split(".")[0] for marker in interesting):
                self.emit("domain.subdomains", f"High-value hostname: {name}", "low", 60)

    def _base(self):
        return self.target if self.kind == KIND_URL else f"https://{self.target}"

    def mod_http(self, target):
        url = self._base()
        resp = self.http.get(url)
        if resp.status_code == 0:
            self.note(f"unreachable: {url}")
            self.emit("domain.http", "Host unreachable over HTTPS", "low", 60)
            return
        self.write_raw("http_" + (urlparse(url).hostname or "host"), resp.text[:200000])
        live("status", str(resp.status_code))
        live("final url", resp.url)
        self.emit("domain.http", f"HTTP {resp.status_code} from {url}", "info", 95,
                  data={"final_url": resp.url})
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for header in ("server", "x-powered-by", "via", "x-generator"):
            if headers.get(header):
                live(header, headers[header][:90])
        if headers.get("server") or headers.get("x-powered-by"):
            self.emit("domain.http", "Server technology disclosed", "low", 90,
                      data={"server": headers.get("server", ""),
                            "x-powered-by": headers.get("x-powered-by", "")})
        stack = sorted({label for sig, label in TECH_SIGNATURES.items() if sig in resp.text.lower()})
        for item in stack:
            live("tech", item)
        if stack:
            self.emit("domain.http", "Technology fingerprint", "info", 65, data={"tech": stack})
        for pattern, label in DISCLOSURE:
            if pattern.search(resp.text):
                self.emit("domain.http", label, "low", 70)
        title = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.S | re.I)
        if title:
            value = re.sub(r"\s+", " ", title.group(1)).strip()[:150]
            live("title", value)
            self.emit("domain.http", "Page title", "info", 95, data={"title": value})
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        if missing:
            self.emit("domain.http", f"{len(missing)} security header(s) missing",
                      "medium", 90, data={"missing": missing})
            for header in missing:
                sev, reason = SECURITY_HEADERS[header]
                self.emit("domain.http", f"Missing {header}", sev, 85, detail=reason)

    def mod_endpoints(self, target):
        base = self._base().rstrip("/")
        robots = self.http.get(base + "/robots.txt")
        if robots.ok and "user-agent" in robots.text.lower():
            paths = [l.strip() for l in robots.text.splitlines()
                     if l.lower().startswith(("disallow", "allow"))]
            for path in paths[:20]:
                live("robots", path)
            self.emit("domain.endpoints", "robots.txt present", "info", 90,
                      data={"paths": paths[:30]})
            self.write_raw("robots", robots.text)
        git = self.http.get(base + "/.git/HEAD")
        if git.ok and "ref:" in git.text[:20]:
            live(".git/HEAD", git.text.strip()[:60])
            self.emit("domain.endpoints", ".git directory exposed", "high", 85)
        for path in ("/.env", "/backup.zip", "/phpinfo.php", "/sitemap.xml",
                     "/.well-known/security.txt"):
            resp = self.http.get(base + path)
            if resp.ok and len(resp.text) > 40:
                live("exposed", f"{path}  HTTP {resp.status_code}")
                sev = "high" if path in ("/.env", "/backup.zip") else "low"
                self.emit("domain.endpoints", f"Sensitive path responds: {path}", sev, 55)

    def mod_favicon(self, target):
        resp = self.http.get(self._base().rstrip("/") + "/favicon.ico")
        if not resp.ok:
            self.note("no favicon")
            return
        raw = resp.text.encode("latin-1", "replace")
        mmh3 = murmur3_32(base64.encodebytes(raw))
        live("mmh3", str(mmh3))
        self.emit("domain.favicon", "Favicon fingerprint computed", "info", 95,
                  data={"mmh3": mmh3, "sha256": hashlib.sha256(raw).hexdigest()},
                  refs=[f"https://www.shodan.io/search?query=http.favicon.hash%3A{mmh3}"])

    def mod_wayback(self, target):
        host = urlparse(target).hostname if self.kind == KIND_URL else target
        resp = self.http.get("http://web.archive.org/cdx/search/cdx",
                             params={"url": f"{host}/*", "output": "json",
                                     "collapse": "urlkey", "limit": "600"})
        if not resp.ok or not resp.text.strip().startswith("["):
            self.note("no CDX response")
            return
        try:
            rows = resp.json()[1:]
        except ValueError:
            self.note("unparseable CDX payload")
            return
        if not rows:
            self.note("no archived captures")
            self.emit("domain.wayback", "No archived captures", "info", 80)
            return
        urls = sorted({r[2] for r in rows if len(r) > 2})
        for url in urls[:15]:
            live("capture", url)
        self.emit("domain.wayback", f"{len(rows)} archived capture(s)", "low", 85,
                  data={"sample": urls[:30]},
                  refs=[f"http://web.archive.org/web/{rows[0][1]}/{rows[0][2]}"])
        interesting = [u for u in urls if any(m in u.lower() for m in
                       ("admin", "login", "api", "backup", "dev", "old", "test", ".env", ".sql"))]
        if interesting:
            self.emit("domain.wayback", f"{len(interesting)} historically interesting URL(s)",
                      "medium", 65, data={"urls": interesting[:20]})

    def mod_cloud(self, target):
        base = re.sub(r"[^a-z0-9-]", "", target.split(".")[0].lower())
        if not base:
            return
        hits = 0
        for name in [base + s for s in BUCKET_SUFFIXES][:8]:
            s3 = self.http.get(f"https://{name}.s3.amazonaws.com/")
            if s3.status_code == 200 and "<ListBucketResult" in s3.text:
                live("aws", f"{name} PUBLIC-LIST")
                self.emit("domain.cloud", f"S3 bucket public-list: {name}", "high", 80,
                          refs=[f"https://{name}.s3.amazonaws.com/"])
                hits += 1
            elif s3.status_code == 403:
                live("aws", f"{name} exists-private")
                self.emit("domain.cloud", f"S3 bucket exists (private): {name}", "low", 70)
                hits += 1
            azure = self.http.get(f"https://{name}.blob.core.windows.net/?comp=list")
            if azure.status_code in (200, 400) and "EnumerationResults" in azure.text:
                live("azure", f"{name} enumerable")
                self.emit("domain.cloud", f"Azure container enumerable: {name}", "high", 75,
                          refs=[f"https://{name}.blob.core.windows.net/"])
                hits += 1
        if not hits:
            self.note("no bucket candidates resolved")
            self.emit("domain.cloud", "No bucket candidates resolved", "info", 60)

    # ===================== modules: IP ==================================== #
    def _resolve(self, target):
        if self.kind == KIND_IP:
            return target
        try:
            return socket.gethostbyname(target)
        except OSError:
            return None

    def mod_geo(self, target):
        ip = self._resolve(target)
        if not ip:
            self.note("resolution failed")
            self.emit("ip.geo", "Host did not resolve", "low", 70)
            return
        live("resolved", ip)
        resp = self.http.get(f"http://ip-api.com/json/{ip}",
                             params={"fields": "status,message,country,regionName,city,lat,lon,"
                                               "isp,org,as,hosting,proxy"})
        if not resp.ok:
            self.note("geo provider unreachable")
            return
        data = resp.json()
        if data.get("status") != "success":
            self.note(data.get("message", "lookup failed"))
            return
        for key in ("country", "regionName", "city", "isp", "org", "as"):
            if data.get(key):
                live(key, str(data[key]))
        self.emit("ip.geo", f"IP attributed to {data.get('country')} / {data.get('isp')}",
                  "info", 85,
                  data={k: data.get(k) for k in
                        ("country", "regionName", "city", "isp", "org", "as", "hosting", "proxy")})
        if data.get("lat") and data.get("lon"):
            maps = f"https://www.google.com/maps?q={data['lat']},{data['lon']}"
            live("maps", maps)
            self.emit("ip.geo", "Coordinates resolved", "info", 70, refs=[maps])
        if data.get("proxy"):
            self.emit("ip.geo", "Proxy / VPN egress detected", "low", 75)

    def mod_rdns(self, target):
        ip = self._resolve(target)
        if not ip:
            return
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            live("ptr", host)
            self.emit("ip.rdns", "Reverse DNS record present", "low", 90, data={"ptr": host})
        except OSError:
            self.note("no PTR record")

    def mod_ports(self, target):
        host = self._resolve(target)
        if not host:
            self.note("resolution failed")
            return
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521,
                 2049, 2375, 3000, 3306, 3389, 5432, 5601, 6379, 8000, 8080, 8443, 8888,
                 9000, 9200, 11211, 27017]

        def probe(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(min(self.settings["timeout"], 3.0))
                return port, sock.connect_ex((host, port)) == 0

        opened = []
        with futures.ThreadPoolExecutor(max_workers=32) as pool:
            for port, alive in pool.map(probe, ports):
                if alive:
                    opened.append(port)
                    ok(f"{port}/tcp  {SERVICE_HINTS.get(port, 'unknown')}")
        if not opened:
            self.note("no open ports in list")
            self.emit("ip.ports", "No open ports in common list", "info", 80)
            return
        labelled = {p: SERVICE_HINTS.get(p, "unknown") for p in sorted(opened)}
        self.emit("ip.ports", f"{len(opened)} open TCP port(s)", "medium", 95, data=labelled)
        for port, service in labelled.items():
            if port in RISKY_PORTS:
                self.emit("ip.ports", f"Risky service exposed: {service}/{port}", "high", 80)

    def mod_vt(self, target):
        key = self.settings["keys"]["virustotal"]
        ip = self._resolve(target)
        if not key:
            warn("no VirusTotal key — set one in Settings (menu 32)")
            return
        if not ip:
            return
        resp = self.http.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                             headers={"x-apikey": key})
        if not resp.ok:
            self.note(f"VT HTTP {resp.status_code or 'unreachable'}")
            return
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        for key_name, value in stats.items():
            live(key_name, str(value))
        malicious = stats.get("malicious", 0)
        self.emit("ip.reputation", f"VT detections: {malicious}",
                  "high" if malicious > 2 else "low" if malicious else "info", 85,
                  data=stats, refs=[f"https://www.virustotal.com/gui/ip-address/{ip}"])

    # ===================== modules: leaks / dorks ========================= #
    def _dork_run(self, target, kind):
        dorks = DORK_SETS.get(kind)
        if not dorks:
            self.note(f"no dork set for {kind}")
            return
        hits = 0
        for label, template in dorks.items():
            query = template.format(t=target)
            info(f"dork: {label}")
            results = self.search(query)
            if not results:
                no("  no hits")
                continue
            hits += 1
            for result in results:
                live("hit", result["url"])
            sev = "low" if ("exposed" in label.lower() or "leak" in label.lower()) else "info"
            self.emit("web.dorks", f"{label} — {len(results)} hit(s)", sev, 55,
                      data={"query": query, "results": results},
                      refs=[r["url"] for r in results[:4]])
        if not hits:
            self.note("no dork produced results")
            self.emit("web.dorks", "Dork sweep returned nothing", "info", 50)

    def mod_dorks(self, target):
        self._dork_run(target, self.kind)

    def mod_org(self, target):
        self._dork_run(target, KIND_ORG)

    def mod_pastes(self, target):
        resp = self.http.get(f"https://psbdmp.ws/api/v3/search/{target}")
        if resp.ok:
            try:
                records = resp.json().get("data", [])
            except ValueError:
                records = []
            ids = [r.get("id") for r in records if r.get("id")]
            for pid in ids[:15]:
                live("paste", f"https://pastebin.com/{pid}")
            if ids:
                self.emit("leaks.pastes", f"{len(ids)} paste(s) referencing target", "high", 80,
                          data={"paste_ids": ids[:25]},
                          refs=[f"https://pastebin.com/{p}" for p in ids[:8]])
        else:
            self.note(f"psbdmp HTTP {resp.status_code or 'unreachable'}")
        for host in PASTE_HOSTS:
            live("dork", f'site:{host} "{target}"')

    # ===================== modules: URL / file ============================ #
    def mod_url(self, target):
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        flags = []
        if parsed.scheme != "https":
            flags.append(("Plain HTTP transport", "medium"))
        if host in SHORTENERS:
            flags.append(("URL shortener — destination hidden", "medium"))
        if host.startswith("xn--") or ".xn--" in host:
            flags.append(("Punycode host — homograph risk", "high"))
        if any(host.endswith(t) for t in SUSPICIOUS_TLDS):
            flags.append((f"High-abuse TLD: {host.rsplit('.', 1)[-1]}", "low"))
        if host.count(".") >= 4:
            flags.append(("Deep subdomain nesting", "medium"))
        if host.count("-") >= 3:
            flags.append(("Excessive hyphens", "low"))
        if len(target) > 90:
            flags.append(("Unusually long URL", "low"))
        if "@" in parsed.netloc:
            flags.append(("Userinfo in authority", "medium"))
        if re.search(r"\d{1,3}(\.\d{1,3}){3}", host):
            flags.append(("Raw IP host", "medium"))
        for brand in BRAND_TOKENS:
            if brand in host and not host.endswith(brand + ".com"):
                flags.append((f"Brand token '{brand}' on non-canonical domain", "medium"))
                break
        if entropy(host) > 3.6:
            flags.append((f"High host entropy ({entropy(host):.2f})", "low"))
        live("host", host)
        live("scheme", parsed.scheme)
        for label, sev in flags:
            live("flag", f"[{sev}] {label}")
            self.emit("url.analyze", label, sev, 70)
        if not flags:
            self.emit("url.analyze", "No obvious phishing indicators", "info", 60)
        resp = self.http.get(target)
        if resp.status_code == 0:
            self.note("target unreachable")
            return
        live("status", str(resp.status_code))
        live("final url", resp.url)
        self.emit("url.analyze", f"Live response HTTP {resp.status_code}", "info", 95,
                  data={"final_url": resp.url})
        if resp.url.rstrip("/") != target.rstrip("/"):
            self.emit("url.analyze", "Redirect observed", "medium", 85, data={"to": resp.url})

    def mod_reverse_image(self, target):
        engines = {"Google Lens": "https://lens.google.com/", "Yandex": "https://yandex.com/images/",
                   "TinEye": "https://tineye.com/", "Bing Visual": "https://www.bing.com/visualsearch"}
        for name, url in engines.items():
            live(name, url)
        self.emit("file.reverse-image", "Reverse-image endpoints", "info", 99,
                  data=engines, refs=list(engines.values()))
        for url in engines.values():
            try:
                webbrowser.open(url)
            except Exception:  # noqa: BLE001
                pass

    def mod_metadata(self, target):
        if not os.path.isfile(target):
            self.note("file not found")
            return
        stat = os.stat(target)
        live("size", f"{stat.st_size} bytes")
        self.emit("file.metadata", "File statistics", "info", 99,
                  data={"size": stat.st_size, "mtime": stat.st_mtime})
        low = target.lower()
        if low.endswith((".jpg", ".jpeg", ".png", ".tif", ".tiff", ".heic")):
            if Image is None:
                warn("Pillow not installed — EXIF skipped")
                return
            with Image.open(target) as image:
                exif = image.getexif()
                found = {}
                for tag_id, value in exif.items():
                    found[EXIF_TAGS.get(tag_id) or ExifTags.TAGS.get(tag_id, str(tag_id))] = str(value)
                for key, value in found.items():
                    live(key, value)
                if found:
                    self.emit("file.metadata", f"{len(found)} EXIF field(s) recovered",
                              "medium", 95, data=found)
                gps = exif.get_ifd(0x8825)
                if gps:
                    gps_data = {GPS_TAGS.get(k, str(k)): str(v) for k, v in gps.items()}
                    for key, value in gps_data.items():
                        live(key, value)
                    self.emit("file.metadata", "GPS block present in EXIF", "high", 95,
                              data=gps_data)
        elif low.endswith(".pdf"):
            with open(target, "rb") as fh:
                blob = fh.read(400000)
            found = {}
            for key in PDF_KEYS:
                match = re.search(rb"/" + key.encode() + rb"\s*\(([^)]{0,200})\)", blob)
                if match:
                    found[key] = match.group(1).decode("latin-1", "replace")
                    live(key, found[key])
            if found:
                self.emit("file.metadata", "PDF properties recovered", "medium", 90, data=found)
        elif low.endswith((".docx", ".xlsx", ".pptx")):
            try:
                with zipfile.ZipFile(target) as archive:
                    for name in ("docProps/core.xml", "docProps/app.xml"):
                        if name in archive.namelist():
                            text = archive.read(name).decode("utf-8", "replace")
                            fields = dict(re.findall(r"<(\w+)[^>]*>([^<]{1,120})</\1>", text))
                            for key, value in fields.items():
                                live(key, value)
                            if fields:
                                self.emit("file.metadata", "Office properties recovered",
                                          "medium", 90, data=fields)
                                return
            except zipfile.BadZipFile:
                self.note("not a valid OOXML container")
        else:
            self.note("no metadata handler for this extension")

    # ===================== deep scan ====================================== #
    PASSIVE = {
        KIND_USERNAME: ["mod_profiles", "mod_github", "mod_github_activity", "mod_reddit",
                        "mod_telegram", "mod_keybase", "mod_dorks", "mod_pastes"],
        KIND_EMAIL: ["mod_email", "mod_breaches", "mod_pastes"],
        KIND_DOMAIN: ["mod_dns", "mod_mail", "mod_rdap", "mod_subdomains", "mod_http",
                      "mod_endpoints", "mod_favicon", "mod_wayback", "mod_dorks", "mod_geo"],
        KIND_IP: ["mod_geo", "mod_rdns", "mod_rdap", "mod_vt"],
        KIND_URL: ["mod_url", "mod_http", "mod_endpoints", "mod_wayback"],
        KIND_FILE: ["mod_metadata", "mod_reverse_image"],
    }
    ACTIVE = {KIND_DOMAIN: ["mod_ports", "mod_cloud"], KIND_IP: ["mod_ports"]}

    def deep_scan(self, target):
        plan = list(self.PASSIVE.get(self.kind, []))
        actives = self.ACTIVE.get(self.kind, [])
        if actives:
            use = self.settings["allow_active"]
            if not use:
                answer = input(c(YELLOW, "  include active modules? [y/N] ")).strip().lower()
                use = answer == "y"
            if use:
                plan += actives
        if not plan:
            warn(f"no modules applicable to {self.kind}")
            return
        info(f"plan: {len(plan)} module(s)")
        for name in plan:
            rule(name)
            started = time.time()
            try:
                getattr(self, name)(target)
            except KeyboardInterrupt:
                raise
            except Exception as exc:  # noqa: BLE001
                self.record_error(name, exc)
            info(f"{name} done in {time.time() - started:.1f}s")
            time.sleep(0.3)

    # ===================== dispatch ======================================= #
    def begin(self, target: str, label: str):
        detected, value = classify(target)
        if detected == KIND_UNKNOWN:
            err(f"unrecognised target: {target}")
            return None
        self.target, self.kind = value, detected
        self.findings, self._seen, self.errors = [], set(), []
        self.http.stats = {"ok": 0, "fail": 0, "insecure": 0, "errors": []}
        self.open_workspace(value)
        rule(label)
        kv("target", value)
        kv("type", detected)
        kv("workspace", self.workspace)
        rule("connectivity")
        self.preflight()
        return value

    def finish(self, started: float) -> None:
        self.export()
        counts = {s: sum(1 for f in self.findings if f.severity == s) for s in SEV_ORDER}
        print()
        kv("findings", str(len(self.findings)))
        kv("severity", " ".join(f"{k}={v}" for k, v in counts.items()))
        kv("http ok/fail", f"{self.http.stats['ok']}/{self.http.stats['fail']}")
        kv("elapsed", f"{time.time() - started:.1f}s")
        if not self.findings:
            rule("diagnostics")
            warn("no findings recorded")
            for line in self.http.stats["errors"][:8]:
                no(f"  transport: {line}")
            for line in self.errors[:8]:
                no(f"  module: {line}")
            if self.http.stats["fail"] and not self.http.stats["ok"]:
                warn("every request failed — try --insecure, check DNS/proxy, verify clock")
            elif self.http.stats["fail"] > self.http.stats["ok"]:
                warn("most requests failed — lower the rate or raise the timeout in Settings")

    def run(self, module_name, target, kind=None):
        detected, _ = classify(target)
        if kind and detected != kind and not (kind == KIND_DOMAIN and detected == KIND_URL):
            warn(f"expected {kind}, got {detected} — continuing")
        value = self.begin(target, module_name)
        if not value:
            return
        started = time.time()
        try:
            getattr(self, module_name)(value)
        except KeyboardInterrupt:
            warn("interrupted")
        except Exception as exc:  # noqa: BLE001
            self.record_error(module_name, exc)
        finally:
            self.finish(started)

    # ===================== menus ========================================== #
    MENU = [
        (1, "Username enumeration", "username", "mod_profiles"),
        (2, "Email intelligence", "email", "mod_email"),
        (3, "Breach exposure (HIBP)", "email", "mod_breaches"),
        (4, "Domain DNS records", "domain", "mod_dns"),
        (5, "Mail posture SPF/DMARC", "domain", "mod_mail"),
        (6, "RDAP registration", "domain/ip", "mod_rdap"),
        (7, "Subdomain discovery", "domain", "mod_subdomains"),
        (8, "HTTP fingerprint", "domain/url", "mod_http"),
        (9, "Endpoint exposure", "domain/url", "mod_endpoints"),
        (10, "Favicon hash pivot", "domain/url", "mod_favicon"),
        (11, "Wayback inventory", "domain/url", "mod_wayback"),
        (12, "Cloud bucket sweep", "domain [active]", "mod_cloud"),
        (13, "IP geolocation", "ip/domain", "mod_geo"),
        (14, "Reverse DNS", "ip/domain", "mod_rdns"),
        (15, "Port scan", "ip/domain [active]", "mod_ports"),
        (16, "VirusTotal reputation", "ip/domain", "mod_vt"),
        (17, "GitHub account", "username", "mod_github"),
        (18, "GitHub commit emails", "username", "mod_github_activity"),
        (19, "Reddit account", "username", "mod_reddit"),
        (20, "Telegram handle", "username", "mod_telegram"),
        (21, "Keybase identity", "username", "mod_keybase"),
        (22, "Paste / leak search", "any", "mod_pastes"),
        (23, "Curated dork sweep", "domain/email/user/org", "mod_dorks"),
        (24, "Company dork sweep", "org", "mod_org"),
        (25, "URL phishing analysis", "url", "mod_url"),
        (26, "File metadata", "file", "mod_metadata"),
        (27, "Reverse image engines", "file", "mod_reverse_image"),
    ]

    def menu(self) -> None:
        self.banner()
        print()
        print(c(CYAN, "  MODULES"))
        half = (len(self.MENU) + 1) // 2
        for i in range(half):
            left = self.MENU[i]
            right = self.MENU[i + half] if i + half < len(self.MENU) else None
            row = f"  {str(left[0]).rjust(2)}. {left[1].ljust(26)}{c(GREY, left[2].ljust(20))}"
            if right:
                row += f"{str(right[0]).rjust(2)}. {right[1].ljust(26)}{c(GREY, right[2])}"
            print(row)
        print()
        print(c(CYAN, "  ACTIONS"))
        print("  30. Deep scan       31. Export reports     32. Settings")
        print("   0. Exit")
        print()
        active = c(GREEN, "on") if self.settings["allow_active"] else c(GREY, "off")
        print(c(GREY, f"  min-severity={self.settings['min_severity']}  active={active}  "
                      f"rate={self.settings['rate']}/s  timeout={self.settings['timeout']}s"))

    def settings_menu(self) -> None:
        while True:
            rule("settings")
            kv("1 timeout", f"{self.settings['timeout']}s")
            kv("2 rate limit", f"{self.settings['rate']} req/s per host")
            kv("3 min severity", self.settings["min_severity"])
            kv("4 active modules", "on" if self.settings["allow_active"] else "off")
            kv("5 cache", "on" if self.settings["cache"] else "off")
            kv("6 HIBP key", "set" if self.settings["keys"]["hibp"] else "unset")
            kv("7 VirusTotal key", "set" if self.settings["keys"]["virustotal"] else "unset")
            kv("8 GitHub token", "set" if self.settings["keys"]["github"] else "unset")
            print("  0. back")
            choice = input(c(YELLOW, "  setting> ")).strip()
            try:
                if choice == "0":
                    return
                if choice == "1":
                    self.settings["timeout"] = float(input("  seconds> "))
                elif choice == "2":
                    self.settings["rate"] = float(input("  requests per second> "))
                elif choice == "3":
                    value = input("  info|low|medium|high> ").strip().lower()
                    if value in SEV_ORDER:
                        self.settings["min_severity"] = value
                elif choice == "4":
                    self.settings["allow_active"] = not self.settings["allow_active"]
                elif choice == "5":
                    self.settings["cache"] = not self.settings["cache"]
                elif choice in ("6", "7", "8"):
                    name = {"6": "hibp", "7": "virustotal", "8": "github"}[choice]
                    self.settings["keys"][name] = input("  key> ").strip()
            except ValueError:
                err("invalid value")

    def ask(self, label: str) -> str:
        return input(c(YELLOW, f"  {label}> ")).strip()

    def loop(self) -> None:
        by_number = {row[0]: row for row in self.MENU}
        while True:
            try:
                self.menu()
                choice = input(c(YELLOW, "  select> ")).strip()
                if choice == "0":
                    ok("done — stay ethical")
                    return
                if choice == "30":
                    target = self.ask("target")
                    value = self.begin(target, "deep scan")
                    if value:
                        started = time.time()
                        try:
                            self.deep_scan(value)
                        except KeyboardInterrupt:
                            warn("interrupted")
                        finally:
                            self.finish(started)
                    input(c(GREY, "\n  enter to continue "))
                    continue
                if choice == "31":
                    if self.workspace:
                        self.export(("json", "md", "html", "csv"))
                    else:
                        warn("run a module first")
                    input(c(GREY, "\n  enter to continue "))
                    continue
                if choice == "32":
                    self.settings_menu()
                    continue
                if choice.isdigit() and int(choice) in by_number:
                    row = by_number[int(choice)]
                    expected = row[2].split("/")[0].replace(" [active]", "")
                    target = self.ask(f"target ({row[2]})")
                    self.run(row[3], target, None if expected == "any" else expected)
                    input(c(GREY, "\n  enter to continue "))
                    continue
                err("invalid choice")
            except KeyboardInterrupt:
                print()
                ok("cancelled")
                return
            except EOFError:
                return


# --------------------------------------------------------------------------- #
# entrypoint
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    global COLOR
    parser = argparse.ArgumentParser(
        prog="socialintellax.py",
        description="OSINT, attack-surface and threat-intelligence framework.",
        epilog=f"{AUTHOR} — {ROLE} — MIT")
    parser.add_argument("target", nargs="?", help="deep scan this target and exit")
    parser.add_argument("--active", action="store_true", help="include active modules")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument("--min-severity", choices=("info", "low", "medium", "high"), default="info")
    parser.add_argument("--list", action="store_true", help="list modules")
    parser.add_argument("--doctor", action="store_true", help="environment check")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("-V", "--version", action="version", version=f"socialintellax {VERSION}")
    args = parser.parse_args(argv)

    if args.no_color:
        COLOR = False

    if args.list:
        for number, name, kind, func in SocialIntellax.MENU:
            print(f"{str(number).rjust(2)}  {name.ljust(30)} {kind.ljust(26)} {func}")
        return 0

    if args.doctor:
        rule("runtime")
        kv("python", sys.version.split()[0])
        kv("platform", sys.platform)
        kv("requests", requests.__version__)
        kv("beautifulsoup4", "present" if BeautifulSoup else "absent (dork parsing degraded)")
        kv("Pillow", "present" if Image else "absent (EXIF disabled)")
        rule("keys")
        for env in ("HIBP_API_KEY", "VT_API_KEY", "GITHUB_TOKEN"):
            kv(env, "set" if os.environ.get(env) else "unset")
        return 0

    app = SocialIntellax()
    app.settings["allow_active"] = args.active
    app.settings["min_severity"] = args.min_severity
    app.settings["insecure"] = args.insecure

    if args.target:
        value = app.begin(args.target, "deep scan")
        if not value:
            return 1
        started = time.time()
        try:
            app.deep_scan(value)
        finally:
            app.finish(started)
        return 0

    app.loop()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        raise SystemExit(130)
