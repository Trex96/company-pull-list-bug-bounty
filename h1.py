#!/usr/bin/env python3

import argparse
import asyncio
import json
import os
import re
import socket
import sys
import threading
from html import unescape
from pathlib import Path
from urllib.parse import urljoin, urlparse

import aiohttp
import tldextract


# ============================================================
# CONFIG
# ============================================================

SCOPE_URL = (
    "https://raw.githubusercontent.com/"
    "rix4uni/scope/main/programs.json"
)

KNOWN_CHANGELOGS_URL = (
    "https://raw.githubusercontent.com/"
    "w9w/bugbounty_changelogs/main/list.txt"
)

DEFAULT_OUTPUT = "changelog_list.txt"
DEFAULT_JSON = "changelog_results.json"
DEFAULT_PROGRESS = "changelog_progress.json"

USER_AGENT = (
    "BugBountyChangelogFinder/2.1 "
    "(public-program-changelog-discovery)"
)

# Full timeout for confirmed/known URLs worth waiting on.
TIMEOUT = 12

# Shorter timeout for speculative/guessed-path probes, so a
# dead or slow host doesn't eat 12s per guess when we're
# firing many guesses in parallel anyway.
PROBE_TIMEOUT = 6

DEFAULT_CONCURRENCY = 200

CHANGELOG_PATHS = [
    "/changelog",
    "/release-notes",
    "/releases",
    "/product-updates",
    "/product/updates",
    "/updates",
    "/whats-new",
    "/what-is-new",
    "/version-history",
    "/patch-notes",
    "/firmware-updates",
    "/software-updates",
    "/new-features",
    "/docs/changelog",
    "/docs/release-notes",
    "/docs/releases",
    "/docs/updates",
    "/docs/whats-new",
    "/developer/changelog",
    "/developers/changelog",
    "/developer/release-notes",
    "/developers/release-notes",
    "/api/changelog",
    "/api/release-notes",
    "/blog/changelog",
    "/blog/releases",
    "/blog/updates",
    "/support/release-notes",
    "/help/release-notes",
    "/help/changelog",
    "/news/releases",
]

SECURITY_PATHS = [
    "/security",
    "/security-center",
    "/trust",
    "/trust-center",
    "/responsible-disclosure",
    "/vulnerability-disclosure",
    "/security-policy",
    "/bug-bounty",
    "/security/bug-bounty",
]

FEED_PATHS = [
    "/feed",
    "/rss",
    "/rss.xml",
    "/feed.xml",
    "/atom.xml",
    "/changelog/feed",
    "/release-notes/feed",
    "/updates/feed",
]

SKIP_HOSTS = {
    "localhost",
    "127.0.0.1",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "youtube.com",
    "tiktok.com",
}

SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".exe",
    ".dmg",
    ".apk",
    ".ipa",
}

# Domains which should never be treated as company root domains.
COMMON_INFRA_SUFFIXES = {
    "amazonaws.com",
    "cloudfront.net",
    "azurewebsites.net",
    "azure.com",
    "googleusercontent.com",
    "appspot.com",
    "herokuapp.com",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "workers.dev",
    "github.io",
    "gitlab.io",
    "webflow.io",
}


# ============================================================
# EVENT LOOP HELPER
# ============================================================

def run_async(coro):
    """
    Run `coro` to completion, working whether or not the calling
    thread already has an asyncio event loop running (e.g. inside
    Jupyter/IPython, or some other async host process).
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No loop running here -- the normal `python script.py` case.
        return asyncio.run(coro)

    # A loop is already running in this thread, so asyncio.run()
    # would raise. Run our coroutine in a fresh loop on a new thread
    # instead, which sidesteps the conflict entirely.
    result = {}
    error = {}

    def runner():
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        try:
            result["value"] = new_loop.run_until_complete(coro)
        except Exception as exc:
            error["value"] = exc
        finally:
            new_loop.close()

    thread = threading.Thread(target=runner)
    thread.start()
    thread.join()

    if "value" in error:
        raise error["value"]

    return result.get("value")


# ============================================================
# DOMAIN HELPERS
# ============================================================

def valid_hostname(host):
    if not host:
        return False

    host = host.lower().strip(".")

    if len(host) > 253:
        return False

    if host in SKIP_HOSTS:
        return False

    if "." not in host:
        return False

    if any(host.endswith(x) for x in SKIP_SUFFIXES):
        return False

    # Reject IP addresses.
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return False

    # Reject strings containing whitespace.
    if re.search(r"\s", host):
        return False

    # Every label must be sane.
    labels = host.split(".")

    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        return False

    return True


def extract_hostname(value):
    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    # Wildcard targets.
    value = re.sub(r"^\*\.\s*", "", value)

    # Remove obvious surrounding characters.
    value = value.strip(
        " \t\r\n\"'`()[]{}<>;,|"
    )

    if "://" not in value:
        candidate = value.split("/")[0]
    else:
        try:
            candidate = urlparse(value).hostname
        except Exception:
            return None

    if not candidate:
        return None

    candidate = candidate.lower().strip(".")

    if valid_hostname(candidate):
        return candidate

    return None


def root_domain(host):
    """
    Convert:

        api.example.com
        docs.example.com

    into:

        example.com

    while respecting public suffixes.
    """

    if not host:
        return None

    host = host.lower().strip(".")

    if not valid_hostname(host):
        return None

    suffix = tldextract.extract(host)

    if not suffix.domain or not suffix.suffix:
        return None

    root = (
        suffix.domain
        + "."
        + suffix.suffix
    )

    # Don't collapse known infrastructure domains.
    if root in COMMON_INFRA_SUFFIXES:
        return None

    return root


# ============================================================
# HTTP
# ============================================================

async def fetch(
    session,
    url,
    semaphore,
    *,
    allow_redirects=True,
    timeout=TIMEOUT,
):
    async with semaphore:

        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(
                    total=timeout
                ),
                allow_redirects=allow_redirects,
            ) as response:

                body = await response.text(
                    errors="ignore"
                )

                return {
                    "status": response.status,
                    "url": str(response.url),
                    "content_type": (
                        response.headers
                        .get("Content-Type", "")
                        .lower()
                    ),
                    "body": body,
                }

        except (
            asyncio.TimeoutError,
            aiohttp.ClientError,
            UnicodeError,
            socket.gaierror,
            OSError,
        ):
            return None


# ============================================================
# DOWNLOAD DATA
# ============================================================

async def download_text(
    session,
    url,
    semaphore,
):
    result = await fetch(
        session,
        url,
        semaphore,
    )

    if not result:
        raise RuntimeError(
            f"Could not download {url}"
        )

    if result["status"] != 200:
        raise RuntimeError(
            f"{url} returned HTTP "
            f"{result['status']}"
        )

    return result["body"]


# ============================================================
# PROGRAM DATA
# ============================================================

def extract_program_records(data):
    """
    Accept several possible layouts because the upstream
    dataset can evolve.
    """

    if isinstance(data, list):
        return data

    if not isinstance(data, dict):
        return []

    for key in (
        "programs",
        "data",
        "results",
        "items",
    ):
        value = data.get(key)

        if isinstance(value, list):
            return value

    records = []

    for value in data.values():
        if isinstance(value, list):
            records.extend(value)

    return records


def get_name(record):
    if not isinstance(record, dict):
        return ""

    for key in (
        "name",
        "program_name",
        "title",
        "company",
        "organization",
    ):
        value = record.get(key)

        if (
            isinstance(value, str)
            and value.strip()
        ):
            return value.strip()

    return ""


def get_program_url(record):
    if not isinstance(record, dict):
        return ""

    for key in (
        "url",
        "program_url",
        "profile_url",
        "programUrl",
    ):
        value = record.get(key)

        if isinstance(value, str):
            return value.strip()

    return ""


def collect_candidate_strings(value):
    """
    Recursively collect strings which are likely to contain
    hostnames.

    IMPORTANT:
    We do NOT treat every string containing "." as a domain.
    """

    found = []

    def walk(obj, depth=0):
        if depth > 8:
            return

        if isinstance(obj, str):

            # URL-like strings.
            if (
                "://" in obj
                or obj.startswith("*.")
            ):
                found.append(obj)
                return

            # Explicit hostname-looking strings only.
            candidate = obj.strip()

            if (
                "." in candidate
                and " " not in candidate
                and "/" not in candidate
                and len(candidate) < 253
            ):
                found.append(candidate)

            return

        if isinstance(obj, list):
            for item in obj:
                walk(item, depth + 1)

            return

        if isinstance(obj, dict):
            for key, item in obj.items():

                key_l = str(key).lower()

                if key_l in {
                    "domain",
                    "domains",
                    "host",
                    "hostname",
                    "target",
                    "targets",
                    "url",
                    "urls",
                    "uri",
                    "website",
                    "website_url",
                    "company_url",
                    "asset",
                    "assets",
                }:
                    walk(item, depth + 1)

                elif isinstance(
                    item,
                    (dict, list),
                ):
                    walk(item, depth + 1)

    walk(value)

    return found


def build_domain_index(records):
    """
    Returns:

    {
        "example.com": {
            "names": {...},
            "program_urls": {...},
            "hosts": {...}
        }
    }
    """

    index = {}

    for record in records:

        name = get_name(record)
        program_url = get_program_url(record)

        strings = collect_candidate_strings(
            record
        )

        hosts = set()

        for value in strings:

            host = extract_hostname(value)

            if not host:
                continue

            root = root_domain(host)

            if not root:
                continue

            hosts.add(host)

            entry = index.setdefault(
                root,
                {
                    "names": set(),
                    "program_urls": set(),
                    "hosts": set(),
                },
            )

            if name:
                entry["names"].add(name)

            if program_url:
                entry["program_urls"].add(
                    program_url
                )

            entry["hosts"].add(host)

    return index


# ============================================================
# KNOWN CHANGELOGS
# ============================================================

def parse_known_changelogs(text):
    """
    Build:

    {
        root_domain: {urls...}
    }
    """

    known = {}

    for line in text.splitlines():

        urls = re.findall(
            r"https?://[^\s|)>]+",
            line,
            flags=re.I,
        )

        for url in urls:

            url = url.rstrip(
                ".,;:)]}\"'"
            )

            try:
                host = urlparse(url).hostname
            except Exception:
                continue

            if not host:
                continue

            root = root_domain(host)

            if not root:
                continue

            known.setdefault(
                root,
                set()
            ).add(url)

    return known


# ============================================================
# HTML ANALYSIS
# ============================================================

def html_to_text(html):
    text = re.sub(
        r"<script\b[^>]*>.*?</script>",
        " ",
        html,
        flags=re.I | re.S,
    )

    text = re.sub(
        r"<style\b[^>]*>.*?</style>",
        " ",
        text,
        flags=re.I | re.S,
    )

    text = re.sub(
        r"<[^>]+>",
        " ",
        text,
        flags=re.S,
    )

    text = unescape(text)

    return re.sub(
        r"\s+",
        " ",
        text,
    ).strip()


def is_html(result):
    if not result:
        return False

    content_type = result.get(
        "content_type",
        "",
    )

    return (
        "text/html" in content_type
        or "application/xhtml" in content_type
        or not content_type
    )


def looks_like_changelog(
    url,
    html,
):
    text = html_to_text(
        html
    ).lower()

    url_l = url.lower()

    url_signal = any(
        x in url_l
        for x in (
            "changelog",
            "change-log",
            "change_log",
            "release-note",
            "release_note",
            "/releases",
            "release-notes",
            "product-update",
            "/updates",
            "whats-new",
            "what-is-new",
            "version-history",
            "version_history",
            "patch-note",
            "patch_note",
            "firmware-update",
            "software-update",
            "new-feature",
            "/support/release",
            "/help/release",
            "/help/changelog",
            "/api/changelog",
            "/api/release",
            "/news/release",
        )
    )

    content_signal = any(
        x in text
        for x in (
            "changelog",
            "change log",
            "release notes",
            "release note",
            "product updates",
            "what's new",
            "whats new",
            "new features",
            "improvements",
            "version history",
            "patch notes",
            "patch note",
            "bug fixes",
            "bug fix",
            "fixed in",
            "firmware update",
            "software update",
            "new in version",
            "added in",
            "known issues",
        )
    )

    return (
        url_signal
        and content_signal
    )


def extract_links(
    page_url,
    html,
    root,
):
    links = set()

    for match in re.finditer(
        r"""href\s*=\s*["']([^"']+)["']""",
        html,
        flags=re.I,
    ):

        raw = unescape(
            match.group(1)
        ).strip()

        if not raw:
            continue

        absolute = urljoin(
            page_url,
            raw,
        )

        try:
            parsed = urlparse(
                absolute
            )
        except Exception:
            continue

        if parsed.scheme not in (
            "http",
            "https",
        ):
            continue

        host = parsed.hostname

        if not host:
            continue

        candidate_root = root_domain(host)

        if candidate_root != root:
            continue

        links.add(
            absolute.split("#")[0]
        )

    return links


def extract_feeds(
    page_url,
    html,
    root,
):
    feeds = set()

    # RSS/Atom <link> elements.
    patterns = [
        r'<link[^>]+href=["\']([^"\']+)["\'][^>]*>',
        r'<link[^>]+rel=["\']([^"\']+)["\'][^>]*>',
    ]

    for pattern in patterns:

        for match in re.finditer(
            pattern,
            html,
            flags=re.I,
        ):

            value = unescape(
                match.group(1)
            )

            if not any(
                x in value.lower()
                for x in (
                    "rss",
                    "atom",
                    "feed",
                )
            ):
                continue

            absolute = urljoin(
                page_url,
                value,
            )

            try:
                host = urlparse(
                    absolute
                ).hostname
            except Exception:
                continue

            if not host:
                continue

            if root_domain(host) == root:
                feeds.add(
                    absolute.split("#")[0]
                )

    # Explicit absolute feed URLs.
    for match in re.findall(
        r"https?://[^\s\"'<>]+",
        html,
        flags=re.I,
    ):

        low = match.lower()

        if not any(
            x in low
            for x in (
                "rss",
                "atom",
                "feed",
            )
        ):
            continue

        try:
            host = urlparse(
                match
            ).hostname
        except Exception:
            continue

        if host and root_domain(host) == root:
            feeds.add(
                match.rstrip(
                    ".,;:)]}\"'"
                )
            )

    return feeds


# ============================================================
# CHANGELOG DISCOVERY
# ============================================================

async def check_changelog_candidate(
    session,
    semaphore,
    url,
    root,
    *,
    timeout=PROBE_TIMEOUT,
):
    result = await fetch(
        session,
        url,
        semaphore,
        timeout=timeout,
    )

    if not result:
        return None, set()

    if result["status"] >= 400:
        return None, set()

    if not is_html(result):
        return None, set()

    final_url = result["url"]
    html = result["body"]

    if not looks_like_changelog(
        final_url,
        html,
    ):
        return None, set()

    feeds = extract_feeds(
        final_url,
        html,
        root,
    )

    return (
        final_url.rstrip("/"),
        feeds,
    )


async def discover_changelog(
    session,
    semaphore,
    root,
    known_urls,
):
    # --------------------------------------------------------
    # 1. Known high-confidence changelog(s) -- checked in
    #    parallel, since these are worth the full timeout.
    # --------------------------------------------------------

    if known_urls:

        tasks = [
            check_changelog_candidate(
                session,
                semaphore,
                url,
                root,
                timeout=TIMEOUT,
            )
            for url in sorted(known_urls)
        ]

        results = await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

        for item in results:

            if isinstance(item, Exception):
                continue

            result, feeds = item

            if result:
                return result, feeds

    base = "https://" + root

    # --------------------------------------------------------
    # 2. Homepage
    # --------------------------------------------------------

    homepage = await fetch(
        session,
        base,
        semaphore,
    )

    if homepage and homepage["status"] < 400:

        if is_html(homepage):

            feeds = extract_feeds(
                homepage["url"],
                homepage["body"],
                root,
            )

            links = extract_links(
                homepage["url"],
                homepage["body"],
                root,
            )

            interesting = []

            for link in links:

                low = link.lower()

                if any(
                    word in low
                    for word in (
                        "changelog",
                        "change-log",
                        "change_log",
                        "release",
                        "update",
                        "whats-new",
                        "what-is-new",
                        "version-history",
                        "version_history",
                        "patch-note",
                        "patch_note",
                        "new-feature",
                        "firmware-update",
                        "software-update",
                        "known-issues",
                    )
                ):
                    interesting.append(
                        link
                    )

            if interesting:

                tasks = [
                    check_changelog_candidate(
                        session,
                        semaphore,
                        link,
                        root,
                    )
                    for link in interesting[:30]
                ]

                results = await asyncio.gather(
                    *tasks,
                    return_exceptions=True,
                )

                for item in results:

                    if isinstance(
                        item,
                        Exception,
                    ):
                        continue

                    result, candidate_feeds = item

                    if result:
                        feeds.update(
                            candidate_feeds
                        )

                        return (
                            result,
                            feeds,
                        )

            # Homepage itself.
            if looks_like_changelog(
                homepage["url"],
                homepage["body"],
            ):
                return (
                    homepage["url"].rstrip("/"),
                    feeds,
                )

    # --------------------------------------------------------
    # 3. Direct paths -- already parallel.
    # --------------------------------------------------------

    tasks = []

    for path in CHANGELOG_PATHS:

        url = base + path

        tasks.append(
            check_changelog_candidate(
                session,
                semaphore,
                url,
                root,
            )
        )

    results = await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )

    for item in results:

        if isinstance(
            item,
            Exception,
        ):
            continue

        result, feeds = item

        if result:
            return result, feeds

    return None, set()


# ============================================================
# FEED DISCOVERY
# ============================================================

async def validate_feed(
    session,
    semaphore,
    url,
    root,
):
    result = await fetch(
        session,
        url,
        semaphore,
        timeout=PROBE_TIMEOUT,
    )

    if not result:
        return ""

    if result["status"] >= 400:
        return ""

    try:
        host = urlparse(
            result["url"]
        ).hostname
    except Exception:
        return ""

    if not host:
        return ""

    if root_domain(host) != root:
        return ""

    content_type = result[
        "content_type"
    ]

    body = result["body"][:10000].lower()

    if (
        "rss" in content_type
        or "atom" in content_type
        or "<rss" in body
        or "<feed" in body
        or "<rdf:rdf" in body
    ):
        return result["url"].rstrip("/")

    return ""


async def discover_feed(
    session,
    semaphore,
    root,
    changelog,
    discovered_feeds,
):
    candidates = set(
        discovered_feeds
    )

    if changelog:

        page = await fetch(
            session,
            changelog,
            semaphore,
        )

        if page and is_html(page):

            candidates.update(
                extract_feeds(
                    page["url"],
                    page["body"],
                    root,
                )
            )

    base = "https://" + root

    for path in FEED_PATHS:
        candidates.add(
            base + path
        )

    # Don't hammer every possible URL.
    candidates = list(candidates)[:20]

    tasks = [
        validate_feed(
            session,
            semaphore,
            url,
            root,
        )
        for url in candidates
    ]

    results = await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )

    for result in results:

        if (
            isinstance(result, str)
            and result
        ):
            return result

    return ""


# ============================================================
# SECURITY
# ============================================================

async def discover_security(
    session,
    semaphore,
    root,
):
    base = "https://" + root

    tasks = []

    for path in SECURITY_PATHS:

        tasks.append(
            fetch(
                session,
                base + path,
                semaphore,
                timeout=PROBE_TIMEOUT,
            )
        )

    results = await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )

    for result in results:

        if (
            not isinstance(
                result,
                dict,
            )
        ):
            continue

        if result["status"] >= 400:
            continue

        if not is_html(result):
            continue

        text = html_to_text(
            result["body"]
        ).lower()

        if any(
            phrase in text
            for phrase in (
                "security",
                "vulnerability",
                "responsible disclosure",
                "bug bounty",
                "security researcher",
            )
        ):
            return result["url"].rstrip("/")

    return ""


# ============================================================
# SECURITY.TXT
# ============================================================

async def discover_security_txt(
    session,
    semaphore,
    root,
):
    urls = [
        f"https://{root}/.well-known/security.txt",
        f"https://{root}/security.txt",
    ]

    tasks = [
        fetch(
            session,
            url,
            semaphore,
            timeout=PROBE_TIMEOUT,
        )
        for url in urls
    ]

    results = await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )

    for result in results:

        if not isinstance(
            result,
            dict,
        ):
            continue

        if result["status"] != 200:
            continue

        if re.search(
            r"(?im)^\s*Contact\s*:",
            result["body"],
        ):
            return result["url"].rstrip("/")

    return ""


# ============================================================
# PROCESS DOMAIN
# ============================================================

async def process_domain(
    session,
    semaphore,
    root,
    info,
    known,
):
    try:

        # Security checks don't depend on the changelog result,
        # so kick them off immediately and let them run
        # concurrently with changelog/feed discovery instead of
        # waiting for it to finish first.
        security_task = asyncio.create_task(
            discover_security(
                session,
                semaphore,
                root,
            )
        )

        security_txt_task = asyncio.create_task(
            discover_security_txt(
                session,
                semaphore,
                root,
            )
        )

        changelog, feeds = (
            await discover_changelog(
                session,
                semaphore,
                root,
                known.get(
                    root,
                    set(),
                ),
            )
        )

        rss = await discover_feed(
            session,
            semaphore,
            root,
            changelog,
            feeds,
        )

        security = await security_task
        security_txt = await security_txt_task

        names = sorted(
            x
            for x in info["names"]
            if x
        )

        name = (
            names[0]
            if names
            else root
        )

        return {
            "name": name,
            "domain": root,
            "changelog": changelog or "",
            "rss": rss or "",
            "security": security or "",
            "security_txt": (
                security_txt or ""
            ),
            "program_urls": sorted(
                info["program_urls"]
            ),
            "hosts": sorted(
                info["hosts"]
            ),
        }

    except Exception as exc:

        return {
            "name": (
                sorted(info["names"])[0]
                if info["names"]
                else root
            ),
            "domain": root,
            "changelog": "",
            "rss": "",
            "security": "",
            "security_txt": "",
            "program_urls": sorted(
                info["program_urls"]
            ),
            "hosts": sorted(
                info["hosts"]
            ),
            "error": str(exc),
        }


# ============================================================
# RESUME
# ============================================================

def load_progress(path):
    if not os.path.exists(path):
        return {}

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as f:
            data = json.load(f)

        if isinstance(data, dict):
            return data

    except Exception:
        pass

    return {}


def save_progress(
    path,
    results,
):
    temporary = path + ".tmp"

    with open(
        temporary,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            results,
            f,
            indent=2,
            ensure_ascii=False,
        )

    os.replace(
        temporary,
        path,
    )


# ============================================================
# OUTPUT
# ============================================================

def write_txt(
    path,
    results,
):
    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:

        for item in sorted(
            results.values(),
            key=lambda x: (
                not bool(
                    x.get(
                        "changelog"
                    )
                ),
                x.get(
                    "domain",
                    "",
                ),
            ),
        ):

            f.write(
                f"{item.get('name', '')}|"
                f"{item.get('changelog', '')}|"
                f"{item.get('rss', '')}|"
                f"{item.get('security', '')}|"
                f"{item.get('security_txt', '')}\n"
            )


def write_json(
    path,
    results,
):
    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            list(results.values()),
            f,
            indent=2,
            ensure_ascii=False,
        )


# ============================================================
# MAIN
# ============================================================

async def main(args):

    print()
    print("=" * 70)
    print(" Bug Bounty -> Changelog Finder v2.1 (optimized)")
    print("=" * 70)
    print()

    # Suppress gaierror / DNS-resolution tracebacks that aiohttp prints
    # from shielded internal futures — they are already handled gracefully
    # in fetch() and just clutter the output.
    def _silent_exception_handler(loop, context):
        exc = context.get("exception")
        if isinstance(exc, (socket.gaierror, OSError)):
            return
        msg = context.get("message", "")
        if "gaierror" in msg or "nodename" in msg:
            return
        loop.default_exception_handler(context)

    asyncio.get_event_loop().set_exception_handler(
        _silent_exception_handler
    )

    connector = aiohttp.TCPConnector(
        limit=args.concurrency,
        limit_per_host=10,
        ttl_dns_cache=600,
        enable_cleanup_closed=True,
    )

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": (
            "text/html,application/xhtml+xml,"
            "application/xml;q=0.9,*/*;q=0.8"
        ),
    }

    timeout = aiohttp.ClientTimeout(
        total=TIMEOUT
    )

    semaphore = asyncio.Semaphore(
        args.concurrency
    )

    async with aiohttp.ClientSession(
        connector=connector,
        headers=headers,
        timeout=timeout,
    ) as session:

        # ----------------------------------------------------
        # Download programs.json
        # ----------------------------------------------------

        print(
            "[+] Downloading public bounty "
            "program data..."
        )

        try:

            text = await download_text(
                session,
                SCOPE_URL,
                semaphore,
            )

            data = json.loads(text)

        except Exception as exc:

            print(
                f"[ERROR] Could not load "
                f"program data: {exc}"
            )

            return 1

        records = extract_program_records(
            data
        )

        print(
            f"[+] Program records found: "
            f"{len(records)}"
        )

        # ----------------------------------------------------
        # Known changelog list
        # ----------------------------------------------------

        print(
            "[+] Downloading known changelog list..."
        )

        known = {}

        try:

            text = await download_text(
                session,
                KNOWN_CHANGELOGS_URL,
                semaphore,
            )

            known = parse_known_changelogs(
                text
            )

            print(
                "[+] Loaded known changelog URLs "
                f"for {len(known)} domains"
            )

        except Exception as exc:

            print(
                "[!] Could not load known "
                f"changelog list: {exc}"
            )

        # ----------------------------------------------------
        # Build root-domain index
        # ----------------------------------------------------

        index = build_domain_index(
            records
        )

        print(
            "[+] Unique root/company domains: "
            f"{len(index)}"
        )

        if args.limit:

            limited = dict(
                list(index.items())[
                    :args.limit
                ]
            )

            index = limited

            print(
                "[+] Applying limit: "
                f"{len(index)} domains"
            )

        # ----------------------------------------------------
        # Resume
        # ----------------------------------------------------

        progress = load_progress(
            args.progress
        )

        remaining = [
            root
            for root in index
            if root not in progress
        ]

        print(
            "[+] Already completed: "
            f"{len(progress)}"
        )

        print(
            "[+] Remaining: "
            f"{len(remaining)}"
        )

        print(
            "[+] Async concurrency: "
            f"{args.concurrency}"
        )

        print()

        # ----------------------------------------------------
        # Scan
        # ----------------------------------------------------

        completed = len(progress)

        queue = asyncio.Queue()

        for root in remaining:
            await queue.put(root)

        async def worker(worker_id):

            nonlocal completed

            while True:

                try:
                    root = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return

                info = index[root]

                result = await process_domain(
                    session,
                    semaphore,
                    root,
                    info,
                    known,
                )

                progress[root] = result

                completed += 1

                changelog = result[
                    "changelog"
                ]

                if changelog:

                    print(
                        f"[{completed}/"
                        f"{len(index)}] "
                        f"[CHANGELOG] "
                        f"{root} -> "
                        f"{changelog}"
                    )

                elif completed % 25 == 0:

                    print(
                        f"[progress] "
                        f"{completed}/"
                        f"{len(index)}"
                    )

                # Save frequently.
                if (
                    completed % args.save_every
                    == 0
                ):
                    save_progress(
                        args.progress,
                        progress,
                    )

                    write_txt(
                        args.output,
                        progress,
                    )

                queue.task_done()

        worker_count = min(
            args.concurrency,
            len(remaining),
        )

        workers = [
            asyncio.create_task(
                worker(i)
            )
            for i in range(
                worker_count
            )
        ]

        await asyncio.gather(
            *workers
        )

        # ----------------------------------------------------
        # Final save
        # ----------------------------------------------------

        save_progress(
            args.progress,
            progress,
        )

        write_txt(
            args.output,
            progress,
        )

        write_json(
            args.json,
            progress,
        )

        found_changelog = sum(
            bool(
                x.get(
                    "changelog"
                )
            )
            for x in progress.values()
        )

        found_rss = sum(
            bool(
                x.get("rss")
            )
            for x in progress.values()
        )

        found_security = sum(
            bool(
                x.get("security")
            )
            for x in progress.values()
        )

        found_security_txt = sum(
            bool(
                x.get("security_txt")
            )
            for x in progress.values()
        )

        print()
        print("=" * 70)
        print(" DONE")
        print("=" * 70)
        print(
            f"Domains processed: {len(progress)}"
        )
        print(
            f"Changelogs found:  {found_changelog}"
        )
        print(
            f"RSS/Atom found:    {found_rss}"
        )
        print(
            f"Security pages:    {found_security}"
        )
        print(
            f"security.txt:      {found_security_txt}"
        )
        print()
        print(
            f"TXT:      {args.output}"
        )
        print(
            f"JSON:     {args.json}"
        )
        print(
            f"Progress: {args.progress}"
        )
        print()

    return 0


# ============================================================
# CLI
# ============================================================

def cli():

    parser = argparse.ArgumentParser(
        description=(
            "Discover product changelogs for "
            "public bug-bounty programs."
        )
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=(
            "Maximum simultaneous HTTP requests "
            "(default: 80)"
        ),
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help=(
            "Scan only N root domains. "
            "0 = all."
        ),
    )

    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help="TXT output filename",
    )

    parser.add_argument(
        "--json",
        default=DEFAULT_JSON,
        help="JSON output filename",
    )

    parser.add_argument(
        "--progress",
        default=DEFAULT_PROGRESS,
        help="Resume/progress JSON filename",
    )

    parser.add_argument(
        "--save-every",
        type=int,
        default=25,
        help=(
            "Save progress every N domains "
            "(default: 25)"
        ),
    )

    args = parser.parse_args()

    if args.concurrency < 1:
        parser.error(
            "--concurrency must be >= 1"
        )

    if args.save_every < 1:
        parser.error(
            "--save-every must be >= 1"
        )

    try:
        return run_async(
            main(args)
        )

    except KeyboardInterrupt:

        print(
            "\n[!] Interrupted. "
            "Progress has been saved."
        )

        return 130


if __name__ == "__main__":
    sys.exit(cli())
