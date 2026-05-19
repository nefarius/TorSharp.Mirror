#!/usr/bin/env python3
"""
TorSharp mirror refresh script.

Downloads the latest Tor expert bundles and Privoxy packages from their
official upstream sources, verifies SHA256 checksums (and Tor's signed
sums file), then emits a manifest.json ready for publishing as a GitHub
Release asset.

Usage:
    python3 scripts/refresh.py [--output-dir dist]
"""

import argparse
import hashlib
import html.parser
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin
from urllib.request import Request, urlopen

USER_AGENT = "TorSharp-Mirror/1.0 (+https://github.com/nefarius/TorSharp.Mirror)"

TOR_BASE_URL = "https://dist.torproject.org/torbrowser/"
PRIVOXY_DEBIAN_BASE_URL = "https://www.silvester.org.uk/privoxy/Debian/"
PRIVOXY_WINDOWS_BASE_URL = "https://www.silvester.org.uk/privoxy/Windows/"

# Base URL for mirror release assets.  Consumers use the /latest/ redirect so
# they always get the most-recent release without needing to know the tag name.
MIRROR_RELEASE_BASE_URL = "https://github.com/nefarius/TorSharp.Mirror/releases/latest/download/"

# Restrict to Debian stable releases whose dependencies are present on
# the Ubuntu LTS versions TorSharp officially supports (22.04, 24.04).
# trixie (Debian 13) links Privoxy against libmbedtls3 / libmbedtls21 which
# is NOT available on Ubuntu 24.04 LTS (noble), so we cap at bookworm.
COMPATIBLE_DEBIAN_CODENAMES: frozenset[str] = frozenset(
    {"wheezy", "jessie", "stretch", "buster", "bullseye", "bookworm"}
)

# (upstream_os, upstream_arch) -> manifest key
TOR_PLATFORMS = [
    ("windows", "i686",   "windows-x86"),
    ("windows", "x86_64", "windows-x86_64"),
    ("linux",   "i686",   "linux-x86"),
    ("linux",   "x86_64", "linux-x86_64"),
]

PRIVOXY_LINUX_ARCHES = [
    ("i386",  "linux-i386"),
    ("amd64", "linux-amd64"),
]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _fetch(url: str, *, timeout: int = 60) -> bytes:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_text(url: str) -> str:
    return _fetch(url).decode("utf-8", errors="replace")


def download_file(url: str, dest: Path) -> str:
    """Download *url* to *dest*, return hex SHA256 of the downloaded file."""
    print(f"  {url}", flush=True)
    data = _fetch(url, timeout=180)
    dest.write_bytes(data)
    return sha256_bytes(data)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# HTML link parser
# ---------------------------------------------------------------------------

class _LinkParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value)


def get_links(url: str) -> list[str]:
    parser = _LinkParser()
    parser.feed(fetch_text(url))
    return parser.links


# ---------------------------------------------------------------------------
# Tor
# ---------------------------------------------------------------------------

def get_latest_tor_version() -> str:
    """Return the latest stable Tor Browser version (no alpha/beta)."""
    links = get_links(TOR_BASE_URL)
    stable: list[tuple] = []
    for link in links:
        # Stable: "15.0.14/"; alpha/beta contain letters: "16.0a6/"
        m = re.match(r"^(\d+)\.(\d+)\.(\d+)/?$", link.rstrip("/"))
        if m:
            stable.append((int(m.group(1)), int(m.group(2)), int(m.group(3)), link.rstrip("/")))
    if not stable:
        raise RuntimeError("No stable Tor Browser version found at " + TOR_BASE_URL)
    stable.sort(reverse=True)
    return stable[0][3]


def download_tor(version: str, output_dir: Path) -> dict:
    ver_url = f"{TOR_BASE_URL}{version}/"
    sums_url = f"{ver_url}sha256sums-signed-build.txt"

    print(f"\n  Fetching SHA256 sums from {sums_url}", flush=True)
    sums_text = fetch_text(sums_url)

    # Build dict: bare filename -> sha256
    expected: dict[str, str] = {}
    for line in sums_text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            digest, fname = parts
            expected[fname.lstrip("./").strip()] = digest.lower()

    entries: dict[str, dict] = {}
    for os_name, arch, key in TOR_PLATFORMS:
        filename = f"tor-expert-bundle-{os_name}-{arch}-{version}.tar.gz"
        url = f"{ver_url}{filename}"
        dest = output_dir / filename

        print(f"\n  Downloading {filename}", flush=True)
        actual = download_file(url, dest)

        # Verify against official sums
        exp = expected.get(filename)
        if exp and actual != exp:
            raise RuntimeError(
                f"SHA256 mismatch for {filename}:\n  expected {exp}\n  got      {actual}"
            )
        if not exp:
            print(f"  WARNING: {filename} not found in sums file — checksum unverified", flush=True)

        entries[key] = {
            "version": version,
            "upstreamUrl": url,
            "url": MIRROR_RELEASE_BASE_URL + filename,
            "sha256": actual,
            "format": "TarGz",
        }

    return entries


# ---------------------------------------------------------------------------
# Privoxy
# ---------------------------------------------------------------------------

def _parse_stable_versions(listing_url: str, *, debian: bool = False) -> list[tuple]:
    """
    Return list of (version_tuple, version_str, dir_name) for all stable
    entries found in the silvester.org.uk directory listing.

    When *debian* is True, entries whose Debian codename is not in
    COMPATIBLE_DEBIAN_CODENAMES are silently skipped so we never serve a
    binary that links against shared libraries unavailable on Ubuntu LTS.
    """
    links = get_links(listing_url)
    results = []
    for link in links:
        link = link.rstrip("/")
        # Pattern: "4.1.0 (stable) trixie"  or  "4.0.0 (stable) bookworm"
        m = re.match(r"^([\d]+\.[\d]+\.[\d]+)\s+\(stable\)(?:\s+(\w+))?", link)
        if m:
            ver_str = m.group(1)
            codename = (m.group(2) or "").lower()
            if debian and codename and codename not in COMPATIBLE_DEBIAN_CODENAMES:
                print(
                    f"  Skipping {link!r} — codename '{codename}' is not in the "
                    f"compatible set {sorted(COMPATIBLE_DEBIAN_CODENAMES)}",
                    flush=True,
                )
                continue
            try:
                ver_tuple = tuple(int(x) for x in ver_str.split("."))
                results.append((ver_tuple, ver_str, link))
            except ValueError:
                pass
    return results


def _get_deb_runtime_deps(deb_path: Path) -> list[str]:
    """
    Extract Depends from the .deb control file using dpkg-deb.
    Falls back to an empty list if dpkg-deb is unavailable.
    """
    try:
        result = subprocess.run(
            ["dpkg-deb", "--field", str(deb_path), "Depends"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return []
        deps = []
        for dep in result.stdout.strip().split(","):
            dep = dep.strip()
            dep = dep.split("|")[0].strip()          # first alternative
            dep = re.sub(r"\s*\(.*?\)", "", dep).strip()  # strip version
            if dep:
                deps.append(dep)
        return deps
    except (FileNotFoundError, subprocess.SubprocessError):
        return []


def _apt_download_privoxy(deb_arch: str, output_dir: Path) -> dict | None:
    """
    Fallback: download Privoxy via apt-get download from the system package
    repository.  Works reliably on Debian/Ubuntu CI runners where silvester.org.uk
    may block the runner's IP range.

    Returns a manifest entry dict on success, None on failure.
    """
    pkg = "privoxy" if deb_arch == "amd64" else f"privoxy:{deb_arch}"

    # Enable cross-arch downloads if needed (dpkg --add-architecture + update).
    if deb_arch != "amd64":
        print(f"    Adding {deb_arch} dpkg architecture...", flush=True)
        subprocess.run(
            ["sudo", "dpkg", "--add-architecture", deb_arch],
            check=False, capture_output=True,
        )
        subprocess.run(
            ["sudo", "apt-get", "update", "-qq"],
            check=False, capture_output=True,
        )

    # Resolve version from apt-cache (e.g. "3.0.34-3" → "3.0.34").
    show = subprocess.run(
        ["apt-cache", "show", pkg],
        capture_output=True, text=True,
    )
    version: str | None = None
    for line in show.stdout.splitlines():
        if line.startswith("Version:"):
            m = re.match(r"([\d.]+)", line.split(":", 1)[1].strip())
            if m:
                version = m.group(1)
            break

    if not version:
        print(f"    apt-cache show {pkg}: package not found — skipping", flush=True)
        return None

    # apt-get download always writes to CWD.
    result = subprocess.run(
        ["apt-get", "download", pkg],
        cwd=str(output_dir),
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"    apt-get download {pkg} failed:\n{result.stderr.strip()}", flush=True)
        return None

    debs = sorted(output_dir.glob(f"privoxy_*{deb_arch}*.deb"))
    if not debs:
        print(f"    No privoxy*{deb_arch}*.deb found after apt-get download", flush=True)
        return None

    dest = debs[-1]
    actual = sha256_file(dest)
    runtime_deps = _get_deb_runtime_deps(dest)

    entry: dict = {
        "version": version,
        "url": MIRROR_RELEASE_BASE_URL + dest.name,
        "sha256": actual,
        "format": "Deb",
    }
    if runtime_deps:
        entry["runtimeDeps"] = runtime_deps
    return entry


def download_privoxy_linux(output_dir: Path) -> dict:
    # Try silvester.org.uk first; fall back to apt-get if the host blocks the
    # runner's IP (HTTP 403/timeout is common from GitHub Actions IP ranges).
    silvester_ok = True
    versions: list = []
    try:
        versions = _parse_stable_versions(PRIVOXY_DEBIAN_BASE_URL, debian=True)
        versions.sort(reverse=True)  # newest first
    except (HTTPError, URLError) as exc:
        print(f"  WARNING: Could not list silvester.org.uk ({exc}) — will use apt fallback for all arches", flush=True)
        silvester_ok = False

    # Architectures may not all be present in the same release directory
    # (e.g. bookworm 4.0.0 dropped i386).  For each arch, independently walk
    # the sorted version list and take the newest release that provides a .deb
    # for that arch.
    entries: dict[str, dict] = {}
    for deb_arch, key in PRIVOXY_LINUX_ARCHES:
        arch_pat = re.compile(
            rf"privoxy[_\-][\d.]+(?:[-_]\d+(?:~pp\+\d)?_)?{re.escape(deb_arch)}\.deb$",
            re.IGNORECASE,
        )

        found = False

        if silvester_ok and versions:
            for ver_tuple, ver_str, dir_name in versions:
                dir_url = PRIVOXY_DEBIAN_BASE_URL + quote(dir_name) + "/"
                try:
                    links = get_links(dir_url)
                except (HTTPError, URLError) as exc:
                    print(f"  WARNING: Could not fetch {dir_url} ({exc}) — switching to apt fallback for {key}", flush=True)
                    break

                filename = next(
                    (lnk.split("/")[-1] for lnk in links if arch_pat.search(lnk)),
                    None,
                )
                if not filename:
                    continue  # this version doesn't ship this arch; try older one

                url = dir_url + filename
                dest = output_dir / filename
                print(f"\n  Downloading {filename} (Privoxy {ver_str} / {dir_name})", flush=True)
                try:
                    actual = download_file(url, dest)
                except (HTTPError, URLError) as exc:
                    print(f"  WARNING: Download of {filename} failed ({exc}) — switching to apt fallback for {key}", flush=True)
                    break

                runtime_deps = _get_deb_runtime_deps(dest)

                entry: dict = {
                    "version": ver_str,
                    "upstreamUrl": url,
                    "url": MIRROR_RELEASE_BASE_URL + filename,
                    "sha256": actual,
                    "format": "Deb",
                }
                if runtime_deps:
                    entry["runtimeDeps"] = runtime_deps

                entries[key] = entry
                found = True
                break

        if not found:
            print(f"\n  Falling back to apt-get download for Privoxy {deb_arch}...", flush=True)
            entry = _apt_download_privoxy(deb_arch, output_dir)
            if entry:
                entries[key] = entry
                found = True

        if not found:
            print(f"  WARNING: No Privoxy {deb_arch} .deb found from any source — skipping {key}", flush=True)

    return entries


def download_privoxy_windows(output_dir: Path) -> dict:
    versions = _parse_stable_versions(PRIVOXY_WINDOWS_BASE_URL)
    if not versions:
        raise RuntimeError("No stable Privoxy version found at " + PRIVOXY_WINDOWS_BASE_URL)
    versions.sort(reverse=True)
    ver_tuple, ver_str, dir_name = versions[0]

    dir_url = PRIVOXY_WINDOWS_BASE_URL + quote(dir_name) + "/"
    print(f"\n  Privoxy Windows {ver_str} from {dir_url}", flush=True)

    zip_pat = re.compile(r"privoxy[-_][\d.]+\.zip$", re.IGNORECASE)
    links = get_links(dir_url)
    filename = next(
        (lnk.split("/")[-1] for lnk in links if zip_pat.search(lnk)),
        None,
    )
    if not filename:
        raise RuntimeError(f"No Privoxy Windows .zip found at {dir_url}")

    url = dir_url + filename
    dest = output_dir / filename
    print(f"\n  Downloading {filename}", flush=True)
    actual = download_file(url, dest)

    return {
        "windows": {
            "version": ver_str,
            "upstreamUrl": url,
            "url": MIRROR_RELEASE_BASE_URL + filename,
            "sha256": actual,
            "format": "Zip",
        }
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Refresh TorSharp mirror artifacts")
    ap.add_argument("--output-dir", default="dist", help="Directory for downloads + manifest.json")
    args = ap.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=== Discovering latest Tor version ===", flush=True)
    tor_version = get_latest_tor_version()
    print(f"Latest stable Tor Browser: {tor_version}", flush=True)

    print("\n=== Downloading Tor expert bundles ===", flush=True)
    tor_entries = download_tor(tor_version, output_dir)

    print("\n=== Downloading Privoxy (Linux) ===", flush=True)
    privoxy_entries = download_privoxy_linux(output_dir)

    print("\n=== Downloading Privoxy (Windows) ===", flush=True)
    privoxy_entries.update(download_privoxy_windows(output_dir))

    manifest = {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tor": tor_entries,
        "privoxy": privoxy_entries,
    }

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"\n=== manifest.json written to {manifest_path} ===", flush=True)
    print(json.dumps(manifest, indent=2), flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
