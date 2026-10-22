"""
Constrained Public GitHub Repository Snapshot Acquisition Service.
Enforces defense-in-depth protections:
- Scheme & Hostname Validation (Strictly HTTPS, public github.com only)
- Credential & Port Stripping (Rejects user:pass@ and non-standard ports)
- Strict SSRF Defense (Pre-flight DNS resolution rejecting loopback, link-local, and RFC1918 IPs)
- Unrestricted Redirect Defense (Validates every redirect target against allowed GitHub hosts & public IPs)
- Bounded Streaming Download (Enforces timeouts and maximum snapshot size limits)
- Integration with SafeArchiveValidator for zero extraction duplication.
"""

import ipaddress
from pathlib import Path
import re
import socket
from typing import Optional, Set, Tuple
import urllib.parse

import httpx

from app.core.config import Settings, settings


class GithubError(Exception):
    """Base exception for GitHub acquisition errors."""
    pass


class GithubValidationError(GithubError):
    """Raised for malformed URLs, forbidden schemes, or invalid repository parameters."""
    pass


class GithubSSRFError(GithubError):
    """Raised when a request target attempts to access private networks, localhost, or cloud metadata."""
    pass


class GithubNotFoundError(GithubError):
    """Raised when repository or reference is not found or is private."""
    pass


class GithubRateLimitError(GithubError):
    """Raised when GitHub API rate limits or secondary limits are encountered."""
    pass


class GithubLimitError(GithubError):
    """Raised when the snapshot download exceeds configured size limits."""
    pass


class GithubNetworkError(GithubError):
    """Raised on connection failure or network timeout."""
    pass


# Strictly approved hostnames for GitHub snapshot retrieval
ALLOWED_GITHUB_ENTRY_HOSTS: Set[str] = {
    "github.com",
    "www.github.com",
}

ALLOWED_GITHUB_DOWNLOAD_HOSTS: Set[str] = {
    "github.com",
    "www.github.com",
    "api.github.com",
    "codeload.github.com",
}


def parse_and_validate_github_url(url: str) -> Tuple[str, str]:
    """
    Parse and validate a public GitHub repository URL.
    Returns (owner, repo).
    Rejects credentials, non-HTTPS schemes, unexpected ports, and non-github.com hosts.
    """
    if not url or not isinstance(url, str):
        raise GithubValidationError("GitHub repository URL must be a non-empty string.")

    trimmed = url.strip()
    try:
        parsed = urllib.parse.urlsplit(trimmed)
    except Exception as exc:
        raise GithubValidationError(f"Invalid URL structure: {exc}") from exc

    # 1. Scheme validation
    if parsed.scheme.lower() != "https":
        raise GithubValidationError("Only secure HTTPS GitHub URLs are accepted.")

    # 2. Reject credentials in URL
    if parsed.username or parsed.password:
        raise GithubValidationError("Embedded credentials in repository URLs are strictly forbidden.")

    # 3. Port validation (default 443 only)
    if parsed.port is not None and parsed.port != 443:
        raise GithubValidationError(f"Non-standard port '{parsed.port}' is forbidden for GitHub intake.")

    # 4. Hostname validation
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise GithubValidationError("Repository URL is missing a valid hostname.")

    if hostname not in ALLOWED_GITHUB_ENTRY_HOSTS:
        raise GithubValidationError(
            f"Unsupported host '{hostname}'. Only public GitHub repositories (github.com) are supported."
        )

    # 5. Path validation: must be /{owner}/{repo} (optional trailing slash or .git)
    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]

    path_parts = [p for p in path.split("/") if p]
    if len(path_parts) != 2:
        raise GithubValidationError(
            f"Invalid GitHub repository path '{parsed.path}'. Expected format: 'https://github.com/owner/repository'."
        )

    owner, repo = path_parts[0], path_parts[1]

    # Validate owner & repo name syntax
    name_regex = re.compile(r"^[a-zA-Z0-9_.-]+$")
    if not name_regex.match(owner) or owner in (".", ".."):
        raise GithubValidationError(f"Invalid repository owner name: '{owner}'.")
    if not name_regex.match(repo) or repo in (".", ".."):
        raise GithubValidationError(f"Invalid repository name: '{repo}'.")

    # Disallow reserved GitHub web paths as owner
    reserved_prefixes = {"settings", "orgs", "explore", "topics", "features", "pricing", "login", "join"}
    if owner.lower() in reserved_prefixes:
        raise GithubValidationError(f"Forbidden or reserved repository path prefix: '{owner}'.")

    return owner, repo


def validate_git_ref(ref: Optional[str]) -> Optional[str]:
    """
    Validate an optional git branch, tag, or commit SHA.
    """
    if ref is None:
        return None

    trimmed = ref.strip()
    if not trimmed:
        return None

    if len(trimmed) > 200:
        raise GithubValidationError("Git reference exceeds maximum allowed length of 200 characters.")

    ref_regex = re.compile(r"^[a-zA-Z0-9_./-]+$")
    if not ref_regex.match(trimmed):
        raise GithubValidationError(f"Invalid characters detected in git reference: '{trimmed}'.")

    if ".." in trimmed or "@{" in trimmed or "//" in trimmed or trimmed.startswith("/") or trimmed.endswith("/"):
        raise GithubValidationError(f"Forbidden path traversal sequence detected in git reference: '{trimmed}'.")

    return trimmed


class GithubIntakeService:
    """
    Acquires snapshots of public GitHub repositories using a constrained HTTP client.
    """

    def __init__(self, app_settings: Optional[Settings] = None):
        self.settings = app_settings or settings

    def verify_ssrf_safety(self, url: str) -> str:
        """
        Verify that the URL targets an approved GitHub host and that all resolved
        IP addresses are valid public/global internet addresses (no loopback, private,
        or metadata IP addresses).
        """
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme != "https":
            raise GithubSSRFError("Blocked non-HTTPS redirect or request.")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise GithubSSRFError("Target URL is missing a valid hostname.")

        if hostname not in ALLOWED_GITHUB_DOWNLOAD_HOSTS:
            raise GithubSSRFError(
                f"Blocked access to non-approved destination host: '{hostname}'."
            )

        port = parsed.port or 443

        # Resolve hostname via DNS and inspect resolved IPs
        try:
            addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise GithubNetworkError(f"DNS resolution failed for '{hostname}': {exc}") from exc

        if not addr_info:
            raise GithubNetworkError(f"DNS resolution returned no addresses for '{hostname}'.")

        for entry in addr_info:
            sockaddr = entry[4]
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                raise GithubSSRFError(f"Unparseable IP address returned for '{hostname}': '{ip_str}'.")

            # Check for non-public IP ranges
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or not ip.is_global:
                raise GithubSSRFError(
                    f"Blocked SSRF attempt: host '{hostname}' resolved to prohibited non-global address '{ip_str}'."
                )

        return url

    def download_snapshot(
        self,
        owner: str,
        repo: str,
        ref: Optional[str],
        destination_zip: Path,
    ) -> Path:
        """
        Download a public repository snapshot from GitHub to destination_zip.
        Follows up to 3 redirects, validating each against SSRF rules.
        Limits download size to max_github_download_size_bytes.
        """
        destination_zip = Path(destination_zip).resolve()
        destination_zip.parent.mkdir(parents=True, exist_ok=True)

        if ref:
            target_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{urllib.parse.quote(ref, safe='')}"
        else:
            target_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"

        headers = {
            "User-Agent": "VulnScope-Intake/0.2.0 (Security-Scanner-Intake)",
            "Accept": "application/vnd.github+json",
        }

        timeout = httpx.Timeout(
            connect=self.settings.github_connect_timeout_seconds,
            read=self.settings.github_read_timeout_seconds,
            write=10.0,
            pool=10.0,
        )

        max_redirects = 3
        current_url = target_url

        try:
            with httpx.Client(timeout=timeout, follow_redirects=False) as client:
                for redirect_hop in range(max_redirects + 1):
                    # Validate URL and enforce SSRF check before opening connection
                    self.verify_ssrf_safety(current_url)

                    try:
                        with client.stream("GET", current_url, headers=headers) as response:
                            status_code = response.status_code

                            # Handle Redirects
                            if status_code in (301, 302, 303, 307, 308):
                                location = response.headers.get("Location")
                                if not location:
                                    raise GithubError("GitHub redirect response missing Location header.")

                                if redirect_hop >= max_redirects:
                                    raise GithubError("Exceeded maximum allowed redirects for GitHub acquisition.")

                                # Resolve relative redirect if necessary
                                next_url = urllib.parse.urljoin(current_url, location)
                                current_url = next_url
                                continue

                            # Handle 404
                            if status_code == 404:
                                raise GithubNotFoundError(
                                    f"GitHub repository '{owner}/{repo}' not found or is private."
                                )

                            # Handle Rate Limits
                            if status_code in (403, 429):
                                raise GithubRateLimitError(
                                    "GitHub API rate limit exceeded or access forbidden."
                                )

                            # Handle other client/server errors
                            if status_code >= 400:
                                raise GithubError(
                                    f"GitHub acquisition request failed with HTTP {status_code}."
                                )

                            # Success (HTTP 200) -> Stream to file with strict size enforcement
                            total_downloaded = 0
                            chunk_size = 64 * 1024

                            with open(destination_zip, "wb") as f_out:
                                for chunk in response.iter_bytes(chunk_size=chunk_size):
                                    if not chunk:
                                        continue
                                    chunk_len = len(chunk)
                                    total_downloaded += chunk_len

                                    if total_downloaded > self.settings.max_github_download_size_bytes:
                                        raise GithubLimitError(
                                            f"GitHub snapshot download exceeded maximum limit of "
                                            f"{self.settings.max_github_download_size_bytes} bytes."
                                        )

                                    f_out.write(chunk)

                            return destination_zip

                    except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
                        raise GithubNetworkError(f"Network timeout while contacting GitHub: {exc}") from exc
                    except (httpx.ConnectError, httpx.NetworkError) as exc:
                        raise GithubNetworkError(f"Network connection failed while contacting GitHub: {exc}") from exc

        except Exception:
            # Clean up destination file on any failure
            if destination_zip.exists():
                try:
                    destination_zip.unlink()
                except OSError:
                    pass
            raise

        raise GithubError("Failed to acquire GitHub repository snapshot.")


# Global instance
github_intake_service = GithubIntakeService()
