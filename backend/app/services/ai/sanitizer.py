"""
Defense-in-depth source code sanitizer, secret redactor, and snippet extractor.
Protects sensitive repository files, credentials, and API tokens from reaching AI models,
logs, or API responses.
"""

from pathlib import Path, PurePosixPath
import re
from typing import Optional, Set


class RedactionService:
    """
    Sanitizes untrusted repository contents and scanner evidence before AI processing.
    Ensures secrets, private keys, and sensitive configuration files are never dispatched.
    """

    # Disallowed sensitive file patterns and extensions
    SENSITIVE_EXTENSIONS: Set[str] = {
        ".pem",
        ".key",
        ".pfx",
        ".p12",
        ".crt",
        ".cer",
        ".der",
        ".jks",
        ".kdbx",
        ".keystore",
    }

    SENSITIVE_FILENAMES: Set[str] = {
        ".env",
        ".env.local",
        ".env.production",
        ".env.staging",
        "id_rsa",
        "id_ed25519",
        "id_dsa",
        "id_ecdsa",
        "credentials",
        "credentials.json",
        "serviceaccountkey.json",
        "secrets.yaml",
        "secrets.yml",
        ".htpasswd",
        ".netrc",
        "wp-config.php",
    }

    # High-confidence regex patterns for automated secret redaction
    SECRET_PATTERNS = [
        # AWS Access Key ID
        (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_AWS_KEY]"),
        # AWS Secret Access Key assignment
        (
            re.compile(r"(?i)(aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
            r"\1=[REDACTED_AWS_SECRET]",
        ),
        # GitHub Personal Access Tokens / App Tokens
        (re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"), "[REDACTED_GITHUB_TOKEN]"),
        (re.compile(r"\b(github_pat_[A-Za-z0-9_]{40,255})\b"), "[REDACTED_GITHUB_TOKEN]"),
        # Slack Tokens
        (re.compile(r"\b(xox[baprs]-[0-9a-zA-Z-]{10,255})\b"), "[REDACTED_SLACK_TOKEN]"),
        # Stripe API Keys
        (re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"), "[REDACTED_STRIPE_KEY]"),
        (re.compile(r"\b(rk_live_[0-9a-zA-Z]{24,})\b"), "[REDACTED_STRIPE_KEY]"),
        # PEM Private Key Blocks
        (
            re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
            "[REDACTED_PRIVATE_KEY_BLOCK]",
        ),
        # OpenSSH Private Keys
        (
            re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----"),
            "[REDACTED_OPENSSH_KEY_BLOCK]",
        ),
        # Generic Passwords & Secrets assignments in code/config
        (
            re.compile(
                r"(?i)\b(api_key|apikey|secret|password|passwd|auth_token|access_token|private_key|client_secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
            ),
            r'\1="[REDACTED_SECRET]"',
        ),
        # Authorization Header Bearer / Basic Tokens
        (
            re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
            r"\1[REDACTED_BEARER_TOKEN]",
        ),
        (
            re.compile(r"(?i)(authorization\s*:\s*basic\s+)[A-Za-z0-9+/]+=*", re.IGNORECASE),
            r"\1[REDACTED_BASIC_AUTH]",
        ),
        # JSON Web Tokens (JWT)
        (
            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
            "[REDACTED_JWT_TOKEN]",
        ),
    ]

    @classmethod
    def redact_secrets(cls, content: Optional[str]) -> str:
        """
        Apply defense-in-depth regex redaction to strip potential secrets, credentials,
        and tokens from text.
        """
        if not content:
            return ""

        redacted = content
        for pattern, replacement in cls.SECRET_PATTERNS:
            redacted = pattern.sub(replacement, redacted)

        return redacted

    @classmethod
    def is_sensitive_file(cls, file_path: Optional[str]) -> bool:
        """
        Determine whether a repository-relative file path references a sensitive configuration,
        credential store, or private key file that should never be sent to an AI provider.
        """
        if not file_path:
            return False

        clean_path = file_path.replace("\\", "/").lower().strip()
        filename = PurePosixPath(clean_path).name

        # Match exact sensitive filename
        if filename in cls.SENSITIVE_FILENAMES or filename.startswith(".env"):
            return True

        # Match sensitive extension
        suffix = PurePosixPath(clean_path).suffix
        if suffix in cls.SENSITIVE_EXTENSIONS:
            return True

        # Match hidden credential directories
        if "/.ssh/" in f"/{clean_path}" or "/.aws/" in f"/{clean_path}":
            return True

        return False

    @classmethod
    def extract_source_snippet(
        cls,
        workspace_source_dir: Path,
        rel_file_path: Optional[str],
        start_line: Optional[int],
        end_line: Optional[int] = None,
        max_lines: int = 20,
        max_bytes: int = 4096,
    ) -> Optional[str]:
        """
        Safely extract a bounded, redacted source code snippet surrounding a finding.
        Enforces path traversal defenses, sensitive file exclusions, line limits, and byte limits.
        """
        if not rel_file_path:
            return None

        # Clean relative path
        clean_rel = rel_file_path.replace("\\", "/").lstrip("/")
        if ".." in clean_rel.split("/"):
            return None

        # Exclude sensitive files entirely
        if cls.is_sensitive_file(clean_rel):
            return "[REDACTED: SENSITIVE FILE CONTENT EXCLUDED]"

        target_file = (workspace_source_dir / clean_rel).resolve()
        source_root = workspace_source_dir.resolve()

        # Validate file is strictly inside source directory and exists
        try:
            target_file.relative_to(source_root)
        except ValueError:
            return None

        if not target_file.is_file():
            return None

        try:
            raw_text = target_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

        lines = raw_text.splitlines()
        total_lines = len(lines)
        if total_lines == 0:
            return None

        target_line = start_line if (start_line and start_line > 0) else 1
        half_window = max(1, max_lines // 2)

        start_idx = max(0, target_line - 1 - half_window)
        end_idx = min(total_lines, target_line + half_window)

        # Include snippet with 1-based line numbers
        snippet_lines = []
        for idx in range(start_idx, end_idx):
            line_no = idx + 1
            marker = " > " if (line_no == target_line) else "   "
            snippet_lines.append(f"{line_no:4d}{marker}{lines[idx]}")

        snippet_text = "\n".join(snippet_lines)

        # Enforce maximum byte limit
        if len(snippet_text.encode("utf-8")) > max_bytes:
            snippet_text = snippet_text[:max_bytes] + "\n... [SNIPPET TRUNCATED TO BOUNDED SIZE]"

        # Redact any embedded secrets in snippet
        return cls.redact_secrets(snippet_text)
