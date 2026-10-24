"""
VulnScope Remediation Guidance Service.
Generates structured, category-specific, deterministic remediation recommendations.
"""

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, List, Optional


@dataclass
class RemediationGuidance:
    """Structured remediation guidance object."""
    category: str
    summary: str
    steps: List[str]
    unsafe_pattern: Optional[str] = None
    safer_alternative: Optional[str] = None
    caveats: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    fixed_version: Optional[str] = None
    package_ecosystem: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RemediationService:
    """
    Produces actionable, deterministic remediation guidance based on verified finding data.
    Never executes auto-fixes, edits manifests, or fabricates fix versions.
    """

    # Trusted domain allowlist for authoritative references
    TRUSTED_REFERENCE_DOMAINS = (
        "owasp.org",
        "cwe.mitre.org",
        "nvd.nist.gov",
        "github.com/advisories",
        "osv.dev",
        "semgrep.dev",
        "python.org",
        "cheatsheetseries.owasp.org",
    )

    @classmethod
    def _is_trusted_url(cls, url: Optional[str]) -> bool:
        if not url:
            return False
        clean = url.strip().lower()
        if not (clean.startswith("https://") or clean.startswith("http://")):
            return False
        return any(domain in clean for domain in cls.TRUSTED_REFERENCE_DOMAINS)

    @classmethod
    def generate_remediation(
        cls,
        category: Optional[str],
        rule_id: Optional[str] = None,
        scanner_name: Optional[str] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
        package_name: Optional[str] = None,
        package_version: Optional[str] = None,
        ecosystem: Optional[str] = None,
        fixed_version: Optional[str] = None,
        advisory_url: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> RemediationGuidance:
        """
        Produce structured remediation guidance tailored to finding category and verified attributes.
        """
        cat = (category or "").strip().lower()
        rule = (rule_id or "").strip()

        if cat == "secret" or (scanner_name and "gitleaks" in scanner_name.lower()):
            return cls._remediation_for_secret(rule, file_path)
        elif cat == "dependency" or (scanner_name and "osv" in scanner_name.lower()):
            return cls._remediation_for_dependency(
                package_name=package_name,
                package_version=package_version,
                ecosystem=ecosystem,
                fixed_version=fixed_version,
                advisory_url=advisory_url,
            )
        else:
            return cls._remediation_for_code(
                rule_id=rule,
                title=title,
                description=description,
                advisory_url=advisory_url,
                file_path=file_path,
            )

    @classmethod
    def _remediation_for_secret(cls, rule_id: str, file_path: Optional[str]) -> RemediationGuidance:
        steps = [
            "Immediately revoke or rotate the exposed credential in the issuing service or provider console.",
            "Audit access logs, audit trails, and monitoring systems for any unauthorized use of the exposed key.",
            "Replace hardcoded credential strings with environment variables or an enterprise secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, or Doppler).",
            "Update local configuration and ensure secret-bearing configuration files (e.g. .env, credentials.json) are listed in .gitignore.",
            "If the commit was pushed to a shared or public repository, purge Git commit history using 'git filter-repo' or BFG Repo-Cleaner after rotation has been completed.",
        ]
        caveats = [
            "CRITICAL: Removing or editing the secret in the source file does NOT invalidate the exposed credential. The secret must be revoked at the provider.",
            "Rewriting Git history does NOT replace credential rotation. Any exposed key must be treated as compromised immediately.",
        ]
        references = [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://git-scm.com/docs/git-filter-repo",
        ]
        return RemediationGuidance(
            category="secret",
            summary="Revoke and rotate exposed credential immediately; migrate to environment variables or a secrets manager.",
            steps=steps,
            unsafe_pattern="Hardcoded credential or API token stored directly in repository files.",
            safer_alternative="Load credentials at runtime via environment variables or a secrets manager service.",
            caveats=caveats,
            references=references,
        )

    @classmethod
    def _remediation_for_dependency(
        cls,
        package_name: Optional[str],
        package_version: Optional[str],
        ecosystem: Optional[str],
        fixed_version: Optional[str],
        advisory_url: Optional[str],
    ) -> RemediationGuidance:
        pkg = package_name or "the affected package"
        cur_ver = package_version or "installed version"

        refs: List[str] = []
        if cls._is_trusted_url(advisory_url):
            refs.append(advisory_url.strip())

        caveats = [
            "Always inspect changelogs and release notes for breaking changes before upgrading dependencies.",
            "Run automated regression tests in a staging environment prior to deploying dependency updates.",
        ]

        if fixed_version and fixed_version.strip():
            target_fix = fixed_version.strip()
            summary = f"Upgrade {pkg} from {cur_ver} to patched version {target_fix} or later."
            steps = [
                f"Upgrade {pkg} from {cur_ver} to patched version {target_fix} or later in your package manifest or lockfile.",
                f"Review changelog and API deprecations for {pkg} between {cur_ver} and {target_fix}.",
                "Execute test suites and verify application functionality against the updated library.",
                "Commit the updated lockfile and manifest to source control.",
            ]
            unsafe_pattern = f"Vulnerable package release {pkg} ({cur_ver}) referenced in project dependencies."
            safer_alternative = f"Patched package release {pkg} ({target_fix}) or latest stable release."
        else:
            summary = f"No verified upstream fixed version is currently recorded for {pkg}."
            steps = [
                f"Check the upstream repository and advisory tracker for {pkg} for pending security releases.",
                "Assess whether vulnerable code paths in the library are reachable in your project.",
                "Implement compensating controls (e.g. strict input validation, isolation, or virtual patching).",
                "Consider temporarily replacing the dependency with an alternative maintained library if no fix is scheduled.",
            ]
            unsafe_pattern = f"Unpatched security vulnerability in {pkg} ({cur_ver}) without an official fix."
            safer_alternative = "Apply defensive input validation or isolate vulnerable components until upstream patch is released."
            caveats.append("No automated fix version could be determined from scanner or advisory data.")

        return RemediationGuidance(
            category="dependency",
            summary=summary,
            steps=steps,
            unsafe_pattern=unsafe_pattern,
            safer_alternative=safer_alternative,
            caveats=caveats,
            references=refs,
            fixed_version=fixed_version if fixed_version and fixed_version.strip() else None,
            package_ecosystem=ecosystem,
        )

    @classmethod
    def _remediation_for_code(
        cls,
        rule_id: str,
        title: Optional[str],
        description: Optional[str],
        advisory_url: Optional[str],
        file_path: Optional[str],
    ) -> RemediationGuidance:
        rule_lower = rule_id.lower()
        desc_lower = (description or "").lower()

        refs: List[str] = []
        if cls._is_trusted_url(advisory_url):
            refs.append(advisory_url.strip())

        # Check for specific vulnerability classes
        if "sql" in rule_lower or "sql" in desc_lower:
            summary = "Refactor dynamic database queries to use parameterized prepared statements or an ORM."
            steps = [
                "Replace string formatting, concatenation, or interpolation in SQL queries with parameterized query placeholders (? or %s).",
                "Pass dynamic user values as separate bind parameters to the database driver.",
                "Ensure database user accounts follow the principle of least privilege.",
            ]
            unsafe = "Executing SQL queries constructed via string concatenation with user-supplied values."
            safer = "cursor.execute('SELECT * FROM records WHERE id = %s', (record_id,))"
            if not refs:
                refs.append("https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")

        elif any(k in rule_lower for k in ("command", "subprocess", "exec", "shell")):
            summary = "Avoid shell invocation with dynamic parameters; use parameterized argument lists."
            steps = [
                "Disable shell interpretation by ensuring shell=False in subprocess calls.",
                "Pass executable arguments as an explicit list of strings rather than a concatenated command string.",
                "Validate all arguments against a strict allowlist of permitted values.",
            ]
            unsafe = "subprocess.run(f'cmd {user_arg}', shell=True)"
            safer = "subprocess.run(['cmd', user_arg], shell=False, check=True)"
            if not refs:
                refs.append("https://owasp.org/www-community/attacks/Command_Injection")

        elif any(k in rule_lower for k in ("deserializ", "pickle", "yaml")):
            summary = "Avoid deserializing untrusted data with unsafe deserializers."
            steps = [
                "Replace Python pickle or unsafe YAML loaders with standardized serialization formats such as JSON.",
                "If YAML must be used, always specify yaml.safe_load().",
                "Verify HMAC cryptographic signatures before processing serialized data from untrusted sources.",
            ]
            unsafe = "pickle.loads(untrusted_data) or yaml.load(data, Loader=Loader)"
            safer = "json.loads(untrusted_data) or yaml.safe_load(data)"
            if not refs:
                refs.append("https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data")

        elif any(k in rule_lower for k in ("traversal", "path", "file")):
            summary = "Canonicalize file paths and enforce strict base directory boundaries."
            steps = [
                "Canonicalize the requested path using os.path.realpath() or Path.resolve().",
                "Verify that the canonical path begins with the authorized base directory prefix.",
                "Reject paths containing directory traversal tokens (e.g., '../') or absolute prefixes.",
            ]
            unsafe = "open(f'/var/data/{user_path}', 'r')"
            safer = "target = (base_dir / user_path).resolve(); if not target.is_relative_to(base_dir): raise ValueError()"
            if not refs:
                refs.append("https://owasp.org/www-community/attacks/Path_Traversal")

        elif any(k in rule_lower for k in ("xss", "cross-site", "html")):
            summary = "Apply contextual HTML encoding and enforce Content Security Policy (CSP)."
            steps = [
                "Ensure untrusted dynamic data is contextually HTML-encoded before inserting into HTML templates or the DOM.",
                "Use frontend frameworks (e.g., React, Vue) that escape content by default.",
                "Deploy Content Security Policy (CSP) headers to restrict script execution origins.",
            ]
            unsafe = "element.innerHTML = user_input or <div dangerouslySetInnerHTML=... />"
            safer = "element.textContent = user_input (or framework text bindings)"
            if not refs:
                refs.append("https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html")

        else:
            summary = f"Review and remediate security flaw flagged by rule '{rule_id}'."
            steps = [
                "Inspect the flagged code line and trace data flow from untrusted inputs to the sink.",
                "Apply strict input validation, type assertions, and defensive error handling.",
                "Consult the scanner rule documentation and relevant language security guides.",
            ]
            unsafe = "Detected pattern flagged by static analysis rules."
            safer = "Refactor logic to adhere to defensive programming standards."

        caveats = [
            "Guidance is derived from static analysis rule metadata and does not replace manual code review.",
            "Verify all proposed logic changes against project test suites.",
        ]

        return RemediationGuidance(
            category="code",
            summary=summary,
            steps=steps,
            unsafe_pattern=unsafe,
            safer_alternative=safer,
            caveats=caveats,
            references=refs,
        )

    @classmethod
    def get_guidance_for_finding(cls, finding: Any) -> RemediationGuidance:
        """Helper to generate guidance directly from a Finding model or dict."""
        def get_attr(key: str, default: Any = None) -> Any:
            if isinstance(finding, dict):
                return finding.get(key, default)
            return getattr(finding, key, default)

        return cls.generate_remediation(
            category=get_attr("category"),
            rule_id=get_attr("rule_id"),
            scanner_name=get_attr("scanner_name"),
            title=get_attr("title"),
            description=get_attr("description"),
            package_name=get_attr("package_name"),
            package_version=get_attr("package_version"),
            ecosystem=get_attr("ecosystem"),
            fixed_version=get_attr("fixed_version"),
            advisory_url=get_attr("advisory_url"),
            file_path=get_attr("file_path"),
        )
