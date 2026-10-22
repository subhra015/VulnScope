"""
Safe Archive Validation & Extraction Service.
Enforces defense-in-depth protections against:
- Zip Slip (path traversal: parent directories, absolute paths, backslashes, null bytes)
- Zip Bombs (uncompressed size limits, individual file limits, excessive compression ratios)
- Unsupported / dangerous entry types (symbolic links, hard links, FIFOs, device nodes)
- Structural abuse (excessive entry count, extreme directory nesting, conflicting/duplicate paths)
- Extraction escape (verifies every resolved path strictly remains within target directory)
"""

import os
from pathlib import Path
import re
import stat
from typing import Any, Dict, List, Optional, Set
import zipfile

from app.core.config import Settings, settings


class ArchiveError(Exception):
    """Base exception for all archive operations."""
    pass


class ArchiveValidationError(ArchiveError):
    """Raised when an archive is corrupted, empty, duplicate, or structurally invalid."""
    pass


class ArchiveSecurityError(ArchiveError):
    """Raised when an archive entry attempts path traversal, symlinks, or forbidden types."""
    pass


class ArchiveLimitError(ArchiveError):
    """Raised when an archive exceeds size, entry count, nesting depth, or compression ratio limits."""
    pass


class SafeArchiveValidator:
    """
    Validates and extracts ZIP archives under strict security constraints.
    """

    def __init__(self, app_settings: Optional[Settings] = None):
        self.settings = app_settings or settings

    def extract_and_validate(
        self,
        archive_path: Path,
        target_dir: Path,
    ) -> Dict[str, Any]:
        """
        Validate and extract an archive into target_dir.
        If validation or extraction fails at any point, raises an appropriate ArchiveError.
        The caller is responsible for cleaning up the target_dir / workspace.

        Returns a dictionary summarizing extraction metrics:
        {
            "file_count": int,
            "total_uncompressed_bytes": int,
            "target_dir": str,
        }
        """
        archive_path = Path(archive_path).resolve()
        target_dir = Path(target_dir).resolve()

        # Step 1: Validate archive file format
        if not archive_path.is_file():
            raise ArchiveValidationError(f"Archive file does not exist: {archive_path.name}")

        if not zipfile.is_zipfile(archive_path):
            raise ArchiveValidationError("Uploaded file is not a valid ZIP archive.")

        try:
            with zipfile.ZipFile(archive_path, mode="r") as zf:
                infolist = zf.infolist()

                # Step 2: Empty archive check
                if not infolist:
                    raise ArchiveValidationError("ZIP archive is empty. At least one file is required.")

                regular_files = [e for e in infolist if not e.is_dir()]
                if not regular_files:
                    raise ArchiveValidationError("ZIP archive contains no files.")

                # Step 3: Archive entry count check
                if len(infolist) > self.settings.max_file_count:
                    raise ArchiveLimitError(
                        f"Archive entry count ({len(infolist)}) exceeds maximum limit of "
                        f"{self.settings.max_file_count} entries."
                    )

                # Step 4: Pre-scan and structural validation
                self._validate_archive_structure(infolist)

                # Step 5: Safe streaming extraction
                metrics = self._stream_extract(zf, infolist, target_dir)
                return metrics

        except zipfile.BadZipFile as exc:
            raise ArchiveValidationError("Uploaded file is not a valid or readable ZIP archive.") from exc

    def _validate_archive_structure(self, infolist: List[zipfile.ZipInfo]) -> None:
        """
        Scan all ZipInfo headers prior to extraction to detect path traversal,
        absolute paths, symlinks, duplicate paths, nesting depth, and size limits.
        """
        declared_total_size = 0
        seen_paths: Set[str] = set()
        seen_files: Set[str] = set()
        seen_dirs: Set[str] = set()

        for info in infolist:
            raw_name = info.filename

            # 1. Null byte detection
            if "\0" in raw_name:
                raise ArchiveSecurityError(
                    f"Null byte detected in archive entry name: '{raw_name}'."
                )

            # 2. Normalize path separators to forward slash
            norm_name = raw_name.replace("\\", "/")

            # 3. Reject absolute paths
            if (
                norm_name.startswith("/")
                or norm_name.startswith("\\")
                or re.match(r"^[a-zA-Z]:", norm_name)
            ):
                raise ArchiveSecurityError(
                    f"Absolute paths are forbidden in archive: '{raw_name}'."
                )

            # 4. Path traversal and component check
            raw_parts = norm_name.split("/")
            parts = [p for p in raw_parts if p]

            if not parts and not info.is_dir():
                raise ArchiveValidationError(f"Archive entry has an invalid empty filename: '{raw_name}'.")

            for part in parts:
                if part in ("..", "."):
                    raise ArchiveSecurityError(
                        f"Path traversal component '{part}' detected in entry: '{raw_name}'."
                    )
                # Disallow alternate data streams or device namespaces on Windows
                if ":" in part:
                    raise ArchiveSecurityError(
                        f"Forbidden stream or device separator ':' detected in entry: '{raw_name}'."
                    )

            # 5. Nesting depth check
            if len(parts) > self.settings.max_directory_depth:
                raise ArchiveLimitError(
                    f"Directory nesting depth ({len(parts)}) exceeds maximum limit of "
                    f"{self.settings.max_directory_depth} for entry: '{raw_name}'."
                )

            # 6. Symlink and special entry check (Unix external_attr)
            # The upper 16 bits of external_attr represent the Unix file mode
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode != 0:
                if stat.S_ISLNK(unix_mode):
                    raise ArchiveSecurityError(
                        f"Symbolic links are forbidden in archive: '{raw_name}'."
                    )
                if stat.S_ISFIFO(unix_mode) or stat.S_ISCHR(unix_mode) or stat.S_ISBLK(unix_mode) or stat.S_ISSOCK(unix_mode):
                    raise ArchiveSecurityError(
                        f"Unsupported special device or socket entry in archive: '{raw_name}'."
                    )

            # 7. Duplicate and conflicting path validation (case-insensitive collision prevention)
            normalized_key = "/".join(parts).lower()
            if not normalized_key and info.is_dir():
                continue

            if normalized_key in seen_paths:
                raise ArchiveValidationError(
                    f"Duplicate or conflicting path detected in archive: '{raw_name}'."
                )
            seen_paths.add(normalized_key)

            if info.is_dir():
                if normalized_key in seen_files:
                    raise ArchiveValidationError(
                        f"Conflicting path (directory matches existing file): '{raw_name}'."
                    )
                seen_dirs.add(normalized_key)
            else:
                if normalized_key in seen_dirs:
                    raise ArchiveValidationError(
                        f"Conflicting path (file matches existing directory): '{raw_name}'."
                    )
                # Ensure no ancestor of this file was registered as a file
                for i in range(1, len(parts)):
                    ancestor = "/".join(parts[:i]).lower()
                    if ancestor in seen_files:
                        raise ArchiveValidationError(
                            f"Conflicting path: ancestor '{ancestor}' of file '{raw_name}' is already a file."
                        )
                seen_files.add(normalized_key)

            # 8. Individual and cumulative declared size limits
            if not info.is_dir():
                if info.file_size > self.settings.max_file_size_bytes:
                    raise ArchiveLimitError(
                        f"File '{raw_name}' declared size ({info.file_size} bytes) exceeds "
                        f"maximum individual file limit of {self.settings.max_file_size_bytes} bytes."
                    )
                declared_total_size += info.file_size
                if declared_total_size > self.settings.max_expanded_size_bytes:
                    raise ArchiveLimitError(
                        f"Archive total declared uncompressed size exceeds limit of "
                        f"{self.settings.max_expanded_size_bytes} bytes."
                    )

                # 9. Zip bomb compression ratio check
                # Only evaluate files above 1KB uncompressed to avoid false positives on tiny text files
                if info.compress_size > 0 and info.file_size > 1024:
                    ratio = info.file_size / info.compress_size
                    if ratio > self.settings.max_compression_ratio:
                        raise ArchiveLimitError(
                            f"Excessive compression ratio ({ratio:.1f}:1) detected for entry "
                            f"'{raw_name}' (potential ZIP bomb)."
                        )

    def _stream_extract(
        self,
        zf: zipfile.ZipFile,
        infolist: List[zipfile.ZipInfo],
        target_dir: Path,
    ) -> Dict[str, Any]:
        """
        Extract entries with chunked streaming, dynamically counting uncompressed
        bytes to prevent bypass via falsified zip header sizes.
        """
        target_dir.mkdir(parents=True, exist_ok=True)
        chunk_size = 64 * 1024  # 64 KB streaming buffer
        total_extracted_bytes = 0
        extracted_file_count = 0

        for info in infolist:
            norm_name = info.filename.replace("\\", "/")
            parts = [p for p in norm_name.split("/") if p]
            if not parts:
                continue

            # Build destination path
            entry_dest = (target_dir / Path(*parts)).resolve()

            # Strict path containment verification
            if not entry_dest.is_relative_to(target_dir) or entry_dest == target_dir:
                raise ArchiveSecurityError(
                    f"Archive entry resolved outside designated workspace: '{info.filename}'."
                )

            if info.is_dir():
                entry_dest.mkdir(parents=True, exist_ok=True)
            else:
                entry_dest.parent.mkdir(parents=True, exist_ok=True)

                file_extracted_bytes = 0
                with zf.open(info, "r") as source_stream, open(entry_dest, "wb") as dest_stream:
                    while True:
                        chunk = source_stream.read(chunk_size)
                        if not chunk:
                            break
                        n = len(chunk)
                        file_extracted_bytes += n
                        total_extracted_bytes += n

                        # Dynamic size limits enforcement
                        if file_extracted_bytes > self.settings.max_file_size_bytes:
                            raise ArchiveLimitError(
                                f"File '{info.filename}' exceeded maximum allowed individual size "
                                f"({self.settings.max_file_size_bytes} bytes) during extraction."
                            )
                        if total_extracted_bytes > self.settings.max_expanded_size_bytes:
                            raise ArchiveLimitError(
                                f"Archive exceeded maximum allowed total uncompressed size "
                                f"({self.settings.max_expanded_size_bytes} bytes) during extraction."
                            )

                        dest_stream.write(chunk)

                extracted_file_count += 1

        return {
            "file_count": extracted_file_count,
            "total_uncompressed_bytes": total_extracted_bytes,
            "target_dir": str(target_dir),
        }


# Global instance
safe_archive_validator = SafeArchiveValidator()
