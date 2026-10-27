from __future__ import annotations

import collections
import datetime as dt
import hashlib
import json
import os
import re
import stat
import time
import unicodedata
from pathlib import Path, PurePosixPath

from . import __version__
from .markdown import classify_target, parse_markdown
from .policy import Policy


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _key(value: str) -> str:
    return unicodedata.normalize("NFC", value).strip().casefold()


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _signature(info: os.stat_result) -> dict[str, int]:
    return {
        "dev": info.st_dev,
        "ino": info.st_ino,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
        "mode": info.st_mode,
    }


def _contains_symlink(path: Path) -> bool:
    # Reject a caller-supplied symlink at the boundary. Interior links are
    # independently skipped during traversal. We intentionally do not reject
    # OS aliases such as macOS /var -> /private/var in ancestor components.
    try:
        return path.is_symlink()
    except OSError:
        return True


def _safe_artifact(path: Path, root: Path) -> Path:
    path = path.absolute()
    if path.exists() and path.is_symlink():
        raise ValueError("ARTIFACT_SYMLINK_REFUSED")
    resolved_parent = path.parent.resolve()
    resolved = resolved_parent / path.name
    if resolved == root or root in resolved.parents:
        raise ValueError("ARTIFACT_INSIDE_SOURCE_REFUSED")
    if path.exists():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("ARTIFACT_NOT_PRIVATE_REGULAR_FILE")
    resolved_parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise


def _read_stable(path: Path, want_text: bool, attempts: int = 3) -> tuple[dict, bytes | None, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    last_error = "UNSTABLE_READ"
    for attempt in range(attempts):
        try:
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise OSError("not_regular")
                digest = hashlib.sha256()
                chunks: list[bytes] = []
                count = 0
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    count += len(chunk)
                    if want_text:
                        chunks.append(chunk)
                after = os.fstat(stream.fileno())
            fresh = path.stat(follow_symlinks=False)
            if _signature(before) != _signature(after) or _signature(after) != _signature(fresh) or count != before.st_size:
                last_error = "UNSTABLE_READ"
                continue
            row = {
                "state": "ok",
                "signature": _signature(after),
                "size": count,
                "sha256": digest.hexdigest(),
                "verifiedAt": _now(),
            }
            return row, b"".join(chunks) if want_text else None, attempt
        except (OSError, ValueError) as error:
            last_error = type(error).__name__
    raise OSError(last_error)


def _normalize(relative: str) -> str | None:
    parts: list[str] = []
    for part in PurePosixPath(relative).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def _walk(root: Path, policy: Policy) -> tuple[dict, set[str], list[dict], list[dict], list[str]]:
    files: dict[str, dict] = {}
    directories: set[str] = set()
    skips: list[dict] = []
    errors: list[dict] = []
    gaps: list[str] = []

    def visit(directory: Path, prefix: str) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name.casefold())
        except OSError as error:
            errors.append({"pathDigest": _sha_bytes(prefix.encode()), "code": "directory_read_error", "errorClass": type(error).__name__})
            gaps.append(prefix)
            return
        for entry in entries:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            try:
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    skips.append({"path": relative, "reason": "symlink", "entryKind": "link"})
                    continue
                is_dir = stat.S_ISDIR(info.st_mode)
                reason = policy.classify_exclusion(entry.name, is_dir)
                if reason:
                    skips.append({"path": relative, "reason": reason, "entryKind": "directory" if is_dir else "file", "knownBytes": None if is_dir else info.st_size})
                    continue
                if is_dir:
                    directories.add(relative)
                    visit(Path(entry.path), relative)
                elif stat.S_ISREG(info.st_mode):
                    files[relative] = _signature(info)
                else:
                    skips.append({"path": relative, "reason": "non_regular", "entryKind": "special"})
            except OSError as error:
                errors.append({"pathDigest": _sha_bytes(relative.encode()), "code": "entry_read_error", "errorClass": type(error).__name__})
                gaps.append(relative)
    visit(root, "")
    return files, directories, skips, errors, gaps


def _resolve_links(records: dict, directories: set[str], skips: list[dict], root: Path, policy: Policy) -> list[dict]:
    by_path: dict[str, list[str]] = collections.defaultdict(list)
    by_name: dict[str, list[str]] = collections.defaultdict(list)
    for relative in records:
        by_path[_key(relative)].append(relative)
        by_name[_key(PurePosixPath(relative).name)].append(relative)
    for relative in directories:
        by_path[_key(relative)].append(relative)

    results: list[dict] = []
    for source, row in records.items():
        for reference in row.get("markdown", {}).get("refs", []):
            classified = classify_target(reference["target"], source, root.as_posix())
            result = {k: v for k, v in reference.items() if k != "target"}
            result.update(classified)
            if classified["classification"] != "internal":
                result["status"] = classified["classification"]
                results.append(result)
                continue
            path = classified["path"]
            if any(policy.classify_exclusion(part, True) for part in PurePosixPath(path).parts if part not in {".", ".."}):
                result["status"] = "excluded_sensitive_or_runtime"
                results.append(result)
                continue
            parent = PurePosixPath(source).parent.as_posix()
            choices = [path] if classified.get("rootRelative") else [f"{parent}/{path}"]
            if reference["format"] == "wiki":
                choices.append(path)
            candidates: set[str] = set()
            escaped = False
            if not path:
                candidates.add(source)
            for choice in choices:
                normalized = _normalize(choice)
                if normalized is None:
                    escaped = True
                    continue
                candidates.update(by_path.get(_key(normalized), []))
                if reference["format"] == "wiki" and not normalized.lower().endswith(".md"):
                    candidates.update(by_path.get(_key(normalized + ".md"), []))
            if not candidates and reference["format"] == "wiki" and "/" not in path:
                names = [path] if path.lower().endswith(".md") else [path, path + ".md"]
                for name in names:
                    candidates.update(by_name.get(_key(name), []))
            if not candidates:
                blocked = any(path == item["path"] or path.startswith(item["path"] + "/") for item in skips)
                result["status"] = "excluded_target" if blocked else "outside_source" if escaped else "missing"
            elif len(candidates) > 1:
                result.update(status="ambiguous", candidateDigests=sorted(_sha_bytes(x.encode()) for x in candidates))
            else:
                target = next(iter(candidates))
                target_row = records.get(target)
                result["resolvedPath"] = target
                if target_row and target_row.get("state") != "ok":
                    result["status"] = "target_read_error"
                elif classified.get("anchorDigest") and target_row and target_row.get("markdown"):
                    result["status"] = "ok" if classified["anchorDigest"] in target_row["markdown"]["anchors"] else "anchor_missing"
                elif classified.get("anchorDigest"):
                    result["status"] = "anchor_unchecked"
                else:
                    result["status"] = "ok"
            results.append(result)
    return results


def _tool_digest() -> str:
    directory = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for name in ("scanner.py", "markdown.py", "policy.py"):
        digest.update((directory / name).read_bytes())
    return digest.hexdigest()


def _exact_duplicate(root: Path, paths: list[str], records: dict) -> bool:
    streams = []
    flags = os.O_RDONLY | (getattr(os, "O_NOFOLLOW", 0))
    try:
        for relative in paths:
            fd = os.open(root / relative, flags)
            stream = os.fdopen(fd, "rb")
            if _signature(os.fstat(stream.fileno())) != records[relative]["signature"]:
                stream.close()
                raise OSError("duplicate_changed_before_compare")
            streams.append(stream)
        while True:
            chunks = [stream.read(1024 * 1024) for stream in streams]
            if any(chunk != chunks[0] for chunk in chunks[1:]):
                return False
            if not chunks[0]:
                break
        for relative, stream in zip(paths, streams):
            if _signature(os.fstat(stream.fileno())) != records[relative]["signature"]:
                raise OSError("duplicate_changed_during_compare")
        return True
    finally:
        for stream in streams:
            stream.close()


def scan(vault: Path, cache_path: Path, report_path: Path, policy: Policy) -> dict:
    started = time.monotonic()
    vault = vault.absolute()
    if not vault.is_dir() or _contains_symlink(vault):
        raise ValueError("SOURCE_NOT_ORDINARY_DIRECTORY")
    vault = vault.resolve()
    cache_path = _safe_artifact(cache_path, vault)
    report_path = _safe_artifact(report_path, vault)
    if cache_path == report_path:
        raise ValueError("CACHE_REPORT_COLLISION")
    binding = {
        "root": str(vault),
        "rootDev": vault.stat().st_dev,
        "rootIno": vault.stat().st_ino,
        "version": __version__,
        "toolSha256": _tool_digest(),
        "policySha256": policy.digest(),
    }
    previous: dict = {}
    if cache_path.exists():
        if stat.S_IMODE(cache_path.stat().st_mode) & 0o077:
            raise ValueError("CACHE_PERMISSIONS_TOO_OPEN")
        previous = json.loads(cache_path.read_text(encoding="utf-8"))
    binding_match = previous.get("binding") == binding
    old = previous.get("files", {}) if binding_match else {}
    inventory, directories, skips, errors, gaps = _walk(vault, policy)
    records: dict[str, dict] = {}
    hashed = reused = hash_bytes = retries = markdown_skipped = 0

    for relative, signature in inventory.items():
        cached = old.get(relative, {})
        is_markdown = relative.casefold().endswith(".md")
        want_text = is_markdown and not policy.metadata_only(relative) and signature["size"] <= policy.max_markdown_bytes
        if is_markdown and not want_text:
            markdown_skipped += 1
        try:
            if cached.get("state") == "ok" and cached.get("signature") == signature:
                current = _signature((vault / relative).stat(follow_symlinks=False))
                if current != signature:
                    raise OSError("cache_signature_changed")
                records[relative] = dict(cached, cacheReused=True)
                reused += 1
                continue
            row, data, attempts = _read_stable(vault / relative, want_text)
            retries += attempts
            row["cacheReused"] = False
            records[relative] = row
            hashed += 1
            hash_bytes += row["size"]
            if want_text and data is not None:
                try:
                    text = data.decode("utf-8-sig")
                except UnicodeError:
                    row["state"] = "parse_error"
                    errors.append({"pathDigest": _sha_bytes(relative.encode()), "code": "markdown_encoding_error"})
                    continue
                parsed = parse_markdown(
                    text,
                    require_frontmatter=policy.require_frontmatter,
                    required_keys=policy.required_frontmatter_keys,
                )
                row["markdown"] = {"refs": parsed["refs"], "anchors": parsed["anchors"], "issues": parsed["issues"]}
        except OSError as error:
            records[relative] = {"state": "error", "signature": signature, "cacheReused": False}
            errors.append({"pathDigest": _sha_bytes(relative.encode()), "code": "file_read_error", "errorClass": type(error).__name__})

    changes: dict[str, list[str]] = collections.defaultdict(list)
    for relative, row in records.items():
        prior = old.get(relative)
        if row["state"] != "ok":
            kind = "error"
        elif not prior:
            kind = "added"
        elif prior.get("state") != "ok":
            kind = "recovered"
        elif row["sha256"] != prior.get("sha256"):
            kind = "modified"
        elif row["signature"] == prior.get("signature"):
            kind = "unchanged"
        else:
            kind = "metadata_only"
        changes[kind].append(relative)
    for relative in set(old) - set(records):
        if any(relative == item["path"] or relative.startswith(item["path"] + "/") for item in skips):
            kind = "now_excluded"
        elif any(not gap or relative == gap or relative.startswith(gap + "/") for gap in gaps):
            kind = "missing_unconfirmed"
        else:
            kind = "deleted"
        changes[kind].append(relative)

    groups: dict[tuple[str, int], list[str]] = collections.defaultdict(list)
    for relative, row in records.items():
        if row.get("state") == "ok":
            groups[(row["sha256"], row["size"])].append(relative)
    duplicates = []
    for (digest, size), paths in sorted(groups.items()):
        if len(paths) < 2:
            continue
        try:
            if _exact_duplicate(vault, paths, records):
                duplicates.append({"sha256": digest, "size": size, "paths": sorted(paths), "exactBytesConfirmed": True})
        except OSError as error:
            errors.append({"pathSetDigest": _sha_bytes(json.dumps(sorted(paths)).encode()), "code": "duplicate_verification_unstable", "errorClass": type(error).__name__})

    links = _resolve_links(records, directories, skips, vault, policy)
    issues = [
        {"path": relative, **issue}
        for relative, row in records.items()
        for issue in row.get("markdown", {}).get("issues", [])
    ]
    report = {
        "schemaVersion": 1,
        "version": __version__,
        "at": _now(),
        "source": str(vault),
        "complete": not errors,
        "summary": {
            "files": len(records),
            "bytes": sum(row.get("size", row.get("signature", {}).get("size", 0)) for row in records.values()),
            "hashedFiles": hashed,
            "hashReadBytes": hash_bytes,
            "cacheReusedFiles": reused,
            "readRetries": retries,
            "errors": len(errors),
            "structuralIssues": len(issues),
            "skippedEntries": len(skips),
            "markdownParseSkipped": markdown_skipped,
            "duplicateGroups": len(duplicates),
            "linkStatuses": dict(collections.Counter(item["status"] for item in links)),
            "changes": {kind: len(paths) for kind, paths in changes.items()},
            "elapsedMs": round((time.monotonic() - started) * 1000, 3),
        },
        "files": records,
        "changes": dict(changes),
        "duplicates": duplicates,
        "links": links,
        "issues": issues,
        "skips": skips,
        "errors": errors,
        "provenance": {
            "binding": binding,
            "cacheBindingMatched": binding_match,
            "network": False,
            "sourceWrites": False,
            "bodyPersisted": False,
            "limitations": [
                "external links and custom URI schemes are classified but never fetched",
                "cache reuse is signature-bound and is not a fresh byte hash",
                "a clean structural report does not validate business facts or freshness",
            ],
        },
    }
    _atomic_json(cache_path, {"binding": binding, "files": records})
    _atomic_json(report_path, report)
    return report

