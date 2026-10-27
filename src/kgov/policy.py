from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_PRUNE = {
    ".git",
    ".obsidian",
    ".trash",
    "node_modules",
    "__pycache__",
    "cache",
    "runtime",
    "backups",
}
DEFAULT_SENSITIVE_WORDS = {
    "credential",
    "secret",
    "password",
    "private-session",
    "access-token",
    "refresh-token",
    "凭据",
    "密钥",
    "密码",
    "身份证",
    "护照",
}
DEFAULT_SENSITIVE_EXTENSIONS = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".kdbx",
    ".log",
}


@dataclass(frozen=True)
class Policy:
    prune_dirs: frozenset[str] = field(default_factory=lambda: frozenset(DEFAULT_PRUNE))
    sensitive_words: frozenset[str] = field(default_factory=lambda: frozenset(DEFAULT_SENSITIVE_WORDS))
    sensitive_extensions: frozenset[str] = field(default_factory=lambda: frozenset(DEFAULT_SENSITIVE_EXTENSIONS))
    max_markdown_bytes: int = 8 * 1024 * 1024
    require_frontmatter: bool = False
    required_frontmatter_keys: tuple[str, ...] = ()
    raw_prefixes: tuple[str, ...] = ("raw", "attachments")

    @classmethod
    def load(cls, path: Path | None) -> "Policy":
        if path is None:
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        allowed = {
            "prune_dirs",
            "sensitive_words",
            "sensitive_extensions",
            "max_markdown_bytes",
            "require_frontmatter",
            "required_frontmatter_keys",
            "raw_prefixes",
        }
        unknown = set(data) - allowed
        if unknown:
            raise ValueError(f"unknown policy keys: {sorted(unknown)}")
        base = cls()
        return cls(
            prune_dirs=frozenset(data.get("prune_dirs", base.prune_dirs)),
            sensitive_words=frozenset(data.get("sensitive_words", base.sensitive_words)),
            sensitive_extensions=frozenset(data.get("sensitive_extensions", base.sensitive_extensions)),
            max_markdown_bytes=int(data.get("max_markdown_bytes", base.max_markdown_bytes)),
            require_frontmatter=bool(data.get("require_frontmatter", base.require_frontmatter)),
            required_frontmatter_keys=tuple(data.get("required_frontmatter_keys", base.required_frontmatter_keys)),
            raw_prefixes=tuple(data.get("raw_prefixes", base.raw_prefixes)),
        )

    def digest(self) -> str:
        body = {
            "prune_dirs": sorted(self.prune_dirs),
            "sensitive_words": sorted(self.sensitive_words),
            "sensitive_extensions": sorted(self.sensitive_extensions),
            "max_markdown_bytes": self.max_markdown_bytes,
            "require_frontmatter": self.require_frontmatter,
            "required_frontmatter_keys": self.required_frontmatter_keys,
            "raw_prefixes": self.raw_prefixes,
        }
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

    def classify_exclusion(self, name: str, is_dir: bool) -> str | None:
        folded = name.casefold()
        if name.startswith("."):
            return "hidden_or_configuration"
        if is_dir and folded in {x.casefold() for x in self.prune_dirs}:
            return "pruned_runtime_backup_dependency"
        if any(word.casefold() in folded for word in self.sensitive_words):
            return "sensitive_name"
        if not is_dir and Path(name).suffix.casefold() in {x.casefold() for x in self.sensitive_extensions}:
            return "sensitive_or_runtime_format"
        return None

    def metadata_only(self, relative_path: str) -> bool:
        first = relative_path.replace("\\", "/").split("/", 1)[0].casefold()
        return first in {x.casefold() for x in self.raw_prefixes}

