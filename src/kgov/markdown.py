from __future__ import annotations

import hashlib
import re
import urllib.parse
import unicodedata


FENCE_RE = re.compile(r"(^|\n)[ \t]*(```|~~~).*?\n.*?\n[ \t]*\2[ \t]*(?=\n|$)", re.S)
INLINE_CODE_RE = re.compile(r"(`+)(?:.|\n)*?\1")
HTML_RE = re.compile(r"<!--[\s\S]*?-->|<[^>\n]+>")
MD_LINK_RE = re.compile(r"(!?)\[([^\]\n]*)\]\(([^)\n]+)\)")
WIKI_LINK_RE = re.compile(r"(!?)\[\[([^\]\n]+)\]\]")
HEADING_RE = re.compile(r"(?m)^#{1,6}[ \t]+(.+?)[ \t]*#*[ \t]*$")
BLOCK_RE = re.compile(r"(?m)(?:^|\s)\^([A-Za-z0-9_-]+)[ \t]*$")
FRONTMATTER_RE = re.compile(r"\A\ufeff?---\r?\n(.*?)\r?\n---(?:\r?\n|$)", re.S)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def anchor_digest(value: str) -> str:
    value = unicodedata.normalize("NFC", value).strip().casefold()
    value = re.sub(r"\s+", " ", value)
    return _digest(value)


def _mask(text: str, pattern: re.Pattern[str]) -> str:
    chars = list(text)
    for match in pattern.finditer(text):
        for index in range(match.start(), match.end()):
            if chars[index] not in "\r\n":
                chars[index] = " "
    return "".join(chars)


def _frontmatter(text: str) -> tuple[dict[str, str], list[dict], str]:
    match = FRONTMATTER_RE.match(text)
    if not match:
        return {}, [], text
    values: dict[str, str] = {}
    issues: list[dict] = []
    for lineno, line in enumerate(match.group(1).splitlines(), start=2):
        if not line.strip() or line.lstrip().startswith("#") or line[:1].isspace():
            continue
        if ":" not in line:
            issues.append({"code": "frontmatter_line_unparsed", "line": lineno})
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key):
            issues.append({"code": "frontmatter_key_invalid", "line": lineno})
            continue
        values[key] = value.strip()
    prefix = "".join(char if char in "\r\n" else " " for char in text[:match.end()])
    body = prefix + text[match.end():]
    return values, issues, body


def parse_markdown(text: str, *, require_frontmatter: bool, required_keys: tuple[str, ...]) -> dict:
    frontmatter, issues, body = _frontmatter(text)
    if require_frontmatter and not FRONTMATTER_RE.match(text):
        issues.append({"code": "frontmatter_missing", "line": 1})
    for key in required_keys:
        if key not in frontmatter:
            issues.append({"code": "frontmatter_key_missing", "keyDigest": _digest(key), "line": 1})

    masked = _mask(_mask(_mask(body, FENCE_RE), INLINE_CODE_RE), HTML_RE)
    refs: list[dict] = []
    for match in MD_LINK_RE.finditer(masked):
        target = match.group(3).strip().split(None, 1)[0].strip("<>")
        refs.append({
            "format": "markdown",
            "embed": bool(match.group(1)),
            "target": target,
            "line": text.count("\n", 0, match.start()) + 1,
        })
    for match in WIKI_LINK_RE.finditer(masked):
        target = match.group(2).split("|", 1)[0].strip()
        refs.append({
            "format": "wiki",
            "embed": bool(match.group(1)),
            "target": target,
            "line": text.count("\n", 0, match.start()) + 1,
        })
    anchors = {anchor_digest(match.group(1)) for match in HEADING_RE.finditer(masked)}
    anchors.update(anchor_digest("^" + match.group(1)) for match in BLOCK_RE.finditer(masked))
    return {"frontmatter": frontmatter, "issues": issues, "refs": refs, "anchors": sorted(anchors)}


def classify_target(target: str, source: str, root: str) -> dict:
    raw = target
    target = urllib.parse.unquote(target.replace("\\", "/"))
    if re.match(r"^[A-Za-z]:/", target):
        return {"classification": "absolute_path_outside", "targetDigest": _digest(raw)}
    try:
        parsed = urllib.parse.urlsplit(target)
    except ValueError:
        return {"classification": "malformed", "targetDigest": _digest(raw)}
    if target.startswith("//") or parsed.scheme in {"http", "https", "mailto", "ftp", "data"}:
        return {"classification": "external", "targetDigest": _digest(raw)}
    if parsed.scheme and parsed.scheme != "file":
        return {"classification": "custom_scheme", "targetDigest": _digest(raw)}

    path = parsed.path
    fragment = parsed.fragment
    if parsed.scheme == "file":
        if parsed.netloc not in {"", "localhost"}:
            return {"classification": "absolute_path_outside", "targetDigest": _digest(raw)}
        if path.startswith(root.rstrip("/") + "/"):
            path = path[len(root.rstrip("/")) + 1:]
            root_relative = True
        else:
            return {"classification": "absolute_path_outside", "targetDigest": _digest(raw)}
    elif path.startswith("/"):
        if path.startswith(root.rstrip("/") + "/"):
            path = path[len(root.rstrip("/")) + 1:]
            root_relative = True
        else:
            return {"classification": "absolute_path_outside", "targetDigest": _digest(raw)}
    else:
        root_relative = False

    if target.startswith("#"):
        path = ""
    result = {
        "classification": "internal",
        "targetDigest": _digest(raw),
        "path": path,
        "rootRelative": root_relative,
    }
    if fragment:
        result["anchorDigest"] = anchor_digest(fragment)
    return result

