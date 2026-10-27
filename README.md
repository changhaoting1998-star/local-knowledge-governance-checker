# Local Knowledge Governance Checker

[![CI](https://github.com/changhaoting1998-star/local-knowledge-governance-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/changhaoting1998-star/local-knowledge-governance-checker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`kgov` audits a local Markdown or Obsidian-style knowledge base without modifying it or sending its contents over the network.

Most vault checkers focus on broken links. `kgov` also treats the scan itself as a security boundary:

- refuses cache and report paths inside the source vault;
- never follows symbolic links;
- excludes configurable secret, runtime, backup, and database paths before reading;
- hashes files with stable-read checks and records file identity;
- binds incremental cache reuse to the source directory, policy, and scanner version;
- re-resolves cached links against the current directory inventory;
- confirms duplicate groups with SHA-256 and exact bytes;
- stores metadata, hashes, link targets, and issue codes, but never Markdown bodies;
- performs no network requests.

The project is alpha software. Use the report as structural evidence, not as proof that business facts are current or correct.

## Quick start

Python 3.10 or newer is required.

```bash
python -m pip install -e .

kgov scan ./examples/vault \
  --policy ./examples/policy.json \
  --cache /tmp/kgov-cache.json \
  --report /tmp/kgov-report.json
```

The cache and report must be outside the scanned vault. Both files are written with owner-only permissions on POSIX systems.

## What the report contains

The JSON report includes:

- stable file signatures and SHA-256 hashes;
- added, modified, deleted, recovered, and newly excluded paths;
- internal Markdown links, wiki links, embeds, headings, and block anchors;
- missing, ambiguous, outside-source, excluded, and anchor-missing references;
- configurable frontmatter requirements;
- exact duplicate groups;
- exclusions, read gaps, errors, cache provenance, and explicit limitations.

Raw or attachment prefixes can be configured as metadata-only. Those files are hashed but Markdown bodies are not parsed.

## Policy

Pass a JSON file with `--policy`. See [`examples/policy.json`](examples/policy.json).

```json
{
  "prune_dirs": [".git", ".obsidian", "runtime", "backups"],
  "sensitive_words": ["credential", "secret", "password"],
  "sensitive_extensions": [".db", ".sqlite", ".pem", ".key"],
  "max_markdown_bytes": 8388608,
  "require_frontmatter": true,
  "required_frontmatter_keys": ["tags"],
  "raw_prefixes": ["raw", "attachments"]
}
```

Unknown policy keys fail closed. Policy changes invalidate the cache.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed. Structural findings may still exist. |
| `1` | Configuration, path, cache, or invocation failure. |
| `2` | Report was written, but one or more files could not be read or parsed reliably. |

## Privacy model

`kgov` is local and read-only by design. It does not fetch external links, call models, repair files, delete duplicates, or schedule background jobs. Reports contain source paths and link targets because they are needed for remediation; treat the report as sensitive metadata when the vault structure is sensitive.

The current parser intentionally covers common Markdown links, Obsidian wiki links, headings, and block anchors. It masks fenced code, inline code, and HTML before looking for wiki links. It is not a complete CommonMark parser.

## 中文说明

`kgov` 用于本地 Markdown／Obsidian 知识库的只读体检。它不仅检查断链，还检查扫描过程本身的边界：输出不得写回源库、不跟随符号链接、敏感目录先排除、文件以 SHA-256 和稳定读取证明身份、缓存与源目录及策略绑定、报告不保存正文、全程不联网。

报告只能证明结构扫描结果，不能证明业务内容正确、最新，也不会自动修复或删除任何文件。

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Every test uses generated synthetic content. No real vault or network service is required.

## License

MIT. See [`LICENSE`](LICENSE).
