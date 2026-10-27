from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .policy import Policy
from .scanner import scan


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="kgov", description="Read-only governance checks for local Markdown knowledge bases.")
    subcommands = result.add_subparsers(dest="command", required=True)
    command = subcommands.add_parser("scan", help="scan a local knowledge base without modifying it")
    command.add_argument("vault", type=Path)
    command.add_argument("--cache", type=Path, required=True, help="private cache path outside the vault")
    command.add_argument("--report", type=Path, required=True, help="JSON report path outside the vault")
    command.add_argument("--policy", type=Path, help="optional JSON policy")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        policy = Policy.load(args.policy)
        report = scan(args.vault, args.cache, args.report, policy)
        print(json.dumps({"complete": report["complete"], "summary": report["summary"], "report": str(args.report.absolute())}, ensure_ascii=False))
        return 0 if report["complete"] else 2
    except Exception as error:
        code = str(error) if isinstance(error, ValueError) else "SCAN_FAILED"
        print(json.dumps({"complete": False, "errorClass": type(error).__name__, "errorCode": code}), file=sys.stderr)
        return 1

