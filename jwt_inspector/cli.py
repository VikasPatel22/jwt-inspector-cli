#!/usr/bin/env python3
"""
jwt-inspector: Decode and security-audit JWTs from the command line.

Usage:
    jwt-inspector <token>
    jwt-inspector --file token.txt
    echo "<token>" | jwt-inspector
    jwt-inspector --json <token>
"""
import argparse
import json
import sys
import time

from .decoder import decode_jwt
from .auditor import audit

COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "dim": "\033[2m",
}

LEVEL_COLORS = {
    "LOW": COLORS["cyan"],
    "MEDIUM": COLORS["yellow"],
    "HIGH": COLORS["red"],
    "CRITICAL": COLORS["red"] + COLORS["bold"],
}

GRADE_COLORS = {
    "A": COLORS["green"],
    "B": COLORS["cyan"],
    "C": COLORS["yellow"],
    "D": COLORS["red"],
    "F": COLORS["red"] + COLORS["bold"],
}


def c(color: str, text: str, no_color: bool = False) -> str:
    if no_color:
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def print_section(title: str, no_color: bool):
    print(f"\n{c('bold', '─' * 50, no_color)}")
    print(c("bold", f"  {title}", no_color))
    print(c("bold", "─" * 50, no_color))


def print_claims(data: dict, no_color: bool, indent: int = 2):
    now = int(time.time())
    for key, val in data.items():
        label = c("cyan", key, no_color)
        if key in ("exp", "iat", "nbf") and isinstance(val, int):
            human = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(val))
            expired = key == "exp" and val < now
            tag = c("red", " [EXPIRED]", no_color) if expired else ""
            print(f"{' ' * indent}{label}: {val}  {c('dim', human, no_color)}{tag}")
        else:
            print(f"{' ' * indent}{label}: {json.dumps(val)}")


def run_cli():
    parser = argparse.ArgumentParser(
        prog="jwt-inspector",
        description="Decode and security-audit JWTs — zero dependencies.",
    )
    parser.add_argument("token", nargs="?", help="JWT token string")
    parser.add_argument("--file", "-f", help="Read token from file")
    parser.add_argument("--json", "-j", action="store_true", help="Output raw JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    args = parser.parse_args()

    # Get token
    token = None
    if args.token:
        token = args.token
    elif args.file:
        with open(args.file) as fh:
            token = fh.read().strip()
    elif not sys.stdin.isatty():
        token = sys.stdin.read().strip()

    if not token:
        parser.print_help()
        sys.exit(1)

    # Decode
    try:
        decoded = decode_jwt(token)
    except ValueError as e:
        print(c("red", f"Error: {e}", args.no_color), file=sys.stderr)
        sys.exit(1)

    header = decoded["header"]
    payload = decoded["payload"]

    # Audit
    report = audit(header, payload)

    # JSON mode
    if args.json:
        output = {
            "header": header,
            "payload": payload,
            "audit": {
                "grade": report.grade,
                "score": report.score,
                "findings": [
                    {
                        "level": f.level,
                        "code": f.code,
                        "title": f.title,
                        "detail": f.detail,
                        "fix": f.fix,
                    }
                    for f in report.findings
                ],
            },
        }
        print(json.dumps(output, indent=2))
        return

    no_color = args.no_color

    # Header
    print_section("JWT HEADER", no_color)
    print_claims(header, no_color)

    # Payload
    print_section("JWT PAYLOAD", no_color)
    print_claims(payload, no_color)

    # Security Report
    print_section("SECURITY AUDIT", no_color)
    grade_color = GRADE_COLORS.get(report.grade, "")
    grade_str = f"{grade_color}{report.grade}{COLORS['reset']}" if not no_color else report.grade
    print(f"  Grade: {grade_str}   Score: {report.score}/100\n")

    if not report.findings:
        print(c("green", "  ✓ No issues found.", no_color))
    else:
        for finding in report.findings:
            lvl_color = LEVEL_COLORS.get(finding.level, "")
            lvl_str = f"{lvl_color}[{finding.level}]{COLORS['reset']}" if not no_color else f"[{finding.level}]"
            print(f"  {lvl_str} {c('bold', finding.code, no_color)} — {finding.title}")
            print(f"       {c('dim', finding.detail, no_color)}")
            print(f"       {c('green', '→ Fix: ', no_color)}{finding.fix}\n")

    print(c("bold", "─" * 50, no_color) + "\n")
    sys.exit(0 if report.grade in ("A", "B") else 1)


if __name__ == "__main__":
    run_cli()
