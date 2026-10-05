"""Command-line interface.

Examples:
    mfa-tracker samples/riverbend_mfa_snapshots.csv --signins samples/riverbend_signins.csv --org "Riverbend Components"
    mfa-tracker snapshots.csv --format html csv --out reports --fail-on high
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analysis import analyze, load_policy
from .loader import DataError, load_signins, load_snapshots
from .reporting import WRITERS, grouped_findings


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mfa-tracker",
                                description="Track MFA rollout progress across monthly snapshots and find where MFA is bypassed.")
    p.add_argument("snapshots", help="CSV of MFA registration snapshots")
    p.add_argument("--signins", help="Optional CSV of aggregated sign-ins")
    p.add_argument("--org", help="Organization name for the report (default: file name)")
    p.add_argument("--format", nargs="+", choices=sorted(WRITERS), default=["html", "csv"])
    p.add_argument("--out", default="reports", help="Output directory (default: reports)")
    p.add_argument("--policy", help="JSON file overriding targets and parameters")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                   help="Exit with code 2 if any finding at or above this severity exists")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
        regs = load_snapshots(args.snapshots, policy["methods"])
        signins = load_signins(args.signins) if args.signins else None
    except (OSError, DataError, ValueError) as exc:
        print(f"Could not read input: {exc}", file=sys.stderr)
        return 1

    org = args.org or Path(args.snapshots).stem.replace("_", " ")
    result = analyze(regs, signins, org, policy)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for fmt in args.format:
        path = out / f"{Path(args.snapshots).stem}.{fmt}"
        path.write_text(WRITERS[fmt](result), encoding="utf-8")
        print(f"Wrote {path}")

    L, F = result.latest, result.first
    print(f"\n{result.organization} | {len(result.snapshots)} snapshots, {F.snapshot} to {L.snapshot}")
    print(f"MFA coverage: {L.mfa_pct:.0f}% (from {F.mfa_pct:.0f}%) | "
          f"Phishing-resistant: {L.phishing_resistant_pct:.0f}%")
    if result.signins["provided"]:
        print(f"Successful sign-ins without MFA: {result.signins['without_mfa_pct']:.0f}%")
    for pr in result.projections:
        print(f"  {pr.measure}: {pr.status}. {pr.explanation}")
    for g in grouped_findings(result)[:5]:
        f = g["finding"]
        n = len(g["accounts"])
        who = f" ({n} account{'s' if n != 1 else ''})" if n else ""
        print(f"  [{f.severity.upper():8}] {f.rule_id} {f.title}{who}")

    if args.fail_on:
        order = ["critical", "high", "medium", "low"]
        if any(order.index(f.severity) <= order.index(args.fail_on) for f in result.findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
