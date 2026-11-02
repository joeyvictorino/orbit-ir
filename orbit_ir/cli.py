from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze_dataset, filter_findings, verify_evidence
from .diff import diff_results, format_diff_text
from .generator import LabConfig, generate_dataset
from .schema import schema_json
from .validate import validate_evidence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Synthetic agent-incident reconstruction lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="Generate deterministic synthetic evidence")
    generate.add_argument("--out", type=Path, required=True)
    generate.add_argument("--agents", type=int, default=1200)
    generate.add_argument("--messages", type=int, default=70000)
    generate.add_argument("--transcripts", type=int, default=1300)
    generate.add_argument("--participants", type=int, default=700)
    generate.add_argument("--spoofed-tool-calls", type=int, default=84)
    generate.add_argument("--coordinators", type=int, default=6)
    generate.add_argument("--seed", type=int, default=20260903)

    analyze = subparsers.add_parser("analyze", help="Analyze evidence and write source-linked findings")
    analyze.add_argument("--input", type=Path, required=True)
    analyze.add_argument("--out", type=Path, required=True)
    analyze.add_argument(
        "--ground-truth",
        type=Path,
        help="Optional synthetic evaluation fixture; never used to determine findings",
    )
    analyze.add_argument("--coordinator-min-assignments", type=int, default=2)
    analyze.add_argument(
        "--format",
        choices=["json", "sarif", "html", "csv"],
        default="json",
        help="Output format: json (default) prints the summary, sarif prints SARIF 2.1.0, html prints the HTML report, csv prints findings CSV",
    )
    analyze.add_argument(
        "--min-confidence",
        choices=["low", "medium", "high"],
        default=None,
        help="Only include findings at or above this confidence level",
    )
    analyze.add_argument(
        "--detection-type",
        default=None,
        help="Comma-separated detection types to include (e.g. tool-name-mismatch,unbacked-completion)",
    )
    analyze.add_argument(
        "--agent",
        default=None,
        help="Comma-separated agent IDs to filter findings to",
    )

    verify = subparsers.add_parser("verify", help="Verify evidence integrity against a manifest")
    verify.add_argument("--input", type=Path, required=True, help="Evidence directory to verify")
    verify.add_argument(
        "--manifest",
        type=Path,
        help="Manifest JSON to verify against (default: <input>/../results/evidence_manifest.json or recompute)",
    )

    validate = subparsers.add_parser("validate", help="Validate evidence format and cross-file integrity")
    validate.add_argument("--input", type=Path, required=True, help="Evidence directory to validate")
    validate.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    diff = subparsers.add_parser("diff", help="Compare two analysis results directories")
    diff.add_argument("--before", type=Path, required=True, help="Earlier results directory")
    diff.add_argument("--after", type=Path, required=True, help="Later results directory")
    diff.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    subparsers.add_parser("schema", help="Print the JSON Schema for the analysis summary output")

    demo = subparsers.add_parser("demo", help="Generate and analyze a full deterministic exercise")
    demo.add_argument("--workdir", type=Path, default=Path("work"))
    demo.add_argument("--seed", type=int, default=20260903)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        _run(args)
    except (ValueError, FileNotFoundError) as exc:
        # Includes EvidenceFormatError (a ValueError) with its exact file:line message.
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _run(args: argparse.Namespace) -> None:
    if args.command == "schema":
        print(schema_json())
        return
    if args.command == "generate":
        config = LabConfig(
            agents=args.agents,
            messages=args.messages,
            transcripts=args.transcripts,
            participants=args.participants,
            spoofed_tool_calls=args.spoofed_tool_calls,
            coordinators=args.coordinators,
            seed=args.seed,
        )
        truth = generate_dataset(args.out, config)
        print(json.dumps({"status": "generated", "config": truth["config"]}, sort_keys=True))
    elif args.command == "verify":
        result = verify_evidence(args.input, manifest_path=args.manifest)
        ok = all(f["status"] == "ok" for f in result["files"])
        for f in result["files"]:
            mark = "OK" if f["status"] == "ok" else "FAIL"
            print(f"  [{mark}] {f['name']}: {f['detail']}")
        if ok:
            print(f"\nAll {len(result['files'])} evidence files verified.")
        else:
            failed = sum(1 for f in result["files"] if f["status"] != "ok")
            print(f"\n{failed} of {len(result['files'])} files failed verification.")
            raise SystemExit(1)
        return
    elif args.command == "validate":
        report = validate_evidence(args.input)
        if args.format == "json":
            print(json.dumps(report, sort_keys=True, indent=2))
        else:
            _print_validation(report)
        if not report["valid"]:
            raise SystemExit(1)
        return
    elif args.command == "diff":
        result = diff_results(args.before, args.after)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_diff_text(result))
        return
    elif args.command == "analyze":
        summary = analyze_dataset(
            args.input,
            args.out,
            ground_truth_path=args.ground_truth,
            coordinator_min_assignments=args.coordinator_min_assignments,
        )
        has_filters = (
            args.min_confidence is not None
            or args.detection_type is not None
            or args.agent is not None
        )
        if has_filters:
            findings_path = args.out / "findings.json"
            all_findings = json.loads(findings_path.read_text(encoding="utf-8"))
            detection_types = args.detection_type.split(",") if args.detection_type else None
            agents = args.agent.split(",") if args.agent else None
            filtered = filter_findings(
                all_findings,
                min_confidence=args.min_confidence,
                detection_types=detection_types,
                agents=agents,
            )
            findings_path.write_text(
                json.dumps(filtered, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            summary["filter"] = {
                "min_confidence": args.min_confidence,
                "detection_types": detection_types,
                "agents": agents,
                "total_before_filter": len(all_findings),
                "total_after_filter": len(filtered),
            }
            (args.out / "summary.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        if args.format == "sarif":
            sarif_path = args.out / "findings.sarif"
            print(sarif_path.read_text(encoding="utf-8"), end="")
        elif args.format == "html":
            html_path = args.out / "report.html"
            print(html_path.read_text(encoding="utf-8"), end="")
        elif args.format == "csv":
            csv_path = args.out / "findings.csv"
            print(csv_path.read_text(encoding="utf-8"), end="")
        else:
            print(json.dumps(summary, sort_keys=True))
    else:
        data_dir = args.workdir / "evidence"
        result_dir = args.workdir / "results"
        generate_dataset(data_dir, LabConfig(seed=args.seed))
        summary = analyze_dataset(
            data_dir,
            result_dir,
            ground_truth_path=data_dir / "ground_truth.json",
        )
        print(json.dumps(summary, sort_keys=True))


def _print_validation(report: dict) -> None:
    for fname, fr in report["files"].items():
        status = "OK" if not fr["errors"] else "FAIL"
        print(f"  [{status}] {fname}: {fr['records']} records")
        for e in fr["errors"]:
            print(f"    ERROR: {e}")
        for w in fr["warnings"]:
            print(f"    WARN:  {w}")

    integrity = report.get("integrity", {})
    if integrity.get("checks"):
        print("\n  Integrity checks:")
        for check in integrity["checks"]:
            name = check.pop("name", "?")
            detail = ", ".join(f"{k}={v}" for k, v in check.items())
            print(f"    {name}: {detail}")
    for e in integrity.get("errors", []):
        print(f"    ERROR: {e}")
    for w in integrity.get("warnings", []):
        print(f"    WARN:  {w}")

    s = report["summary"]
    print(f"\n  {s['total_records']} records, {s['total_errors']} errors, {s['total_warnings']} warnings")
    print(f"  Valid: {report['valid']}")


if __name__ == "__main__":
    main()
