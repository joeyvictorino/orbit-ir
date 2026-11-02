from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import (
    analyze_dataset,
    build_evidence_chain,
    build_navigator_layer,
    filter_findings,
    verify_evidence,
    verify_evidence_chain,
)
from .stats import evidence_stats, format_stats_text
from .diff import diff_results, format_diff_text
from .comm_graph import load_and_build as load_comm_graph, format_dot as format_comm_dot, format_summary as format_comm_summary
from .heatmap import load_and_build_heatmap, format_heatmap_summary
from .generator import LabConfig, generate_dataset
from .schema import schema_json
from .timeline import build_timeline, format_json as format_timeline_json, format_text as format_timeline_text
from .cef import findings_to_cef
from .validate import validate_evidence
from .merge import merge_evidence
from .correlate import correlate_events, format_correlate_text
from .fingerprint import fingerprint_agents, format_fingerprint_text


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
        choices=["json", "sarif", "html", "csv", "cef"],
        default="json",
        help="Output format: json (default) prints the summary, sarif prints SARIF 2.1.0, html prints the HTML report, csv prints findings CSV, cef prints CEF for SIEM ingestion",
    )
    analyze.add_argument(
        "--min-confidence",
        choices=["low", "medium", "high"],
        default=None,
        help="Only include findings at or above this confidence level",
    )
    analyze.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Only include findings at or above this severity level",
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
    analyze.add_argument(
        "--navigator-layer",
        action="store_true",
        default=False,
        help="Export findings as a MITRE ATT&CK Navigator layer JSON file",
    )
    analyze.add_argument(
        "--evidence-chain",
        action="store_true",
        default=False,
        help="Regenerate and print the evidence chain JSON (cryptographic hash linking findings to evidence)",
    )
    analyze.add_argument(
        "--comm-graph",
        action="store_true",
        default=False,
        help="Export agent communication graph as DOT to comm_graph.dot in the output directory",
    )
    analyze.add_argument(
        "--heatmap",
        action="store_true",
        default=False,
        help="Export agent activity heatmap as JSON to heatmap.json in the output directory",
    )
    analyze.add_argument(
        "--heatmap-bucket",
        type=int,
        default=60,
        help="Bucket size in minutes for heatmap (default: 60)",
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

    stats = subparsers.add_parser("stats", help="Print summary statistics for an evidence dataset")
    stats.add_argument("--input", type=Path, required=True, help="Evidence directory")
    stats.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    merge = subparsers.add_parser("merge", help="Merge multiple evidence directories into one")
    merge.add_argument("--inputs", type=Path, nargs="+", required=True, help="Evidence directories to merge")
    merge.add_argument("--out", type=Path, required=True, help="Output directory for merged evidence")

    tl = subparsers.add_parser("timeline", help="Merge evidence into a single chronological event stream")
    tl.add_argument("--input", type=Path, required=True, help="Evidence directory")
    tl.add_argument("--format", choices=["json", "text"], default="text", help="Output format")
    tl.add_argument("--source", choices=["messages", "transcripts", "control_plane"], default=None,
                    help="Filter to a single evidence source")
    tl.add_argument("--agent", default=None, help="Filter to events from this agent ID")

    fp = subparsers.add_parser("fingerprint", help="Compute agent behavior fingerprints and anomaly scores")
    fp.add_argument("--input", type=Path, required=True, help="Evidence directory")
    fp.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    corr = subparsers.add_parser("correlate", help="Cross-link events across evidence sources by agent and time")
    corr.add_argument("--input", type=Path, required=True, help="Evidence directory")
    corr.add_argument("--time-window", type=int, default=5, help="Time window in seconds (default: 5)")
    corr.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

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
    elif args.command == "stats":
        s = evidence_stats(args.input)
        if args.format == "json":
            print(json.dumps(s, sort_keys=True, indent=2))
        else:
            print(format_stats_text(s), end="")
        return
    elif args.command == "diff":
        result = diff_results(args.before, args.after)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_diff_text(result))
        return
    elif args.command == "merge":
        result = merge_evidence(args.inputs, args.out)
        print(json.dumps(result, sort_keys=True, indent=2))
        return
    elif args.command == "timeline":
        events = build_timeline(args.input)
        if args.source:
            events = [e for e in events if e.get("source") == args.source]
        if args.agent:
            events = [e for e in events if e.get("agent_id") == args.agent]
        if args.format == "json":
            print(format_timeline_json(events), end="")
        else:
            print(format_timeline_text(events), end="")
        return
    elif args.command == "fingerprint":
        result = fingerprint_agents(args.input)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_fingerprint_text(result), end="")
        return
    elif args.command == "correlate":
        result = correlate_events(args.input, time_window_seconds=args.time_window)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_correlate_text(result), end="")
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
            or args.min_severity is not None
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
                min_severity=args.min_severity,
                detection_types=detection_types,
                agents=agents,
            )
            findings_path.write_text(
                json.dumps(filtered, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            summary["filter"] = {
                "min_confidence": args.min_confidence,
                "min_severity": args.min_severity,
                "detection_types": detection_types,
                "agents": agents,
                "total_before_filter": len(all_findings),
                "total_after_filter": len(filtered),
            }
            (args.out / "summary.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        if args.comm_graph:
            graph = load_comm_graph(args.input)
            dot_text = format_comm_dot(graph)
            dot_path = args.out / "comm_graph.dot"
            dot_path.write_text(dot_text, encoding="utf-8")
            summary_path = args.out / "comm_graph.json"
            summary_path.write_text(
                json.dumps(format_comm_summary(graph), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(dot_text, end="")
        elif args.heatmap:
            heatmap = load_and_build_heatmap(args.input, args.heatmap_bucket)
            heatmap_summary = format_heatmap_summary(heatmap)
            heatmap_path = args.out / "heatmap.json"
            heatmap_text = json.dumps(heatmap_summary, indent=2, sort_keys=True) + "\n"
            heatmap_path.write_text(heatmap_text, encoding="utf-8")
            print(heatmap_text, end="")
        elif args.evidence_chain:
            chain_path = args.out / "evidence_chain.json"
            print(chain_path.read_text(encoding="utf-8"), end="")
        elif args.navigator_layer:
            findings_path = args.out / "findings.json"
            layer_findings = json.loads(findings_path.read_text(encoding="utf-8"))
            layer = build_navigator_layer(layer_findings)
            layer_path = args.out / "navigator_layer.json"
            layer_text = json.dumps(layer, indent=2, sort_keys=True) + "\n"
            layer_path.write_text(layer_text, encoding="utf-8")
            print(layer_text, end="")
        elif args.format == "sarif":
            sarif_path = args.out / "findings.sarif"
            print(sarif_path.read_text(encoding="utf-8"), end="")
        elif args.format == "html":
            html_path = args.out / "report.html"
            print(html_path.read_text(encoding="utf-8"), end="")
        elif args.format == "csv":
            csv_path = args.out / "findings.csv"
            print(csv_path.read_text(encoding="utf-8"), end="")
        elif args.format == "cef":
            findings_path = args.out / "findings.json"
            cef_findings = json.loads(findings_path.read_text(encoding="utf-8"))
            cef_text = findings_to_cef(cef_findings)
            cef_path = args.out / "findings.cef"
            cef_path.write_text(cef_text, encoding="utf-8")
            print(cef_text, end="")
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
