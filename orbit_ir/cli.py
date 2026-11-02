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
from .export import export_findings
from .fingerprint import fingerprint_agents, format_fingerprint_text
from .scope import apply_scope
from .summary import build_executive_summary, format_summary_text
from .dedup import deduplicate_findings, format_dedup_summary
from .audit import audit_reproducibility, format_audit_text
from .bundle import create_bundle, format_bundle_text
from .compare_agents import compare_agents, format_comparison_text
from .replay import replay_events, format_replay_text
from .enrich import enrich_evidence, format_enrich_text
from .policy import load_policy, evaluate_policy, format_policy_text
from .simulate import generate_evidence as simulate_evidence, list_scenarios, format_simulate_text
from .dashboard import generate_dashboard
from .watch import watch_evidence
from .convert import convert_jsonl_to_csv, convert_csv_to_jsonl, convert_evidence_dir, format_convert_text
from .schema_def import validate_evidence_schema, format_schema_text, format_validation_text
from .normalize import normalize_evidence, format_normalize_text
from .tag import tag_events, list_tags, filter_by_tag, format_tag_text
from .search import search_evidence as search_evidence_fn, format_search_text
from .report_gen import generate_report, ReportConfig
from .chain import parse_chain, run_chain, format_chain_text
from .sample import sample_evidence, format_sample_text
from .anonymize import anonymize_evidence, format_anonymize_text
from .inspect import list_events, inspect_event, format_inspect_text
from .pivot import pivot_events, format_pivot_text
from .redact import redact_evidence, format_redact_text
from .batch import parse_batch_file, run_batch, format_batch_text
from .diff_agents import diff_agents, format_diff_agents_text
from .filter import filter_events, format_filter_text
from .aggregate import aggregate_events, format_aggregate_text
from .rank import rank_agents, format_rank_text
from .window import window_analysis, format_window_text
from .detect import detect_anomalies, format_detect_text as format_detect_output
from .classify import classify_events, format_classify_text
from .baseline import create_baseline, compare_baseline, format_baseline_text


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

    exp = subparsers.add_parser("export", help="Convert findings to CSV, CEF, or SARIF without re-analyzing")
    exp.add_argument("--input", type=Path, required=True, help="Path to findings.json")
    exp.add_argument("--format", choices=["csv", "cef", "sarif", "json"], default="csv", help="Output format")
    exp.add_argument("--out", type=Path, default=None, help="Write output to file instead of stdout")

    sc = subparsers.add_parser("scope", help="Filter evidence by time window, agent set, or source before analysis")
    sc.add_argument("--input", type=Path, required=True, help="Evidence directory")
    sc.add_argument("--out", type=Path, required=True, help="Output directory for scoped evidence")
    sc.add_argument("--start", default=None, help="Start of time window (ISO-8601)")
    sc.add_argument("--end", default=None, help="End of time window (ISO-8601)")
    sc.add_argument("--agents", default=None, help="Comma-separated agent IDs to include")
    sc.add_argument("--sources", default=None, help="Comma-separated sources: messages,transcripts,control_plane")

    summ = subparsers.add_parser("summary", help="Generate an executive summary from analysis results")
    summ.add_argument("--input", type=Path, required=True, help="Results directory (contains summary.json and findings.json)")
    summ.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    dedup = subparsers.add_parser("deduplicate", help="Remove duplicate or near-duplicate findings")
    dedup.add_argument("--input", type=Path, required=True, help="Path to findings.json")
    dedup.add_argument("--out", type=Path, required=True, help="Output path for deduplicated findings JSON")
    dedup.add_argument("--strategy", choices=["exact", "fuzzy"], default="exact",
                       help="Dedup strategy: exact (same type+agent+reasons) or fuzzy (same type+agent)")
    dedup.add_argument("--format", choices=["json", "text"], default="json", help="Output format for summary")

    aud = subparsers.add_parser("audit", help="Reproducibility audit: re-analyze evidence and compare to a reference run")
    aud.add_argument("--input", type=Path, required=True, help="Evidence directory")
    aud.add_argument("--reference", type=Path, required=True, help="Previous results directory (must contain findings.json)")
    aud.add_argument("--work-dir", type=Path, default=None, help="Work directory for re-analysis (default: temp)")
    aud.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    bun = subparsers.add_parser("bundle", help="Package evidence into a portable zip bundle with manifest")
    bun.add_argument("--input", type=Path, required=True, help="Evidence directory")
    bun.add_argument("--output", type=Path, required=True, help="Output zip file path")
    bun.add_argument("--include-analysis", action="store_true", default=False,
                     help="Run analysis and include results in the bundle")

    cmp = subparsers.add_parser("compare", help="Side-by-side comparison of two agents' behavior")
    cmp.add_argument("--input", type=Path, required=True, help="Evidence directory")
    cmp.add_argument("--agent-a", required=True, help="First agent ID")
    cmp.add_argument("--agent-b", required=True, help="Second agent ID")
    cmp.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    rpl = subparsers.add_parser("replay", help="Chronological event replay with behavioral annotations")
    rpl.add_argument("--input", type=Path, required=True, help="Evidence directory")
    rpl.add_argument("--format", choices=["json", "text"], default="text", help="Output format")
    rpl.add_argument("--no-annotations", action="store_true", default=False,
                     help="Disable behavioral annotations")

    enr = subparsers.add_parser("enrich", help="Add metadata (tool docs, roles, risk tags) to evidence")
    enr.add_argument("--input", type=Path, required=True, help="Evidence directory")
    enr.add_argument("--output", type=Path, required=True, help="Output directory for enriched evidence")
    enr.add_argument("--enrichments", default=None,
                     help="Comma-separated enrichments: tool_docs,agent_roles,risk_tags (default: all)")

    pol = subparsers.add_parser("policy", help="Evaluate evidence against user-defined detection rules")
    pol.add_argument("--rules", type=Path, required=True, help="Policy YAML file with detection rules")
    pol.add_argument("--input", type=Path, required=True, help="Evidence directory")
    pol.add_argument("--format", choices=["json", "text"], default="text", help="Output format")
    pol.add_argument("--severity", default=None, help="Minimum severity filter (LOW, MEDIUM, HIGH, CRITICAL)")

    sim = subparsers.add_parser("simulate", help="Generate synthetic evidence for testing detection pipelines")
    sim.add_argument("--output", type=Path, required=True, help="Output directory for generated evidence")
    sim.add_argument("--scenario", required=True,
                     help=f"Scenario: {', '.join(list_scenarios().keys())}")
    sim.add_argument("--agents", type=int, default=3, help="Number of agents (default: 3)")
    sim.add_argument("--events", type=int, default=20, help="Number of events (default: 20)")
    sim.add_argument("--seed", type=int, default=42, help="Random seed for deterministic output (default: 42)")

    dash = subparsers.add_parser("dashboard", help="Generate a standalone HTML dashboard from evidence")
    dash.add_argument("--input", type=Path, required=True, help="Evidence directory")
    dash.add_argument("--output", type=Path, default=Path("dashboard.html"), help="Output HTML file (default: dashboard.html)")
    dash.add_argument("--title", default="Orbit-IR Dashboard", help="Dashboard title")

    wat = subparsers.add_parser("watch", help="Monitor evidence directory for changes")
    wat.add_argument("--input", type=Path, required=True, help="Evidence directory to watch")
    wat.add_argument("--interval", type=float, default=2.0, help="Poll interval in seconds (default: 2)")

    conv = subparsers.add_parser("convert", help="Convert evidence between JSONL and CSV formats")
    conv.add_argument("--input", type=Path, required=True, help="Input file or directory")
    conv.add_argument("--output", type=Path, required=True, help="Output file or directory")
    conv.add_argument("--to", choices=["csv", "jsonl"], required=True, dest="target_format",
                      help="Target format: csv or jsonl")

    es = subparsers.add_parser("evidence-schema", help="Print or validate evidence file schemas")
    es.add_argument("--print", action="store_true", default=False, dest="print_schema",
                    help="Print the expected evidence schema")
    es.add_argument("--validate", type=Path, default=None, metavar="DIR",
                    help="Validate evidence files in DIR against the schema")
    es.add_argument("--format", choices=["json", "text"], default="text", help="Output format")
    es.add_argument("--strict", action="store_true", default=False,
                    help="Treat unknown fields as errors instead of warnings")

    norm = subparsers.add_parser("normalize", help="Normalize evidence fields (timestamps, agent IDs, whitespace)")
    norm.add_argument("--input", type=Path, required=True, help="Evidence directory")
    norm.add_argument("--output", type=Path, required=True, help="Output directory for normalized evidence")
    norm.add_argument("--rename", action="append", default=[], metavar="OLD=NEW",
                      help="Rename a field (repeatable, e.g. --rename src_agent=agent_id)")
    norm.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    tg = subparsers.add_parser("tag", help="Tag evidence events with custom labels")
    tg.add_argument("--input", type=Path, required=True, help="Evidence directory")
    tg.add_argument("--output", type=Path, default=None, help="Output directory for tagged evidence")
    tg.add_argument("--rule", action="append", default=[], metavar="FIELD=VALUE:TAG",
                    help="Tagging rule (repeatable, e.g. --rule agent_id=a1:suspicious)")
    tg.add_argument("--list", action="store_true", default=False, dest="list_tags",
                    help="List existing tags in the evidence")
    tg.add_argument("--filter", default=None, dest="filter_tag", metavar="TAG",
                    help="Filter events to those with this tag")
    tg.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    srch = subparsers.add_parser("search", help="Search evidence for events matching criteria")
    srch.add_argument("input", type=Path, help="Evidence JSONL file")
    srch.add_argument("--query", "-q", help="Full-text regex search across event fields")
    srch.add_argument("--agent", help="Filter by agent name")
    srch.add_argument("--action", help="Filter by action type")
    srch.add_argument("--after", help="Events after this ISO timestamp")
    srch.add_argument("--before", help="Events before this ISO timestamp")
    srch.add_argument("--format", choices=["json", "text"], default="text", dest="output_format")

    rpt = subparsers.add_parser("report", help="Generate a customizable analysis report with selectable sections")
    rpt.add_argument("--input", type=Path, required=True, help="Evidence directory")
    rpt.add_argument("--sections", default=None,
                     help="Comma-separated sections: summary,findings,agents,timeline,tools,recommendations (default: all)")
    rpt.add_argument("--severity", default=None,
                     help="Minimum severity threshold (low, medium, high, critical)")
    rpt.add_argument("--format", choices=["text", "markdown"], default="text", help="Output format")
    rpt.add_argument("--title", default="Orbit-IR Analysis Report", help="Report title")
    rpt.add_argument("--output", type=Path, default=None, help="Write report to file instead of stdout")

    ch = subparsers.add_parser("chain", help="Run a multi-step analysis pipeline from a YAML definition")
    ch.add_argument("--pipeline", type=Path, required=True, help="Pipeline YAML file")
    ch.add_argument("--input", type=Path, required=True, help="Base evidence directory")
    ch.add_argument("--work-dir", type=Path, default=None, help="Working directory for intermediate outputs")

    samp = subparsers.add_parser("sample", help="Downsample evidence for testing or exploration")
    samp.add_argument("--input", type=Path, required=True, help="Evidence directory")
    samp.add_argument("--output", type=Path, required=True, help="Output directory for sampled evidence")
    samp.add_argument("--count", type=int, default=None, help="Maximum events per source file")
    samp.add_argument("--percent", type=float, default=None, help="Percentage of events to keep (0-100)")
    samp.add_argument("--stratify-by", default=None, help="Field to stratify by (e.g. agent_id)")
    samp.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    samp.add_argument("--format", choices=["text", "json"], default="text")

    anon = subparsers.add_parser("anonymize", help="Redact identifiers with consistent pseudonyms for safe sharing")
    anon.add_argument("--input", type=Path, required=True, help="Evidence directory")
    anon.add_argument("--output", type=Path, required=True, help="Output directory for anonymized evidence")
    anon.add_argument("--salt", default="orbit-ir", help="Salt for pseudonym generation")
    anon.add_argument("--save-mapping", action="store_true", help="Save original->pseudonym mapping to file")
    anon.add_argument("--format", choices=["text", "json"], default="text")

    insp = subparsers.add_parser("inspect", help="Deep analysis of individual evidence events with context")
    insp.add_argument("--input", type=Path, required=True, help="Evidence file or directory")
    insp.add_argument("--index", type=int, default=None, help="Event index to inspect")
    insp.add_argument("--event-id", default=None, help="Event ID to inspect")
    insp.add_argument("--context", type=int, default=3, help="Number of surrounding events")
    insp.add_argument("--format", choices=["text", "json"], default="text")

    rdc = subparsers.add_parser("redact", help="Scrub PII from evidence with typed placeholders")
    rdc.add_argument("--input", type=Path, required=True, help="Evidence directory")
    rdc.add_argument("--output", type=Path, required=True, help="Output directory for redacted evidence")
    rdc.add_argument("--pattern-file", type=Path, default=None, help="Custom patterns file (NAME: regex per line)")
    rdc.add_argument("--format", choices=["text", "json"], default="text")

    bat = subparsers.add_parser("batch", help="Run multiple commands in sequence from a file")
    bat.add_argument("--file", type=Path, required=True, help="Batch file (one command per line, or YAML)")
    bat.add_argument("--var", action="append", default=[], metavar="KEY=VALUE",
                     help="Variable substitution (repeatable, e.g. --var INPUT=/data)")
    bat.add_argument("--format", choices=["text", "json"], default="text")

    da = subparsers.add_parser("diff-agents", help="Behavioral delta analysis between two agents")
    da.add_argument("--input", type=Path, required=True, help="Evidence directory")
    da.add_argument("--agent-a", required=True, help="First agent ID")
    da.add_argument("--agent-b", required=True, help="Second agent ID")
    da.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    piv = subparsers.add_parser("pivot", help="Cross-field pivot table for evidence events")
    piv.add_argument("--input", type=Path, required=True, help="Evidence directory or JSONL file")
    piv.add_argument("--row", required=True, help="Row field (supports dot notation, e.g. agent_id)")
    piv.add_argument("--col", required=True, help="Column field (supports dot notation, e.g. event_type)")
    piv.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    flt = subparsers.add_parser("filter", help="Complex event queries with AND/OR combinators")
    flt.add_argument("--input", type=Path, required=True, help="Evidence directory or JSONL file")
    flt.add_argument("--query", required=True,
                     help="Filter expression: field=val, field!=val, field~regex, field>n; AND with comma, OR with pipe")
    flt.add_argument("--limit", type=int, default=None, help="Max events to return")
    flt.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    agg = subparsers.add_parser("aggregate", help="Combine evidence from multiple sources")
    agg.add_argument("--input", type=Path, nargs="+", required=True, help="Evidence directories or JSONL files")
    agg.add_argument("--strategy", choices=["union", "intersect", "unique"], default="union",
                     help="Aggregation strategy (default: union)")
    agg.add_argument("--no-dedup", action="store_true", help="Keep duplicate events in union mode")
    agg.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    rnk = subparsers.add_parser("rank", help="Rank agents by composite risk score")
    rnk.add_argument("--input", type=Path, required=True, help="Evidence directory or JSONL file")
    rnk.add_argument("--sort", choices=["risk", "volume", "diversity"], default="risk",
                     help="Sort order (default: risk)")
    rnk.add_argument("--top", type=int, default=None, help="Show only top N agents")
    rnk.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    win = subparsers.add_parser("window", help="Sliding window analysis over event streams")
    win.add_argument("--input", type=Path, required=True, help="Evidence directory or JSONL file")
    win.add_argument("--size", type=int, default=10, help="Window size in events (default: 10)")
    win.add_argument("--step", type=int, default=None, help="Step size (default: half window)")
    win.add_argument("--metric", choices=["count", "agents", "types", "errors"], default="count",
                     help="Metric to compute per window")
    win.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    det = subparsers.add_parser("detect", help="Anomaly pattern detection in event streams")
    det.add_argument("--input", type=Path, required=True, help="Evidence directory or JSONL file")
    det.add_argument("--patterns", type=str, default=None,
                     help="Comma-separated patterns: burst,repeat,escalation,unusual_type")
    det.add_argument("--threshold", type=float, default=2.0, help="Detection threshold (default: 2.0)")
    det.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    cls = subparsers.add_parser("classify", help="Classify events as benign, suspicious, or malicious")
    cls.add_argument("--input", type=Path, required=True, help="Evidence directory or JSONL file")
    cls.add_argument("--threshold", type=float, default=0.5, help="Confidence threshold for high-risk (default: 0.5)")
    cls.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    bl = subparsers.add_parser("baseline", help="Create or compare behavioral baselines")
    bl.add_argument("--input", type=Path, required=True, help="Evidence directory or JSONL file")
    bl.add_argument("--create", action="store_true", help="Create a new baseline profile")
    bl.add_argument("--compare", type=Path, default=None, help="Path to baseline JSON to compare against")
    bl.add_argument("--drift-threshold", type=float, default=0.1, help="Minimum drift to report (default: 0.1)")
    bl.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

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
    elif args.command == "export":
        text = export_findings(args.input, args.format, output_path=args.out)
        print(text, end="")
        return
    elif args.command == "summary":
        result = build_executive_summary(args.input)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_summary_text(result), end="")
        return
    elif args.command == "deduplicate":
        all_findings = json.loads(args.input.read_text(encoding="utf-8"))
        unique, removed = deduplicate_findings(all_findings, strategy=args.strategy)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(unique, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        summary_text = format_dedup_summary(unique, removed, args.strategy)
        if args.format == "json":
            print(json.dumps({
                "total_input": len(all_findings),
                "unique": len(unique),
                "removed": len(removed),
                "strategy": args.strategy,
            }, sort_keys=True, indent=2))
        else:
            print(summary_text, end="")
        return
    elif args.command == "audit":
        import tempfile
        work = args.work_dir or Path(tempfile.mkdtemp(prefix="orbit-audit-"))
        report = audit_reproducibility(args.input, args.reference, work_dir=work)
        if args.format == "json":
            print(json.dumps(report, sort_keys=True, indent=2))
        else:
            print(format_audit_text(report), end="")
        if not report["reproducible"]:
            raise SystemExit(1)
        return
    elif args.command == "scope":
        agents_list = args.agents.split(",") if args.agents else None
        sources_list = args.sources.split(",") if args.sources else None
        result = apply_scope(
            args.input, args.out,
            start=args.start, end=args.end,
            agents=agents_list, sources=sources_list,
        )
        print(json.dumps(result, sort_keys=True, indent=2))
        return
    elif args.command == "bundle":
        result = create_bundle(args.input, args.output, include_analysis=args.include_analysis)
        print(format_bundle_text(result), end="")
        return
    elif args.command == "compare":
        result = compare_agents(args.input, args.agent_a, args.agent_b)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_comparison_text(result), end="")
        return
    elif args.command == "replay":
        events = replay_events(args.input, annotate=not args.no_annotations)
        if args.format == "json":
            print(json.dumps(events, sort_keys=True, indent=2, default=str))
        else:
            print(format_replay_text(events, show_annotations=not args.no_annotations), end="")
        return
    elif args.command == "enrich":
        enrichment_list = args.enrichments.split(",") if args.enrichments else None
        result = enrich_evidence(args.input, args.output, enrichments=enrichment_list)
        print(format_enrich_text(result), end="")
        return
    elif args.command == "policy":
        pol = load_policy(args.rules)
        violations = evaluate_policy(pol, args.input, severity_filter=args.severity)
        if args.format == "json":
            print(json.dumps(violations, sort_keys=True, indent=2))
        else:
            print(format_policy_text(violations), end="")
        if violations:
            raise SystemExit(1)
        return
    elif args.command == "simulate":
        result = simulate_evidence(
            args.output, args.scenario,
            num_agents=args.agents, num_events=args.events, seed=args.seed,
        )
        print(format_simulate_text(result), end="")
        return
    elif args.command == "dashboard":
        result = generate_dashboard(args.input, args.output, title=args.title)
        print(json.dumps(result, sort_keys=True, indent=2))
        return
    elif args.command == "watch":
        watch_evidence(args.input, interval=args.interval)
        return
    elif args.command == "convert":
        if args.input.is_dir():
            result = convert_evidence_dir(args.input, args.output, args.target_format)
        else:
            if args.target_format == "csv":
                result = convert_jsonl_to_csv(args.input, args.output)
            else:
                result = convert_csv_to_jsonl(args.input, args.output)
        print(format_convert_text(result), end="")
        return
    elif args.command == "evidence-schema":
        if args.print_schema:
            print(format_schema_text(), end="")
            return
        if args.validate is not None:
            issues = validate_evidence_schema(args.validate, strict=args.strict)
            if args.format == "json":
                print(json.dumps(issues, sort_keys=True, indent=2))
            else:
                print(format_validation_text(issues), end="")
            if any(i["severity"] == "error" for i in issues):
                raise SystemExit(1)
            return
        print("Use --print to display schemas or --validate DIR to validate evidence.", file=sys.stderr)
        raise SystemExit(2)
    elif args.command == "normalize":
        renames: dict[str, str] | None = None
        if args.rename:
            renames = {}
            for r in args.rename:
                if "=" not in r:
                    print(f"error: invalid rename {r!r}, expected OLD=NEW", file=sys.stderr)
                    raise SystemExit(2)
                old, new = r.split("=", 1)
                renames[old] = new
        result = normalize_evidence(args.input, args.output, renames=renames)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_normalize_text(result), end="")
        return
    elif args.command == "tag":
        if args.list_tags:
            result = list_tags(args.input)
            if args.format == "json":
                print(json.dumps(result, sort_keys=True, indent=2))
            else:
                for tag in result.get("unique_tags", []):
                    count = result["total_tags"].get(tag, 0)
                    print(f"  {tag}: {count}")
            return
        if args.filter_tag:
            events = filter_by_tag(args.input, args.filter_tag)
            if args.format == "json":
                print(json.dumps(events, sort_keys=True, indent=2, default=str))
            else:
                for e in events:
                    src = e.pop("_source_file", "")
                    agent = e.get("agent_id", "?")
                    ts = e.get("timestamp", "")
                    print(f"  [{src}] {ts} agent={agent} tags={e.get('tags', [])}")
            return
        if not args.output:
            print("error: --output is required when tagging (use --list or --filter for read-only)", file=sys.stderr)
            raise SystemExit(2)
        rules_list: list[dict] = []
        for r in args.rule:
            if ":" not in r or "=" not in r:
                print(f"error: invalid rule {r!r}, expected FIELD=VALUE:TAG", file=sys.stderr)
                raise SystemExit(2)
            field_value, tag = r.rsplit(":", 1)
            field, value = field_value.split("=", 1)
            rules_list.append({field: value, "tag": tag})
        result = tag_events(args.input, args.output, rules_list)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_tag_text(result), end="")
        return
    elif args.command == "search":
        results = search_evidence_fn(
            args.input,
            query=args.query,
            agent=args.agent,
            action=args.action,
            after=args.after,
            before=getattr(args, "before", None),
        )
        if args.output_format == "json":
            print(json.dumps(results, sort_keys=True, indent=2, default=str))
        else:
            print(format_search_text(results), end="")
        return
    elif args.command == "report":
        sections = args.sections.split(",") if args.sections else None
        config = ReportConfig(
            title=args.title,
            sections=sections or list(("summary", "findings", "agents", "timeline", "tools", "recommendations")),
            severity_threshold=args.severity,
            format=args.format,
        )
        text = generate_report(args.input, config)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8")
            print(f"Report written to {args.output}", file=sys.stderr)
        else:
            print(text, end="")
        return
    elif args.command == "chain":
        import tempfile
        pipeline_text = args.pipeline.read_text(encoding="utf-8")
        steps = parse_chain(pipeline_text)
        work = args.work_dir or Path(tempfile.mkdtemp(prefix="orbit-chain-"))
        result = run_chain(steps, args.input, work)
        print(format_chain_text(result), end="")
        if result["failed"] > 0:
            raise SystemExit(1)
        return
    elif args.command == "sample":
        result = sample_evidence(
            args.input, args.output,
            count=args.count, percent=args.percent,
            stratify_by=args.stratify_by, seed=args.seed,
        )
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_sample_text(result), end="")
        return
    elif args.command == "anonymize":
        result = anonymize_evidence(
            args.input, args.output,
            salt=args.salt, save_mapping=args.save_mapping,
        )
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_anonymize_text(result), end="")
        return
    elif args.command == "inspect":
        if args.event_id is not None or args.index is not None:
            result = inspect_event(
                args.input, index=args.index, event_id=args.event_id,
                context=args.context,
            )
        else:
            result = list_events(args.input)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2, default=str))
        else:
            print(format_inspect_text(result), end="")
        return
    elif args.command == "redact":
        result = redact_evidence(
            args.input, args.output, pattern_file=args.pattern_file,
        )
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_redact_text(result), end="")
        return
    elif args.command == "batch":
        steps = parse_batch_file(args.file)
        variables: dict[str, str] = {}
        for v in args.var:
            if "=" in v:
                k, val = v.split("=", 1)
                variables[k] = val
        result = run_batch(steps, variables=variables if variables else None)
        if args.format == "json":
            print(json.dumps(result.to_dict(), sort_keys=True, indent=2))
        else:
            print(format_batch_text(result), end="")
        if result.failed > 0:
            raise SystemExit(1)
        return
    elif args.command == "diff-agents":
        result = diff_agents(args.input, args.agent_a, args.agent_b)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_diff_agents_text(result), end="")
        return
    elif args.command == "filter":
        result = filter_events(args.input, args.query, limit=args.limit)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_filter_text(result), end="")
        return
    elif args.command == "pivot":
        result = pivot_events(args.input, args.row, args.col)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_pivot_text(result), end="")
        return
    elif args.command == "aggregate":
        result = aggregate_events(
            args.input,
            strategy=args.strategy,
            deduplicate=not args.no_dedup,
        )
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_aggregate_text(result), end="")
        return
    elif args.command == "rank":
        result = rank_agents(
            args.input,
            sort_by=args.sort,
            top_n=args.top,
        )
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_rank_text(result), end="")
        return
    elif args.command == "window":
        result = window_analysis(
            args.input,
            window_size=args.size,
            step=args.step,
            metric=args.metric,
        )
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_window_text(result), end="")
        return
    elif args.command == "detect":
        pats = args.patterns.split(",") if args.patterns else None
        result = detect_anomalies(
            args.input,
            patterns=pats,
            threshold=args.threshold,
        )
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_detect_output(result), end="")
        return
    elif args.command == "classify":
        result = classify_events(args.input, threshold=args.threshold)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_classify_text(result), end="")
        return
    elif args.command == "baseline":
        if args.create:
            result = create_baseline(args.input)
            if args.format == "json":
                print(json.dumps(result, sort_keys=True, indent=2))
            else:
                print(format_baseline_text(result), end="")
        elif args.compare:
            result = compare_baseline(
                args.input, args.compare,
                drift_threshold=args.drift_threshold,
            )
            if args.format == "json":
                print(json.dumps(result, sort_keys=True, indent=2))
            else:
                print(format_baseline_text(result), end="")
        else:
            print("error: specify --create or --compare <baseline.json>", file=sys.stderr)
            raise SystemExit(2)
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
