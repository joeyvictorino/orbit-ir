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
from .correlate_agents import correlate_agents_analysis, format_correlate_agents_text
from .sentiment import analyze_sentiment, format_sentiment_text
from .profile_agents import profile_agents, format_profile_text
from .benchmark import run_benchmark, format_benchmark_text
from .reconstruct import reconstruct_incident, format_reconstruct_text
from .ioc import extract_iocs, format_ioc_text
from .topology import load_and_build as load_topology, format_topology_text, format_topology_dot
from .timeline_compare import load_and_compare, format_compare_text
from .mitre_report import generate_mitre_report, format_mitre_report_text
from .evidence_chain import build_evidence_chains, format_evidence_chain_text
from .blast_radius import estimate_blast_radius, format_blast_radius_text
from .remediate_ir import generate_remediations, format_remediate_text
from .frequency import build_frequency as build_freq, format_frequency_text, load_and_build as load_frequency
from .outlier import detect_outliers, format_outlier_text, load_and_detect as load_outliers
from .playbook import generate_playbook, format_playbook_text
from .risk_score import compute_risk_score, format_risk_score_text
from .timeline_export import export_timeline, TimelineExporter
from .agent_profile import profile_evidence_agents, format_agent_profile_text
from .compliance_map import map_compliance, format_compliance_map_text
from .evidence_score import score_evidence, format_evidence_score_text
from .stix_export import STIXExporter, export_stix
from .executive_brief import ExecutiveBriefGenerator, generate_executive_brief, format_brief_text, format_brief_markdown
from .ingest import EvidenceIngester, format_ingest_text
from .report_template import TemplateReporter, list_templates, show_template, format_template_list
from .attribution import load_and_attribute, format_attribution_text, summarize_attributions
from .diff_timeline import load_and_diff, format_diff_text as format_diff_timeline_text
from .kill_chain import load_and_analyze as load_and_analyze_kill_chain, format_kill_chain_text
from .impact import analyze_impact, format_impact_text
from .counterfactual import analyze_counterfactual, format_counterfactual_text
from .privesc import analyze_privilege_escalation, format_text as format_privesc_text, format_json as format_privesc_json
from .data_flow import analyze_data_flow, format_data_flow_text
from .compliance_check import check_compliance, format_compliance_text, list_frameworks


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

    ca = subparsers.add_parser("correlate-agents", help="Cross-agent behavioral correlation analysis")
    ca.add_argument("--input", type=Path, required=True, help="Evidence directory or JSONL file")
    ca.add_argument("--min-similarity", type=float, default=0.3, help="Minimum Jaccard similarity (default: 0.3)")
    ca.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    sent = subparsers.add_parser("sentiment", help="Analyze event tone and intent markers")
    sent.add_argument("--input", type=Path, required=True, help="Evidence directory or JSONL file")
    sent.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    prof = subparsers.add_parser("profile", help="Profile agent behavior patterns from evidence")
    prof.add_argument("--input", type=Path, required=True, help="Evidence directory")
    prof.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    bench = subparsers.add_parser("benchmark", help="Benchmark analysis pipeline performance")
    bench.add_argument("--input", type=Path, required=True, help="Evidence directory")
    bench.add_argument("--iterations", type=int, default=5, help="Number of iterations (default: 5)")
    bench.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    topo = subparsers.add_parser("topology", help="Map agent communication topology with centrality analysis")
    topo.add_argument("--input", type=Path, required=True, help="Evidence directory or messages.jsonl")
    topo.add_argument("--out", type=Path, default=None, help="Output file (default: stdout)")
    topo.add_argument("--format", choices=["text", "json", "dot"], default="text", help="Output format")

    tc = subparsers.add_parser("timeline-compare", help="Diff two timeline exports")
    tc.add_argument("--a", type=Path, required=True, help="First timeline JSONL")
    tc.add_argument("--b", type=Path, required=True, help="Second timeline JSONL")
    tc.add_argument("--out", type=Path, default=None, help="Output file (default: stdout)")
    tc.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    recon = subparsers.add_parser("reconstruct", help="Build an incident narrative from evidence events")
    recon.add_argument("--input", type=Path, required=True, help="Evidence directory or file")
    recon.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    recon.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ioc_parser = subparsers.add_parser("ioc", help="Extract indicators of compromise from evidence")
    ioc_parser.add_argument("--input", type=Path, required=True, help="Evidence directory or file")
    ioc_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    ioc_parser.add_argument("--type", default=None, dest="ioc_type",
                            help="Filter to specific IOC type (ipv4, domain, md5, sha256, url, email, file_path, command)")
    ioc_parser.add_argument("--min-count", type=int, default=1, help="Minimum occurrence count (default: 1)")
    ioc_parser.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    mr = subparsers.add_parser("mitre-report", help="MITRE ATT&CK coverage report from evidence")
    mr.add_argument("--input", type=Path, required=True, help="Evidence directory or file")
    mr.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    mr.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ec = subparsers.add_parser("evidence-chain", help="Build causal chains linking events by shared entities")
    ec.add_argument("--input", type=Path, required=True, help="Evidence directory or file")
    ec.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    ec.add_argument("--min-chain-length", type=int, default=2, help="Minimum events in a chain (default: 2)")
    ec.add_argument("--max-chains", type=int, default=20, help="Maximum chains to show (default: 20)")
    ec.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    freq_p = subparsers.add_parser("frequency", help="Event frequency analysis across agents and types")
    freq_p.add_argument("--input", type=Path, required=True, help="Evidence directory or JSONL file")
    freq_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    freq_p.add_argument("--out", type=Path, default=None, help="Write output to file")

    out_p = subparsers.add_parser("outlier", help="Statistical outlier detection for event patterns")
    out_p.add_argument("--input", type=Path, required=True, help="Evidence directory or JSONL file")
    out_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    out_p.add_argument("--z-threshold", type=float, default=2.0, help="Z-score threshold (default: 2.0)")
    out_p.add_argument("--out", type=Path, default=None, help="Write output to file")

    br = subparsers.add_parser("blast-radius", help="Estimate incident blast radius from evidence")
    br.add_argument("--input", type=Path, required=True, help="Evidence directory or file")
    br.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    br.add_argument("--threshold", type=float, default=0.0, help="Minimum blast radius score to report (default: 0)")
    br.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    rem = subparsers.add_parser("remediate", help="Generate remediation suggestions from detected incidents")
    rem.add_argument("--input", type=Path, required=True, help="Evidence directory or file")
    rem.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    rem.add_argument("--severity", default=None, help="Minimum severity filter (critical, high, medium, low)")
    rem.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    pb = subparsers.add_parser("playbook", help="Generate incident response playbooks from evidence")
    pb.add_argument("--input", type=Path, required=True, help="Evidence directory or file")
    pb.add_argument("--format", choices=["text", "json", "markdown"], default="text", help="Output format")
    pb.add_argument("--severity", default=None, help="Minimum severity threshold")
    pb.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    rs = subparsers.add_parser("risk-score", help="Compute composite risk score from findings")
    rs.add_argument("--input", type=Path, required=True, help="Findings JSON file or evidence directory")
    rs.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    rs.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    te = subparsers.add_parser("timeline-export", help="Export incident timeline in multiple formats (CSV, ICS, Gantt, Markdown)")
    te.add_argument("--input", type=Path, required=True, help="Evidence directory or file")
    te.add_argument("--format", choices=["csv", "ics", "gantt", "markdown"], default="csv", help="Export format")
    te.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    te.add_argument("--agent", default=None, help="Filter to specific agent")
    te.add_argument("--since", default=None, help="Only events after this ISO timestamp")

    ap = subparsers.add_parser("agent-profile", help="Build behavioral profiles for each agent")
    ap.add_argument("--input", type=Path, required=True, help="Evidence directory or file")
    ap.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    ap.add_argument("--agent", default=None, help="Filter to specific agent")
    ap.add_argument("--min-risk", type=float, default=0.0, help="Minimum risk score to show (default: 0)")
    ap.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    cm = subparsers.add_parser("compliance-map", help="Map findings to compliance frameworks (NIST, SOC2, ISO 27001)")
    cm.add_argument("--input", type=Path, required=True, help="Analysis results JSON file")
    cm.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    cm.add_argument("--framework", action="append", default=None, help="Framework(s) to map (default: all); repeat for multiple")
    cm.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    es = subparsers.add_parser("evidence-score", help="Score evidence quality and completeness")
    es.add_argument("--input", type=Path, required=True, help="Evidence directory or file")
    es.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    es.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    stix = subparsers.add_parser("stix", help="Export evidence as STIX 2.1 cyber threat intelligence bundle")
    stix.add_argument("--input", type=Path, required=True, help="Evidence directory or file")
    stix.add_argument("--include-indicators", action="store_true", default=False, help="Extract IP/domain indicators from events")
    stix.add_argument("--format", choices=["json"], default="json", help="Output format")
    stix.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    eb = subparsers.add_parser("executive-brief", help="Generate one-page executive briefing from evidence")
    eb.add_argument("--input", type=Path, required=True, help="Evidence directory or file")
    eb.add_argument("--classification", default="CONFIDENTIAL", help="Document classification level")
    eb.add_argument("--format", choices=["text", "json", "markdown"], default="text", help="Output format")
    eb.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ig = subparsers.add_parser("ingest", help="Ingest evidence from multiple formats (JSON, CSV, syslog, CloudTrail)")
    ig.add_argument("--input", type=Path, required=True, help="Evidence file or directory to ingest")
    ig.add_argument("--format", choices=["json", "csv", "syslog", "cloudtrail", "auto"], default="auto", help="Input format (default: auto-detect)")
    ig.add_argument("--output", type=Path, default=None, help="Write normalised events to output directory")
    ig.add_argument("--column-map", type=str, default=None, help="CSV column mapping as JSON object, e.g. '{\"timestamp\":\"ts\",\"agent\":\"actor\"}'")

    rt = subparsers.add_parser("report-template", help="Generate reports from customizable templates")
    rt.add_argument("--list", action="store_true", default=False, help="List available report templates")
    rt.add_argument("--show", type=str, default=None, metavar="NAME", help="Show template source for a builtin template")
    rt.add_argument("--path", type=Path, default=None, help="Evidence directory or file")
    rt.add_argument("--template", type=str, default="full", help="Template name or path to custom template file")
    rt.add_argument("--title", type=str, default="Incident Report", help="Report title")
    rt.add_argument("--format", choices=["text", "markdown", "html"], default="text", help="Output format")
    rt.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    attr = subparsers.add_parser("attribution", help="Attribute evidence items to source agents and actions")
    attr.add_argument("--timeline", type=Path, required=True, help="Timeline events file or directory")
    attr.add_argument("--evidence", type=Path, required=True, help="Evidence items file or directory")
    attr.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    attr.add_argument("--min-confidence", type=float, default=0.0, help="Minimum attribution confidence (0.0-1.0)")
    attr.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    dtl = subparsers.add_parser("diff-timeline", help="Compare two incident timelines and highlight differences")
    dtl.add_argument("--baseline", type=Path, required=True, help="Baseline timeline file or directory")
    dtl.add_argument("--compare", type=Path, required=True, help="Comparison timeline file or directory")
    dtl.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    dtl.add_argument("--match-keys", type=str, default=None, help="Comma-separated keys for event matching")
    dtl.add_argument("--threshold", type=float, default=60.0, help="Timing shift detection threshold in seconds")
    dtl.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    kc = subparsers.add_parser("kill-chain", help="Score kill chain completeness and detect coverage gaps")
    kc.add_argument("--path", type=Path, required=True, help="Evidence file or directory to analyze")
    kc.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    kc.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    imp = subparsers.add_parser("impact", help="Per-detection impact quantification with blast radius scoring")
    imp.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    imp.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    imp.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="low", help="Minimum detection severity to assess")
    imp.add_argument("--window", type=float, default=300.0, help="Time window in seconds around each detection")
    imp.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    cf = subparsers.add_parser("counterfactual", help="What-if scenario analysis for incident response")
    cf.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    cf.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    cf.add_argument("--scenarios", type=Path, default=None, help="YAML/JSON file defining custom scenarios")
    cf.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    pe = subparsers.add_parser("privilege-escalation", help="Detect privilege escalation paths in agent control events")
    pe.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    pe.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    pe.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    df = subparsers.add_parser("data-flow", help="Trace data flows through agent interactions")
    df.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    df.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    df.add_argument("--sensitivity-threshold", choices=["low", "medium", "high"], default="medium", help="Minimum sensitivity for exfiltration alerts")
    df.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    cc = subparsers.add_parser("compliance-check", help="Evaluate evidence against compliance framework controls")
    cc.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    cc.add_argument("--framework", choices=["nist", "soc2", "iso27001"], default="nist", help="Compliance framework")
    cc.add_argument("--rules", type=Path, default=None, help="Custom rules YAML/JSON file")
    cc.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    cc.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

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
    elif args.command == "correlate-agents":
        result = correlate_agents_analysis(
            args.input, min_similarity=args.min_similarity,
        )
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_correlate_agents_text(result), end="")
        return
    elif args.command == "sentiment":
        result = analyze_sentiment(args.input)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_sentiment_text(result), end="")
        return
    elif args.command == "classify":
        result = classify_events(args.input, threshold=args.threshold)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_classify_text(result), end="")
        return
    elif args.command == "profile":
        result = profile_agents(str(args.input))
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_profile_text(result), end="")
        return
    elif args.command == "benchmark":
        result = run_benchmark(str(args.input), iterations=args.iterations)
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(format_benchmark_text(result), end="")
        return
    elif args.command == "topology":
        topo = load_topology(args.input)
        if args.format == "json":
            output = json.dumps(topo, indent=2, sort_keys=True)
        elif args.format == "dot":
            output = format_topology_dot(topo)
        else:
            output = format_topology_text(topo)
        if args.out:
            args.out.write_text(output, encoding="utf-8")
            print(f"Topology written to {args.out}")
        else:
            print(output, end="")
        return
    elif args.command == "timeline-compare":
        result = load_and_compare(args.a, args.b)
        if args.format == "json":
            output = json.dumps(result, indent=2, sort_keys=True)
        else:
            output = format_compare_text(result)
        if args.out:
            args.out.write_text(output, encoding="utf-8")
            print(f"Comparison written to {args.out}")
        else:
            print(output, end="")
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
    elif args.command == "reconstruct":
        r = reconstruct_incident(args.input)
        if args.format == "json":
            output = json.dumps(r.to_dict(), sort_keys=True, indent=2)
        else:
            output = format_reconstruct_text(r)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Narrative written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "ioc":
        extractor = extract_iocs(args.input)
        data = extractor.to_dict()
        if args.format == "json":
            output = json.dumps(data, sort_keys=True, indent=2)
        else:
            output = format_ioc_text(data, type_filter=args.ioc_type, min_count=args.min_count)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"IOCs written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "mitre-report":
        gen = generate_mitre_report(args.input)
        data = gen.to_dict()
        if args.format == "json":
            output = json.dumps(data, sort_keys=True, indent=2)
        else:
            output = format_mitre_report_text(data)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"MITRE report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "evidence-chain":
        builder = build_evidence_chains(
            args.input,
            min_chain_length=args.min_chain_length,
            max_chains=args.max_chains,
        )
        data = builder.to_dict()
        if args.format == "json":
            output = json.dumps(data, sort_keys=True, indent=2)
        else:
            output = format_evidence_chain_text(data)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Evidence chains written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return

    elif args.command == "frequency":
        result = load_frequency(args.input)
        if args.format == "json":
            output = json.dumps(result, sort_keys=True, indent=2)
        else:
            output = format_frequency_text(result)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return

    elif args.command == "outlier":
        result = load_outliers(args.input, z_threshold=args.z_threshold)
        if args.format == "json":
            output = json.dumps(result, sort_keys=True, indent=2)
        else:
            output = format_outlier_text(result)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return

    elif args.command == "blast-radius":
        est = estimate_blast_radius(args.input)
        data = est.to_dict()
        if args.format == "json":
            output = json.dumps(data, sort_keys=True, indent=2)
        else:
            output = format_blast_radius_text(data, threshold=args.threshold)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Blast radius report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "remediate":
        gen = generate_remediations(args.input, severity_filter=args.severity)
        data = gen.to_dict()
        if args.format == "json":
            output = json.dumps(data, sort_keys=True, indent=2)
        else:
            output = format_remediate_text(data)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Remediation report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "playbook":
        gen = generate_playbook(args.input, severity_threshold=args.severity)
        data = gen.to_dict()
        if args.format == "json":
            output = json.dumps(data, sort_keys=True, indent=2)
        elif args.format == "markdown":
            from .playbook import format_playbook_markdown
            output = format_playbook_markdown(data)
        else:
            output = format_playbook_text(data)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Playbook written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "risk-score":
        result = compute_risk_score(args.input)
        data = result.to_dict()
        if args.format == "json":
            output = json.dumps(data, sort_keys=True, indent=2)
        else:
            output = format_risk_score_text(data)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Risk score report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "timeline-export":
        output = export_timeline(
            args.input, fmt=args.format,
            agent=args.agent, since=args.since,
        )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Timeline exported to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "agent-profile":
        profiler = profile_evidence_agents(
            args.input, agent=args.agent, min_risk=args.min_risk,
        )
        data = profiler.to_dict()
        if args.format == "json":
            output = json.dumps(data, sort_keys=True, indent=2)
        else:
            output = format_agent_profile_text(data)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Agent profiles written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "compliance-map":
        result = map_compliance(args.input, frameworks=args.framework)
        data = result.to_dict()
        if args.format == "json":
            output = json.dumps(data, sort_keys=True, indent=2)
        else:
            output = format_compliance_map_text(data)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Compliance map written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "evidence-score":
        result = score_evidence(args.input)
        data = result.to_dict()
        if args.format == "json":
            output = json.dumps(data, sort_keys=True, indent=2)
        else:
            output = format_evidence_score_text(data)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Evidence score written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "stix":
        exporter = STIXExporter()
        exporter.load_events(args.input)
        bundle = exporter.to_stix_bundle(include_indicators=args.include_indicators)
        output = json.dumps(bundle, sort_keys=True, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"STIX bundle written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "executive-brief":
        gen = ExecutiveBriefGenerator(classification=args.classification)
        gen.load_events(args.input)
        data = gen.generate()
        if args.format == "json":
            output = json.dumps(data, sort_keys=True, indent=2)
        elif args.format == "markdown":
            output = format_brief_markdown(data)
        else:
            output = format_brief_text(data)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Executive brief written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "ingest":
        column_map = None
        if args.column_map:
            column_map = json.loads(args.column_map)
        ingester = EvidenceIngester(column_map=column_map)
        ingester.ingest(args.input, fmt=args.format, output_dir=args.output)
        print(format_ingest_text(ingester.summary()))
        return
    elif args.command == "report-template":
        if args.list:
            print(format_template_list(list_templates()))
            return
        if args.show:
            tmpl = show_template(args.show)
            if tmpl is None:
                print(f"Unknown template: {args.show}", file=sys.stderr)
                raise SystemExit(1)
            print(tmpl, end="")
            return
        if not args.path:
            print("error: --path is required when rendering a report", file=sys.stderr)
            raise SystemExit(2)
        reporter = TemplateReporter()
        rendered = reporter.render(args.template, args.path, title=args.title)
        if args.format == "html":
            output = reporter.to_html(rendered)
        else:
            output = rendered
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "attribution":
        report = load_and_attribute(
            args.timeline, args.evidence, min_confidence=args.min_confidence
        )
        if args.format == "json":
            data = {
                "attributions": [
                    {
                        "evidence_id": a.evidence_id,
                        "source": {"name": a.source.name, "type": a.source.source_type, "confidence": a.source.confidence},
                        "timestamp": a.timestamp,
                        "action": a.action,
                        "confidence": a.context.get("matched_confidence", 0),
                        "chain": a.chain,
                    }
                    for a in report.attributions
                ],
                "unattributed": report.unattributed,
                "sources": [
                    {"name": s.name, "type": s.source_type, "confidence": s.confidence, "evidence_count": len(s.evidence_ids)}
                    for s in report.sources
                ],
                "confidence_distribution": report.confidence_distribution,
                "summary": summarize_attributions(report),
            }
            output = json.dumps(data, sort_keys=True, indent=2)
        else:
            output = format_attribution_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Attribution report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "diff-timeline":
        match_keys = None
        if args.match_keys:
            match_keys = [k.strip() for k in args.match_keys.split(",")]
        diff = load_and_diff(
            args.baseline, args.compare, match_keys=match_keys, threshold_seconds=args.threshold
        )
        if args.format == "json":
            data = {
                "added": diff.added,
                "removed": diff.removed,
                "modified": [{"baseline": old, "compare": new} for old, new in diff.modified],
                "timing_shifts": diff.timing_shifts,
                "summary": diff.summary,
            }
            output = json.dumps(data, sort_keys=True, indent=2)
        else:
            output = format_diff_timeline_text(diff)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Timeline diff written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "impact":
        from .blast_radius import _load_events as _load_ev
        evidence_events = _load_ev(args.evidence_dir)
        detections = [e for e in evidence_events if e.get("type") in (
            "detection", "anomaly", "alert", "finding",
        ) or e.get("severity") or e.get("risk_level")]
        if not detections:
            detections = evidence_events
        assessments = analyze_impact(
            detections, args.evidence_dir,
            window_seconds=args.window, min_severity=args.min_severity,
        )
        if args.format == "json":
            output = json.dumps(assessments, sort_keys=True, indent=2)
        else:
            output = format_impact_text(assessments)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Impact assessment written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "counterfactual":
        from .blast_radius import _load_events as _load_ev2
        evidence_events = _load_ev2(args.evidence_dir)
        detections = [e for e in evidence_events if e.get("type") in (
            "detection", "anomaly", "alert", "finding",
        ) or e.get("severity") or e.get("risk_level")]
        if not detections:
            detections = evidence_events
        results = analyze_counterfactual(
            detections, args.evidence_dir,
            scenario_file=args.scenarios,
        )
        if args.format == "json":
            output = json.dumps(results, sort_keys=True, indent=2)
        else:
            output = format_counterfactual_text(results)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Counterfactual analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "privilege-escalation":
        from .blast_radius import _load_events as _load_pe
        evidence_events = _load_pe(args.evidence_dir)
        control = [e for e in evidence_events if e.get("actual_tool") or e.get("policy_decision")]
        report = analyze_privilege_escalation(evidence_events, control)
        if args.format == "json":
            output = format_privesc_json(report)
        else:
            output = format_privesc_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Privilege escalation analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "data-flow":
        result = analyze_data_flow(
            args.evidence_dir,
            sensitivity_threshold=args.sensitivity_threshold,
        )
        if args.format == "json":
            output = json.dumps(result, sort_keys=True, indent=2)
        else:
            output = format_data_flow_text(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Data flow analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "compliance-check":
        result = check_compliance(
            args.evidence_dir,
            framework=args.framework,
            custom_rules_path=args.rules,
        )
        if args.format == "json":
            output = json.dumps(result, sort_keys=True, indent=2)
        else:
            output = format_compliance_text(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Compliance check written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "kill-chain":
        report = load_and_analyze_kill_chain(str(args.path))
        if args.format == "json":
            from dataclasses import asdict
            output = json.dumps(asdict(report), sort_keys=True, indent=2)
        else:
            output = format_kill_chain_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Kill chain analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
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
