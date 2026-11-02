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
from .session_replay import replay_sessions, format_replay_text as format_session_replay_text, format_replay_json as format_session_replay_json
from .intent import classify_intents, format_intent_text, format_intent_json
from .dwell_time import analyze as analyze_dwell_time, format_text as format_dwell_text, format_json as format_dwell_json
from .access_pattern import analyze as analyze_access_pattern, format_text as format_access_text, format_json as format_access_json
from .threat_intel import analyze as analyze_threat_intel, format_text as format_threat_text, format_json as format_threat_json
from .sla import analyze as analyze_sla, format_text as format_sla_text, format_json as format_sla_json
from .evidence_quality import analyze as analyze_evidence_quality, format_text as format_eq_text, format_json as format_eq_json
from .response_effectiveness import analyze as analyze_response_effectiveness, format_text as format_re_text, format_json as format_re_json
from .coordination import analyze as analyze_coordination, format_text as format_coord_text, format_json as format_coord_json
from .evidence_gaps import analyze as analyze_evidence_gaps, format_text as format_gaps_text, format_json as format_gaps_json
from .tactic_chain import analyze_tactic_chains, format_text as format_tc_text, format_json as format_tc_json, _load_events as _load_tc_events
from .resource_map import analyze_resource_map, format_text as format_rm_text, format_json as format_rm_json, _load_events as _load_rm_events
from .exfil_detect import analyze_exfiltration, format_text as format_exfil_text, format_json as format_exfil_json, _load_events as _load_exfil_events
from .c2_detect import analyze_c2, format_text as format_c2_text, format_json as format_c2_json, _load_events as _load_c2_events
from .persistence_detect import analyze_persistence, format_text as format_persist_text, format_json as format_persist_json, _load_events as _load_persist_events
from .defense_evasion import analyze_defense_evasion, format_text as format_evasion_text, format_json as format_evasion_json, _load_events as _load_evasion_events
from .lateral_path import analyze_lateral, format_text as format_lateral_text, format_json as format_lateral_json, _load_events as _load_lateral_events
from .credential_harvest import analyze_harvest, format_text as format_harvest_text, format_json as format_harvest_json, _load_events as _load_harvest_events
from .tool_abuse import analyze_tool_abuse, format_text as format_abuse_text, format_json as format_abuse_json, _load_events as _load_abuse_events
from .data_staging import analyze_staging, format_text as format_staging_text, format_json as format_staging_json, _load_events as _load_staging_events
from .privilege_abuse import analyze_privilege_abuse, format_text as format_privabuse_text, format_json as format_privabuse_json, _load_events as _load_privabuse_events
from .tool_misuse import analyze_tool_misuse, format_text as format_toolmisuse_text, format_json as format_toolmisuse_json, _load_events as _load_toolmisuse_events
from .sandbox_escape import analyze_sandbox_escape, format_text as format_escape_text, format_json as format_escape_json, _load_events as _load_escape_events
from .supply_chain import analyze as analyze_supply_chain, format_text as format_sc_text, format_json as format_sc_json, _load_events as _load_sc_events
from .api_abuse import analyze_api_abuse, format_text as format_apiabuse_text, format_json as format_apiabuse_json, _load_events as _load_apiabuse_events
from .memory_forensics import analyze_memory_forensics, format_text as format_memfor_text, format_json as format_memfor_json, _load_events as _load_memfor_events
from .command_inject import analyze_command_inject, format_text as format_cmdinject_text, format_json as format_cmdinject_json, _load_events as _load_cmdinject_events
from .file_access import analyze_file_access, format_text as format_fileaccess_text, format_json as format_fileaccess_json, _load_events as _load_fileaccess_events
from .prompt_inject import analyze_prompt_inject, format_text as format_promptinject_text, format_json as format_promptinject_json, _load_events as _load_promptinject_events
from .impact_chain import analyze_impact_chains, format_text as format_ic_text, format_json as format_ic_json, _load_events as _load_ic_events
from .session_link import analyze_session_links, format_text as format_sl_text, format_json as format_sl_json, _load_events as _load_sl_events
from .anomaly_score import score_anomalies, format_text as format_as_text, format_json as format_as_json, _load_events as _load_as_events
from .trust_boundary import analyze_trust_boundaries, format_text as format_tb_text, format_json as format_tb_json, _load_events as _load_tb_events
from .threat_model import analyze as analyze_threat_model, format_text as format_tm_text, format_json as format_tm_json
from .capability_map import analyze_capability_map, format_text as format_cm_text, format_json as format_cm_json, _load_events as _load_cm_events
from .session_stats import analyze as analyze_session_stats, format_text as format_ss_text, format_json as format_ss_json
from .role_drift import analyze_role_drift, format_text as format_rd_text, format_json as format_rd_json, _load_events as _load_rd_events
from .deception_detect import analyze_deception, format_text as format_deception_text, format_json as format_deception_json, _load_events as _load_deception_events
from .goal_drift import analyze_goal_drift, format_text as format_goaldrift_text, format_json as format_goaldrift_json, _load_events as _load_goaldrift_events
from .steganography import analyze_steganography, format_text as format_stego_text, format_json as format_stego_json, _load_events as _load_stego_events
from .behavior_cluster import analyze_behavior_clusters, format_text as format_cluster_text, format_json as format_cluster_json, _load_events as _load_cluster_events
from .token_trace import analyze_token_trace, format_text as format_tt_text, format_json as format_tt_json, _load_events as _load_tt_events
from .event_graph import analyze_event_graph, format_text as format_eg_text, format_json as format_eg_json, _load_events as _load_eg_events
from .chain_of_thought import analyze_chain_of_thought, format_text as format_cot_text, format_json as format_cot_json, _load_events as _load_cot_events
from .alert_fatigue import analyze_alert_fatigue, format_text as format_af_text, format_json as format_af_json, _load_events as _load_af_events
from .decision_tree import analyze_decision_tree, format_text as format_dt_text, format_json as format_dt_json, _load_events as _load_dt_events
from .log_anomaly import analyze_log_anomalies, format_text as format_la_text, format_json as format_la_json, _load_events as _load_la_events
from .agent_drift import analyze_agent_drift, format_text as format_ad_text, format_json as format_ad_json, _load_events as _load_ad_events
from .response_time import analyze_response_times, format_text as format_rt_text, format_json as format_rt_json, _load_events as _load_rt_events
from .action_sequence import analyze_action_sequences, format_text as format_as_text, format_json as format_as_json
from .insider_threat import analyze as analyze_insider_threat, format_text as format_it_text, format_json as format_it_json, _load_events as _load_it_events
from .exfil_rate import analyze_exfil_rates, format_text as format_er_text, format_json as format_er_json, _load_events as _load_er_events
from .event_cluster import analyze_event_clusters, format_text as format_ec_text, format_json as format_ec_json, _load_events as _load_ec_events
from .tool_chain import analyze_tool_chains, format_text as format_tch_text, format_json as format_tch_json, _load_events as _load_tch_events
from .privilege_chain import analyze as analyze_privilege_chain, format_text as format_pc_text, format_json as format_pc_json, _load_events as _load_pc_events
from .resource_abuse import analyze as analyze_resource_abuse, format_text as format_ra_text, format_json as format_ra_json, _load_events as _load_ra_events
from .event_timeline_gap import analyze_timeline_gaps, format_text as format_etg_text, format_json as format_etg_json, _load_events as _load_etg_events
from .agent_handoff import analyze_handoffs, format_text as format_ah_text, format_json as format_ah_json, _load_events as _load_ah_events
from .credential_replay import analyze as analyze_credential_replay, format_text as format_creplay_text, format_json as format_creplay_json, _load_events as _load_creplay_events
from .agent_collusion import analyze as analyze_agent_collusion, format_text as format_collusion_text, format_json as format_collusion_json, _load_events as _load_collusion_events
from .evidence_replay import analyze as analyze_evidence_replay, format_text as format_ereplay_text, format_json as format_ereplay_json
from .anomaly_correlate import analyze as analyze_anomaly_correlate, format_text as format_acorr_text, format_json as format_acorr_json
from .policy_enforce import analyze as analyze_policy_enforce, format_text as format_penforce_text, format_json as format_penforce_json
from .signal_noise import analyze as analyze_signal_noise, format_text as format_signoise_text, format_json as format_signoise_json
from .social_engineering import analyze as analyze_social_eng, format_text as format_se_text, format_json as format_se_json, _load_events as _load_se_events
from .timing_attack import analyze as analyze_timing_attack, format_text as format_ta_text, format_json as format_ta_json, _load_events as _load_ta_events
from .resource_hijack import analyze as analyze_resource_hijack, format_text as format_rh_text, format_json as format_rh_json, _load_events as _load_rh_events
from .data_poisoning import analyze as analyze_data_poisoning, format_text as format_dp_text, format_json as format_dp_json, _load_events as _load_dp_events
from .model_extraction import analyze as analyze_model_extraction, format_text as format_me_text, format_json as format_me_json, _load_events as _load_me_events
from .denial_of_service import analyze as analyze_dos, format_text as format_dos_text, format_json as format_dos_json, _load_events as _load_dos_events
from .network_scan import analyze_network_scans, format_text as format_netscan_text, format_json as format_netscan_json, _load_events as _load_netscan_events
from .anti_forensics import analyze_anti_forensics, format_text as format_antifor_text, format_json as format_antifor_json, _load_events as _load_antifor_events
from .config_tamper import analyze_config_tamper, format_text as format_ct_text, format_json as format_ct_json, _load_events as _load_ct_events
from .model_theft import analyze_model_theft, format_text as format_mt_text, format_json as format_mt_json, _load_events as _load_mt_events
from .token_exfil import analyze_token_exfil, format_text as format_te_text, format_json as format_te_json, _load_events as _load_te_events
from .replay_attack import analyze_replay_attack, format_text as format_ra_text, format_json as format_ra_json, _load_events as _load_ra_events
from .model_poisoning import analyze_model_poisoning, format_text as format_mp_text, format_json as format_mp_json, _load_events as _load_mp_events
from .identity_spoof import analyze_identity_spoof, format_text as format_is_text, format_json as format_is_json, _load_events as _load_is_events
from .dns_tunnel import analyze_dns_tunneling, format_text as format_dnst_text, format_json as format_dnst_json, _load_events as _load_dnst_events
from .session_hijack import analyze_session_hijack, format_text as format_sh_text, format_json as format_sh_json, _load_events as _load_sh_events
from .log_forging import analyze_log_forging, format_text as format_lf_text, format_json as format_lf_json, _load_events as _load_lf_events
from .clock_manipulation import analyze_clock_manipulation, format_text as format_clk_text, format_json as format_clk_json, _load_events as _load_clk_events
from .env_manipulation import analyze_env_manipulation, format_text as format_em_text, format_json as format_em_json, _load_events as _load_em_events
from .shadow_api import analyze_shadow_apis, format_text as format_sapi_text, format_json as format_sapi_json, _load_events as _load_sapi_events
from .llm_jailbreak import analyze_jailbreaks, format_text as format_jb_text, format_json as format_jb_json, _load_events as _load_jb_events
from .api_key_leak import analyze_api_key_leaks, format_text as format_akl_text, format_json as format_akl_json, _load_events as _load_akl_events
from .container_escape import analyze_container_escapes, format_text as format_ce_text, format_json as format_ce_json, _load_events as _load_ce_events
from .auth_bypass import analyze_auth_bypass, format_text as format_ab_text, format_json as format_ab_json, _load_events as _load_ab_events
from .resource_leak import analyze_resource_leaks, format_text as format_rl_text, format_json as format_rl_json, _load_events as _load_rl_events
from .role_impersonation import analyze_role_impersonation, format_text as format_ri_text, format_json as format_ri_json, _load_events as _load_ri_events


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

    sr = subparsers.add_parser("session-replay", help="Reconstruct agent sessions from evidence into readable transcripts")
    sr.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    sr.add_argument("--agent", default=None, help="Filter to specific agent ID")
    sr.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    sr.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    intent = subparsers.add_parser("intent", help="Classify agent intent from action sequences")
    intent.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    intent.add_argument("--agent", default=None, help="Filter to specific agent ID")
    intent.add_argument("--min-confidence", type=float, default=0.5, help="Minimum signal confidence (default: 0.5)")
    intent.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    intent.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    dw = subparsers.add_parser("dwell-time", help="Measure incident dwell time with phase breakdown and benchmarks")
    dw.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    dw.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    dw.add_argument("--benchmark-detect-days", type=float, default=None, help="Benchmark days for time to detect")
    dw.add_argument("--benchmark-respond-days", type=float, default=None, help="Benchmark days for time to respond")
    dw.add_argument("--benchmark-total-days", type=float, default=None, help="Benchmark days for total duration")
    dw.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ap = subparsers.add_parser("access-pattern", help="Detect access pattern anomalies in agent behavior")
    ap.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    ap.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    ap.add_argument("--baseline-start", type=int, default=6, help="Baseline hours start (default: 6)")
    ap.add_argument("--baseline-end", type=int, default=22, help="Baseline hours end (default: 22)")
    ap.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ti = subparsers.add_parser("threat-intel", help="Enrich extracted IOCs against threat intelligence feeds")
    ti.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    ti.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    ti.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    sla_p = subparsers.add_parser("sla", help="Measure incident response times against SLA targets")
    sla_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    sla_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    sla_p.add_argument("--ack-minutes", type=float, default=None, help="SLA target for time to acknowledge (minutes)")
    sla_p.add_argument("--contain-minutes", type=float, default=None, help="SLA target for time to contain (minutes)")
    sla_p.add_argument("--resolve-minutes", type=float, default=None, help="SLA target for time to resolve (minutes)")
    sla_p.add_argument("--notify-minutes", type=float, default=None, help="SLA target for time to notify (minutes)")
    sla_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    eq = subparsers.add_parser("evidence-quality", help="Score evidence completeness, consistency, and coverage")
    eq.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    eq.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    eq.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    re = subparsers.add_parser("response-effectiveness", help="Measure incident response action effectiveness")
    re.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    re.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    re.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    coord_p = subparsers.add_parser("coordination", help="Analyze agent coordination patterns and handoffs")
    coord_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    coord_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    coord_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    gaps_p = subparsers.add_parser("evidence-gaps", help="Detect gaps in evidence timeline coverage")
    gaps_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    gaps_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    gaps_p.add_argument("--threshold", type=float, default=300.0, help="Gap threshold in seconds (default: 300)")
    gaps_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    tc_p = subparsers.add_parser("tactic-chain", help="Detect MITRE ATT&CK tactic progression chains in agent behavior")
    tc_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    tc_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    tc_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    rm_p = subparsers.add_parser("resource-map", help="Build resource access topology and detect concentration/contention")
    rm_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    rm_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    rm_p.add_argument("--concentration-threshold", type=int, default=5, help="Min unique resources for concentration alert (default: 5)")
    rm_p.add_argument("--contention-threshold", type=int, default=2, help="Min agents for contention alert (default: 2)")
    rm_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    exfil_p = subparsers.add_parser("exfil-detect", help="Detect data exfiltration patterns in agent behavior")
    exfil_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    exfil_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    exfil_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    c2_p = subparsers.add_parser("c2-detect", help="Detect command-and-control communication patterns")
    c2_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    c2_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    c2_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    persist_p = subparsers.add_parser("persistence-detect", help="Detect persistence mechanism establishment patterns")
    persist_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    persist_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    persist_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    evasion_p = subparsers.add_parser("defense-evasion", help="Detect defense evasion techniques mapped to MITRE ATT&CK")
    evasion_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    evasion_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    evasion_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    lateral_p = subparsers.add_parser("lateral-path", help="Reconstruct lateral movement paths between agents and hosts")
    lateral_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    lateral_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    lateral_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    harvest_p = subparsers.add_parser("credential-harvest", help="Detect credential harvesting patterns mapped to MITRE ATT&CK")
    harvest_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    harvest_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    harvest_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    abuse_p = subparsers.add_parser("tool-abuse", help="Detect tool misuse patterns and parameter injection")
    abuse_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    abuse_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    abuse_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    staging_p = subparsers.add_parser("data-staging", help="Detect data staging patterns in preparation for exfiltration")
    staging_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    staging_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    staging_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    privabuse_p = subparsers.add_parser("privilege-abuse", help="Detect privilege abuse patterns in agent behavior")
    privabuse_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    privabuse_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    privabuse_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    toolmisuse_p = subparsers.add_parser("tool-misuse", help="Classify tool misuse patterns and build agent tool profiles")
    toolmisuse_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    toolmisuse_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    toolmisuse_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    escape_p = subparsers.add_parser("sandbox-escape", help="Detect sandbox and container escape attempts")
    escape_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    escape_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    escape_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    sc_p = subparsers.add_parser("supply-chain", help="Detect supply chain attack patterns")
    sc_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    sc_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    sc_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    apiabuse_p = subparsers.add_parser("api-abuse", help="Detect API abuse patterns")
    apiabuse_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    apiabuse_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    apiabuse_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    memfor_p = subparsers.add_parser("memory-forensics", help="Detect context manipulation and memory tampering")
    memfor_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    memfor_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    memfor_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    cmdinject_p = subparsers.add_parser("command-inject", help="Detect command injection patterns in agent tool calls")
    cmdinject_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    cmdinject_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    cmdinject_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    fileaccess_p = subparsers.add_parser("file-access", help="Detect unauthorized file access patterns")
    fileaccess_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    fileaccess_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    fileaccess_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    promptinject_p = subparsers.add_parser("prompt-inject", help="Detect prompt injection attempts in agent inputs")
    promptinject_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    promptinject_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    promptinject_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ic_p = subparsers.add_parser("impact-chain", help="Trace cascading impact chains across agents")
    ic_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    ic_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    ic_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    sl_p = subparsers.add_parser("session-link", help="Detect cross-session event links and overlaps")
    sl_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    sl_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    sl_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    as_p = subparsers.add_parser("anomaly-score", help="Compute composite anomaly scores for agents")
    as_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    as_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    as_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    tb_p = subparsers.add_parser("trust-boundary", help="Detect trust boundary crossings between zones and privilege levels")
    tb_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    tb_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    tb_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    cm_p = subparsers.add_parser("capability-map", help="Map agent capabilities from observed tool and resource usage")
    cm_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    cm_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    cm_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    rd_p = subparsers.add_parser("role-drift", help="Detect agent role drift from declared vs. observed behavior")
    rd_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    rd_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    rd_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    rd_p.add_argument("--role-map", type=str, default=None, help="JSON file mapping agent_id to expected role")

    tm_p = subparsers.add_parser("threat-model", help="Build STRIDE threat model from agent incident evidence")
    tm_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    tm_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    tm_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ss_p = subparsers.add_parser("session-stats", help="Per-session summary statistics from agent evidence")
    ss_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    ss_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    ss_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    deception_p = subparsers.add_parser("deception-detect", help="Detect agent deception patterns in behavior evidence")
    deception_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    deception_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    deception_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    stego_p = subparsers.add_parser("steganography", help="Detect hidden communication channels in agent behavior")
    stego_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    stego_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    stego_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    cluster_p = subparsers.add_parser("behavior-cluster", help="Cluster agents by behavioral similarity")
    cluster_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    cluster_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    cluster_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    cluster_p.add_argument("--threshold", type=float, default=0.3, help="Similarity threshold for clustering (0-1)")

    goaldrift_p = subparsers.add_parser("goal-drift", help="Detect agent goal deviation and objective drift")
    goaldrift_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    goaldrift_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    goaldrift_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    goaldrift_p.add_argument("--window-size", type=int, default=10, help="Sliding window size for goal state analysis")

    tt_p = subparsers.add_parser("token-trace", help="Trace token usage patterns and detect anomalous consumption")
    tt_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    tt_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    tt_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    eg_p = subparsers.add_parser("event-graph", help="Build and analyze event dependency graphs")
    eg_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    eg_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    eg_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    cot_p = subparsers.add_parser("chain-of-thought", help="Analyze reasoning traces for anomalous thought patterns")
    cot_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    cot_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    cot_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    af_p = subparsers.add_parser("alert-fatigue", help="Detect redundant and duplicate alerts causing analyst fatigue")
    af_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    af_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    af_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    dt_p = subparsers.add_parser("decision-tree", help="Reconstruct agent decision paths and detect anomalous decisions")
    dt_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    dt_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    dt_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    la_p = subparsers.add_parser("log-anomaly", help="Detect anomalous patterns in agent log evidence")
    la_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    la_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    la_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ad_p = subparsers.add_parser("agent-drift", help="Detect behavioral drift in agent actions over time")
    ad_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    ad_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    ad_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    rt_p = subparsers.add_parser("response-time", help="Analyze incident response timing metrics")
    rt_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    rt_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    rt_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    rt_p.add_argument("--detection-types", nargs="*", default=None, help="Custom detection event types")

    as_p = subparsers.add_parser("action-sequence", help="Mine action sequence patterns from agent logs")
    as_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    as_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    as_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    as_p.add_argument("--min-frequency", type=int, default=2, help="Minimum pattern frequency")
    as_p.add_argument("--max-length", type=int, default=5, help="Maximum sequence length")

    ec_p = subparsers.add_parser("event-cluster", help="Cluster events by temporal proximity and detect campaigns")
    ec_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    ec_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    ec_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    ec_p.add_argument("--gap", type=float, default=60.0, help="Seconds gap to split clusters")
    ec_p.add_argument("--burst-min", type=int, default=5, help="Minimum events for burst detection")
    ec_p.add_argument("--burst-max", type=float, default=30.0, help="Maximum seconds for burst window")

    tch_p = subparsers.add_parser("tool-chain", help="Analyze tool invocation chains and detect suspicious sequences")
    tch_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    tch_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    tch_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    tch_p.add_argument("--chain-gap", type=float, default=120.0, help="Seconds gap to split chains")

    it_p = subparsers.add_parser("insider-threat", help="Detect insider threat patterns in agent behavior")
    it_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    it_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    it_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    er_p = subparsers.add_parser("exfil-rate", help="Analyze exfiltration transfer rates and detect anomalies")
    er_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    er_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    er_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    er_p.add_argument("--burst-threshold", type=int, default=10000, help="Bytes threshold for burst detection")
    er_p.add_argument("--window", type=int, default=300, help="Window size in seconds for burst detection")

    pc_p = subparsers.add_parser("privilege-chain", help="Reconstruct privilege escalation chains from agent evidence")
    pc_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    pc_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    pc_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ra_p = subparsers.add_parser("resource-abuse", help="Detect resource abuse patterns in agent behavior")
    ra_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    ra_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    ra_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    ra_p.add_argument("--api-threshold", type=int, default=10, help="API call count threshold for abuse detection")
    ra_p.add_argument("--window", type=float, default=60.0, help="Time window in seconds for rate detection")
    ra_p.add_argument("--storage-threshold", type=int, default=1000000, help="Storage threshold in bytes")
    ra_p.add_argument("--bandwidth-threshold", type=int, default=5000000, help="Bandwidth threshold in bytes")

    etg_p = subparsers.add_parser("event-timeline-gap", help="Detect suspicious gaps in event timelines")
    etg_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    etg_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    etg_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    etg_p.add_argument("--min-gap", type=float, default=300.0, help="Minimum gap duration in seconds")

    ah_p = subparsers.add_parser("agent-handoff", help="Analyze agent task handoff patterns and latencies")
    ah_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    ah_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    ah_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    ah_p.add_argument("--handoff-gap", type=float, default=5.0, help="Maximum gap between events to count as a handoff")

    creplay_p = subparsers.add_parser("credential-replay", help="Detect credential replay attacks in agent evidence")
    creplay_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    creplay_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    creplay_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    creplay_p.add_argument("--gap-threshold", type=float, default=3600.0, help="Temporal gap threshold in seconds")

    collusion_p = subparsers.add_parser("agent-collusion", help="Detect coordinated malicious behavior between agents")
    collusion_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    collusion_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    collusion_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    collusion_p.add_argument("--sync-window", type=float, default=5.0, help="Time window for synchronized action detection")
    collusion_p.add_argument("--escalation-window", type=float, default=120.0, help="Time window for coordinated escalation detection")

    ereplay_p = subparsers.add_parser("evidence-replay", help="Replay evidence events chronologically and score fidelity")
    ereplay_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    ereplay_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    ereplay_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    acorr_p = subparsers.add_parser("anomaly-correlate", help="Cross-detector anomaly correlation analysis")
    acorr_p.add_argument("evidence_dir", type=Path, help="Evidence directory to analyze")
    acorr_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    acorr_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")
    acorr_p.add_argument("--window", type=float, default=300.0, help="Time window in seconds for correlation (default: 300)")

    penforce_p = subparsers.add_parser("policy-enforce", help="Evaluate evidence events against configurable policy rules")
    penforce_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    penforce_p.add_argument("--policy", type=Path, required=True, help="Path to policy rules JSON file")
    penforce_p.add_argument("--format", choices=["text", "json"], default="text")
    penforce_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    signoise_p = subparsers.add_parser("signal-noise", help="Separate high-signal anomaly events from noise")
    signoise_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    signoise_p.add_argument("--format", choices=["text", "json"], default="text")
    signoise_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    se_p = subparsers.add_parser("social-engineering", help="Detect social engineering manipulation patterns")
    se_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    se_p.add_argument("--format", choices=["text", "json"], default="text")
    se_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ta_p = subparsers.add_parser("timing-attack", help="Detect timing-based attack patterns")
    ta_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    ta_p.add_argument("--format", choices=["text", "json"], default="text")
    ta_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    rh_p = subparsers.add_parser("resource-hijack", help="Detect resource hijacking patterns")
    rh_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    rh_p.add_argument("--format", choices=["text", "json"], default="text")
    rh_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    dp_p = subparsers.add_parser("data-poisoning", help="Detect data poisoning patterns")
    dp_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    dp_p.add_argument("--format", choices=["text", "json"], default="text")
    dp_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    me_p = subparsers.add_parser("model-extraction", help="Detect model extraction/stealing attempts")
    me_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    me_p.add_argument("--format", choices=["text", "json"], default="text")
    me_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    dos_p = subparsers.add_parser("denial-of-service", help="Detect denial of service patterns")
    dos_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    dos_p.add_argument("--format", choices=["text", "json"], default="text")
    dos_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    netscan_p = subparsers.add_parser("network-scan", help="Detect network scanning patterns")
    netscan_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    netscan_p.add_argument("--format", choices=["text", "json"], default="text")
    netscan_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    antifor_p = subparsers.add_parser("anti-forensics", help="Detect anti-forensics techniques")
    antifor_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    antifor_p.add_argument("--format", choices=["text", "json"], default="text")
    antifor_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ct_p = subparsers.add_parser("config-tamper", help="Detect configuration tampering patterns")
    ct_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    ct_p.add_argument("--format", choices=["text", "json"], default="text")
    ct_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    mt_p = subparsers.add_parser("model-theft", help="Detect model theft and IP exfiltration patterns")
    mt_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    mt_p.add_argument("--format", choices=["text", "json"], default="text")
    mt_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    te_p = subparsers.add_parser("token-exfil", help="Detect token and credential exfiltration patterns")
    te_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    te_p.add_argument("--format", choices=["text", "json"], default="text")
    te_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ra_p = subparsers.add_parser("replay-attack", help="Detect replay attack patterns")
    ra_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    ra_p.add_argument("--format", choices=["text", "json"], default="text")
    ra_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    mp_p = subparsers.add_parser("model-poisoning", help="Detect model poisoning and backdoor patterns")
    mp_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    mp_p.add_argument("--format", choices=["text", "json"], default="text")
    mp_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    is_p = subparsers.add_parser("identity-spoof", help="Detect agent identity spoofing patterns")
    is_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    is_p.add_argument("--format", choices=["text", "json"], default="text")
    is_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    dnst_p = subparsers.add_parser("dns-tunnel", help="Detect DNS tunneling patterns")
    dnst_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    dnst_p.add_argument("--format", choices=["text", "json"], default="text")
    dnst_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    sh_p = subparsers.add_parser("session-hijack", help="Detect session hijacking patterns")
    sh_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    sh_p.add_argument("--format", choices=["text", "json"], default="text")
    sh_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    lf_p = subparsers.add_parser("log-forging", help="Detect log injection and forging patterns")
    lf_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    lf_p.add_argument("--format", choices=["text", "json"], default="text")
    lf_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    clk_p = subparsers.add_parser("clock-manipulation", help="Detect timestamp and clock manipulation patterns")
    clk_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    clk_p.add_argument("--format", choices=["text", "json"], default="text")
    clk_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    em_p = subparsers.add_parser("env-manipulation", help="Detect environment variable manipulation patterns")
    em_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    em_p.add_argument("--format", choices=["text", "json"], default="text")
    em_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    sapi_p = subparsers.add_parser("shadow-api", help="Detect shadow/undocumented API access patterns")
    sapi_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    sapi_p.add_argument("--format", choices=["text", "json"], default="text")
    sapi_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    jb_p = subparsers.add_parser("llm-jailbreak", help="Detect LLM jailbreak and prompt injection bypass attempts")
    jb_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    jb_p.add_argument("--format", choices=["text", "json"], default="text")
    jb_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    akl_p = subparsers.add_parser("api-key-leak", help="Detect API key and secret leakage in agent outputs")
    akl_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    akl_p.add_argument("--format", choices=["text", "json"], default="text")
    akl_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ce_p = subparsers.add_parser("container-escape", help="Detect container/sandbox escape attempts")
    ce_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    ce_p.add_argument("--format", choices=["text", "json"], default="text")
    ce_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ab_p = subparsers.add_parser("auth-bypass", help="Detect authentication bypass patterns")
    ab_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    ab_p.add_argument("--format", choices=["text", "json"], default="text")
    ab_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    rl_p = subparsers.add_parser("resource-leak", help="Detect resource leak patterns (files, connections, locks, memory)")
    rl_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    rl_p.add_argument("--format", choices=["text", "json"], default="text")
    rl_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

    ri_p = subparsers.add_parser("role-impersonation", help="Detect agent role impersonation patterns")
    ri_p.add_argument("evidence_dir", type=Path, help="Evidence directory")
    ri_p.add_argument("--format", choices=["text", "json"], default="text")
    ri_p.add_argument("--output", type=Path, default=None, help="Write output to file instead of stdout")

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
    elif args.command == "session-replay":
        report = replay_sessions(args.evidence_dir, agent_id=args.agent)
        if args.format == "json":
            output = format_session_replay_json(report)
        else:
            output = format_session_replay_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Session replay written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "intent":
        report = classify_intents(
            args.evidence_dir, agent_id=args.agent,
            min_confidence=args.min_confidence,
        )
        if args.format == "json":
            output = format_intent_json(report)
        else:
            output = format_intent_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Intent classification written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "dwell-time":
        benchmarks = None
        if any(v is not None for v in [args.benchmark_detect_days, args.benchmark_respond_days, args.benchmark_total_days]):
            benchmarks = {}
            if args.benchmark_detect_days is not None:
                benchmarks["time_to_detect_days"] = args.benchmark_detect_days
            if args.benchmark_respond_days is not None:
                benchmarks["time_to_respond_days"] = args.benchmark_respond_days
            if args.benchmark_total_days is not None:
                benchmarks["total_duration_days"] = args.benchmark_total_days
        report = analyze_dwell_time(args.evidence_dir, benchmarks=benchmarks)
        if args.format == "json":
            output = format_dwell_json(report)
        else:
            output = format_dwell_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Dwell time analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "access-pattern":
        report = analyze_access_pattern(
            args.evidence_dir,
            baseline_hours=(args.baseline_start, args.baseline_end),
        )
        if args.format == "json":
            output = format_access_json(report)
        else:
            output = format_access_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Access pattern analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "threat-intel":
        report = analyze_threat_intel(args.evidence_dir)
        if args.format == "json":
            output = format_threat_json(report)
        else:
            output = format_threat_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Threat intel report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "sla":
        sla_targets = None
        if any(v is not None for v in [args.ack_minutes, args.contain_minutes, args.resolve_minutes, args.notify_minutes]):
            sla_targets = {}
            if args.ack_minutes is not None:
                sla_targets["time_to_acknowledge_minutes"] = args.ack_minutes
            if args.contain_minutes is not None:
                sla_targets["time_to_contain_minutes"] = args.contain_minutes
            if args.resolve_minutes is not None:
                sla_targets["time_to_resolve_minutes"] = args.resolve_minutes
            if args.notify_minutes is not None:
                sla_targets["time_to_notify_minutes"] = args.notify_minutes
        report = analyze_sla(args.evidence_dir, sla_targets=sla_targets)
        if args.format == "json":
            output = format_sla_json(report)
        else:
            output = format_sla_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"SLA report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "evidence-quality":
        report = analyze_evidence_quality(args.evidence_dir)
        if args.format == "json":
            output = format_eq_json(report)
        else:
            output = format_eq_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Evidence quality report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "response-effectiveness":
        report = analyze_response_effectiveness(args.evidence_dir)
        if args.format == "json":
            output = format_re_json(report)
        else:
            output = format_re_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Response effectiveness report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "coordination":
        report = analyze_coordination(args.evidence_dir)
        if args.format == "json":
            output = format_coord_json(report)
        else:
            output = format_coord_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Coordination report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "evidence-gaps":
        report = analyze_evidence_gaps(args.evidence_dir, gap_threshold_seconds=args.threshold)
        if args.format == "json":
            output = format_gaps_json(report)
        else:
            output = format_gaps_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Evidence gaps report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "tactic-chain":
        evidence_events = _load_tc_events(args.evidence_dir)
        report = analyze_tactic_chains(evidence_events)
        if args.format == "json":
            output = format_tc_json(report)
        else:
            output = format_tc_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Tactic chain report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "resource-map":
        evidence_events = _load_rm_events(args.evidence_dir)
        report = analyze_resource_map(
            evidence_events,
            concentration_threshold=args.concentration_threshold,
            contention_threshold=args.contention_threshold,
        )
        if args.format == "json":
            output = format_rm_json(report)
        else:
            output = format_rm_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Resource map report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "exfil-detect":
        evidence_events = _load_exfil_events(args.evidence_dir)
        report = analyze_exfiltration(evidence_events)
        if args.format == "json":
            output = format_exfil_json(report)
        else:
            output = format_exfil_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Exfiltration detection report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "c2-detect":
        evidence_events = _load_c2_events(args.evidence_dir)
        report = analyze_c2(evidence_events)
        if args.format == "json":
            output = format_c2_json(report)
        else:
            output = format_c2_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"C2 detection report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "persistence-detect":
        evidence_events = _load_persist_events(args.evidence_dir)
        report = analyze_persistence(evidence_events)
        if args.format == "json":
            output = format_persist_json(report)
        else:
            output = format_persist_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Persistence detection report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "defense-evasion":
        evidence_events = _load_evasion_events(args.evidence_dir)
        report = analyze_defense_evasion(evidence_events)
        if args.format == "json":
            output = format_evasion_json(report)
        else:
            output = format_evasion_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Defense evasion report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "lateral-path":
        evidence_events = _load_lateral_events(args.evidence_dir)
        report = analyze_lateral(evidence_events)
        if args.format == "json":
            output = format_lateral_json(report)
        else:
            output = format_lateral_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Lateral path report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "credential-harvest":
        evidence_events = _load_harvest_events(args.evidence_dir)
        report = analyze_harvest(evidence_events)
        if args.format == "json":
            output = format_harvest_json(report)
        else:
            output = format_harvest_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Credential harvest report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "tool-abuse":
        evidence_events = _load_abuse_events(args.evidence_dir)
        report = analyze_tool_abuse(evidence_events)
        if args.format == "json":
            output = format_abuse_json(report)
        else:
            output = format_abuse_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Tool abuse report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "data-staging":
        evidence_events = _load_staging_events(args.evidence_dir)
        report = analyze_staging(evidence_events)
        if args.format == "json":
            output = format_staging_json(report)
        else:
            output = format_staging_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Data staging report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "privilege-abuse":
        evidence_events = _load_privabuse_events(args.evidence_dir)
        report = analyze_privilege_abuse(evidence_events)
        if args.format == "json":
            output = format_privabuse_json(report)
        else:
            output = format_privabuse_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Privilege abuse report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "tool-misuse":
        evidence_events = _load_toolmisuse_events(args.evidence_dir)
        report = analyze_tool_misuse(evidence_events)
        if args.format == "json":
            output = format_toolmisuse_json(report)
        else:
            output = format_toolmisuse_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Tool misuse report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "sandbox-escape":
        evidence_events = _load_escape_events(args.evidence_dir)
        report = analyze_sandbox_escape(evidence_events)
        if args.format == "json":
            output = format_escape_json(report)
        else:
            output = format_escape_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Sandbox escape report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "supply-chain":
        evidence_events = _load_sc_events(args.evidence_dir)
        report = analyze_supply_chain(evidence_events)
        if args.format == "json":
            output = format_sc_json(report)
        else:
            output = format_sc_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Supply chain report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "api-abuse":
        evidence_events = _load_apiabuse_events(args.evidence_dir)
        report = analyze_api_abuse(evidence_events)
        if args.format == "json":
            output = format_apiabuse_json(report)
        else:
            output = format_apiabuse_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"API abuse report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "memory-forensics":
        evidence_events = _load_memfor_events(args.evidence_dir)
        report = analyze_memory_forensics(evidence_events)
        if args.format == "json":
            output = format_memfor_json(report)
        else:
            output = format_memfor_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Memory forensics report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "command-inject":
        evidence_events = _load_cmdinject_events(args.evidence_dir)
        report = analyze_command_inject(evidence_events)
        if args.format == "json":
            output = format_cmdinject_json(report)
        else:
            output = format_cmdinject_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Command injection report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "file-access":
        evidence_events = _load_fileaccess_events(args.evidence_dir)
        report = analyze_file_access(evidence_events)
        if args.format == "json":
            output = format_fileaccess_json(report)
        else:
            output = format_fileaccess_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"File access report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "prompt-inject":
        evidence_events = _load_promptinject_events(args.evidence_dir)
        report = analyze_prompt_inject(evidence_events)
        if args.format == "json":
            output = format_promptinject_json(report)
        else:
            output = format_promptinject_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Prompt injection report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "impact-chain":
        evidence_events = _load_ic_events(args.evidence_dir)
        report = analyze_impact_chains(evidence_events)
        if args.format == "json":
            output = format_ic_json(report)
        else:
            output = format_ic_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Impact chain report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "session-link":
        evidence_events = _load_sl_events(args.evidence_dir)
        report = analyze_session_links(evidence_events)
        if args.format == "json":
            output = format_sl_json(report)
        else:
            output = format_sl_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Session link report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "anomaly-score":
        evidence_events = _load_as_events(args.evidence_dir)
        report = score_anomalies(evidence_events)
        if args.format == "json":
            output = format_as_json(report)
        else:
            output = format_as_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Anomaly score report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "trust-boundary":
        evidence_events = _load_tb_events(args.evidence_dir)
        report = analyze_trust_boundaries(evidence_events)
        if args.format == "json":
            output = format_tb_json(report)
        else:
            output = format_tb_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Trust boundary report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "capability-map":
        events = _load_cm_events(str(args.evidence_dir))
        report = analyze_capability_map(events)
        if args.format == "json":
            output = format_cm_json(report)
        else:
            output = format_cm_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Capability map written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "role-drift":
        events = _load_rd_events(str(args.evidence_dir))
        role_map = None
        if args.role_map:
            import json as _json
            role_map = _json.loads(Path(args.role_map).read_text())
        report = analyze_role_drift(events, role_map=role_map)
        if args.format == "json":
            output = format_rd_json(report)
        else:
            output = format_rd_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Role drift analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "threat-model":
        report = analyze_threat_model(args.evidence_dir)
        if args.format == "json":
            output = format_tm_json(report)
        else:
            output = format_tm_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Threat model report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "session-stats":
        report = analyze_session_stats(args.evidence_dir)
        if args.format == "json":
            output = format_ss_json(report)
        else:
            output = format_ss_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Session stats written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "deception-detect":
        events = _load_deception_events(args.evidence_dir)
        report = analyze_deception(events)
        if args.format == "json":
            output = format_deception_json(report)
        else:
            output = format_deception_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Deception detection report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "steganography":
        events = _load_stego_events(args.evidence_dir)
        report = analyze_steganography(events)
        if args.format == "json":
            output = format_stego_json(report)
        else:
            output = format_stego_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Steganography detection written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "behavior-cluster":
        events = _load_cluster_events(args.evidence_dir)
        report = analyze_behavior_clusters(events, similarity_threshold=args.threshold)
        if args.format == "json":
            output = format_cluster_json(report)
        else:
            output = format_cluster_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Behavior clustering written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "goal-drift":
        events = _load_goaldrift_events(args.evidence_dir)
        report = analyze_goal_drift(events, window_size=args.window_size)
        if args.format == "json":
            output = format_goaldrift_json(report)
        else:
            output = format_goaldrift_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Goal drift analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "token-trace":
        events = _load_tt_events(args.evidence_dir)
        report = analyze_token_trace(events)
        if args.format == "json":
            output = format_tt_json(report)
        else:
            output = format_tt_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Token trace written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "event-graph":
        events = _load_eg_events(args.evidence_dir)
        report = analyze_event_graph(events)
        if args.format == "json":
            output = format_eg_json(report)
        else:
            output = format_eg_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Event graph written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "chain-of-thought":
        events = _load_cot_events(args.evidence_dir)
        report = analyze_chain_of_thought(events)
        if args.format == "json":
            output = format_cot_json(report)
        else:
            output = format_cot_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Chain-of-thought analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "alert-fatigue":
        events = _load_af_events(args.evidence_dir)
        report = analyze_alert_fatigue(events)
        if args.format == "json":
            output = format_af_json(report)
        else:
            output = format_af_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Alert fatigue analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "decision-tree":
        events = _load_dt_events(args.evidence_dir)
        report = analyze_decision_tree(events)
        if args.format == "json":
            output = format_dt_json(report)
        else:
            output = format_dt_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Decision tree analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "log-anomaly":
        events, control = _load_la_events(args.evidence_dir)
        report = analyze_log_anomalies(events, control)
        if args.format == "json":
            output = format_la_json(report)
        else:
            output = format_la_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Log anomaly analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "agent-drift":
        events, control = _load_ad_events(args.evidence_dir)
        report = analyze_agent_drift(events, control)
        if args.format == "json":
            output = format_ad_json(report)
        else:
            output = format_ad_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Agent drift analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "response-time":
        events = _load_rt_events(args.evidence_dir)
        report = analyze_response_times(events, detection_types=args.detection_types)
        if args.format == "json":
            output = format_rt_json(report)
        else:
            output = format_rt_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Response time analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "action-sequence":
        events = _load_rt_events(args.evidence_dir)
        report = analyze_action_sequences(events, min_frequency=args.min_frequency, max_sequence_length=args.max_length)
        if args.format == "json":
            output = format_as_json(report)
        else:
            output = format_as_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Action sequence analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "event-cluster":
        events = _load_ec_events(args.evidence_dir)
        report = analyze_event_clusters(events, gap_threshold_seconds=args.gap, burst_min_events=args.burst_min, burst_max_seconds=args.burst_max)
        if args.format == "json":
            output = format_ec_json(report)
        else:
            output = format_ec_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Event cluster analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "tool-chain":
        events = _load_tch_events(args.evidence_dir)
        report = analyze_tool_chains(events, chain_gap_seconds=args.chain_gap)
        if args.format == "json":
            output = format_tch_json(report)
        else:
            output = format_tch_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Tool chain analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "insider-threat":
        events, control = _load_it_events(args.evidence_dir)
        report = analyze_insider_threat(events, control)
        if args.format == "json":
            output = format_it_json(report)
        else:
            output = format_it_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Insider threat analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "exfil-rate":
        events = _load_er_events(args.evidence_dir)
        report = analyze_exfil_rates(events, burst_threshold=args.burst_threshold, window_seconds=args.window)
        if args.format == "json":
            output = format_er_json(report)
        else:
            output = format_er_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Exfiltration rate analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "privilege-chain":
        events, control = _load_pc_events(args.evidence_dir)
        report = analyze_privilege_chain(events, control)
        if args.format == "json":
            output = format_pc_json(report)
        else:
            output = format_pc_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Privilege chain analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "event-timeline-gap":
        events = _load_etg_events(args.evidence_dir)
        report = analyze_timeline_gaps(events, min_gap_seconds=args.min_gap)
        if args.format == "json":
            output = format_etg_json(report)
        else:
            output = format_etg_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Timeline gap analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "agent-handoff":
        events = _load_ah_events(args.evidence_dir)
        report = analyze_handoffs(events, handoff_gap_seconds=args.handoff_gap)
        if args.format == "json":
            output = format_ah_json(report)
        else:
            output = format_ah_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Agent handoff analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "credential-replay":
        events, control = _load_creplay_events(args.evidence_dir)
        report = analyze_credential_replay(events, control, gap_threshold=args.gap_threshold)
        if args.format == "json":
            output = format_creplay_json(report)
        else:
            output = format_creplay_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Credential replay analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "agent-collusion":
        events, control = _load_collusion_events(args.evidence_dir)
        report = analyze_agent_collusion(events, control,
                                          sync_window=args.sync_window,
                                          escalation_window=args.escalation_window)
        if args.format == "json":
            output = format_collusion_json(report)
        else:
            output = format_collusion_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Agent collusion analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "resource-abuse":
        events, control = _load_ra_events(args.evidence_dir)
        report = analyze_resource_abuse(events, control,
                                         api_threshold=args.api_threshold,
                                         window_seconds=args.window,
                                         storage_threshold=args.storage_threshold,
                                         bandwidth_threshold=args.bandwidth_threshold)
        if args.format == "json":
            output = format_ra_json(report)
        else:
            output = format_ra_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Resource abuse analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "evidence-replay":
        report = analyze_evidence_replay(args.evidence_dir)
        if args.format == "json":
            output = format_ereplay_json(report)
        else:
            output = format_ereplay_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Evidence replay analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "anomaly-correlate":
        report = analyze_anomaly_correlate(args.evidence_dir, window_seconds=args.window)
        if args.format == "json":
            output = format_acorr_json(report)
        else:
            output = format_acorr_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Anomaly correlation analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "policy-enforce":
        report = analyze_policy_enforce(args.evidence_dir, args.policy)
        if args.format == "json":
            output = format_penforce_json(report)
        else:
            output = format_penforce_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Policy enforcement report written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "signal-noise":
        report = analyze_signal_noise(args.evidence_dir)
        if args.format == "json":
            output = format_signoise_json(report)
        else:
            output = format_signoise_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Signal-noise analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "social-engineering":
        events = _load_se_events(args.evidence_dir / "transcripts.jsonl")
        control = _load_se_events(args.evidence_dir / "control_plane.jsonl")
        report = analyze_social_eng(events, control)
        if args.format == "json":
            output = format_se_json(report)
        else:
            output = format_se_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Social engineering analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "timing-attack":
        events = _load_ta_events(args.evidence_dir / "transcripts.jsonl")
        control = _load_ta_events(args.evidence_dir / "control_plane.jsonl")
        report = analyze_timing_attack(events, control)
        if args.format == "json":
            output = format_ta_json(report)
        else:
            output = format_ta_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Timing attack analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "resource-hijack":
        events = _load_rh_events(args.evidence_dir / "transcripts.jsonl")
        control = _load_rh_events(args.evidence_dir / "control_plane.jsonl")
        report = analyze_resource_hijack(events, control)
        if args.format == "json":
            output = format_rh_json(report)
        else:
            output = format_rh_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Resource hijack analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "data-poisoning":
        events = _load_dp_events(args.evidence_dir / "transcripts.jsonl")
        control = _load_dp_events(args.evidence_dir / "control_plane.jsonl")
        report = analyze_data_poisoning(events, control)
        if args.format == "json":
            output = format_dp_json(report)
        else:
            output = format_dp_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Data poisoning analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "model-extraction":
        events = _load_me_events(str(args.evidence_dir))
        report = analyze_model_extraction(events)
        if args.format == "json":
            output = format_me_json(report)
        else:
            output = format_me_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Model extraction analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "denial-of-service":
        events = _load_dos_events(str(args.evidence_dir))
        report = analyze_dos(events)
        if args.format == "json":
            output = format_dos_json(report)
        else:
            output = format_dos_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Denial of service analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "network-scan":
        events = _load_netscan_events(str(args.evidence_dir))
        report = analyze_network_scans(events)
        if args.format == "json":
            output = format_netscan_json(report)
        else:
            output = format_netscan_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Network scan analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "anti-forensics":
        events = _load_antifor_events(str(args.evidence_dir))
        report = analyze_anti_forensics(events)
        if args.format == "json":
            output = format_antifor_json(report)
        else:
            output = format_antifor_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Anti-forensics analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "config-tamper":
        events = _load_ct_events(str(args.evidence_dir))
        report = analyze_config_tamper(events)
        if args.format == "json":
            output = format_ct_json(report)
        else:
            output = format_ct_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Config tamper analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "model-theft":
        events = _load_mt_events(str(args.evidence_dir))
        report = analyze_model_theft(events)
        if args.format == "json":
            output = format_mt_json(report)
        else:
            output = format_mt_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Model theft analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "token-exfil":
        events = _load_te_events(str(args.evidence_dir))
        report = analyze_token_exfil(events)
        if args.format == "json":
            output = format_te_json(report)
        else:
            output = format_te_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Token exfil analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "replay-attack":
        events = _load_ra_events(str(args.evidence_dir))
        report = analyze_replay_attack(events)
        if args.format == "json":
            output = format_ra_json(report)
        else:
            output = format_ra_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Replay attack analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "model-poisoning":
        report = analyze_model_poisoning(args.evidence_dir)
        if args.format == "json":
            output = format_mp_json(report)
        else:
            output = format_mp_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Model poisoning analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "identity-spoof":
        report = analyze_identity_spoof(args.evidence_dir)
        if args.format == "json":
            output = format_is_json(report)
        else:
            output = format_is_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Identity spoof analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "dns-tunnel":
        events = _load_dnst_events(str(args.evidence_dir))
        report = analyze_dns_tunneling(events)
        if args.format == "json":
            output = format_dnst_json(report)
        else:
            output = format_dnst_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"DNS tunnel analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "session-hijack":
        events = _load_sh_events(str(args.evidence_dir))
        report = analyze_session_hijack(events)
        if args.format == "json":
            output = format_sh_json(report)
        else:
            output = format_sh_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Session hijack analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "log-forging":
        report = analyze_log_forging(args.evidence_dir)
        if args.format == "json":
            output = format_lf_json(report)
        else:
            output = format_lf_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Log forging analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "clock-manipulation":
        report = analyze_clock_manipulation(args.evidence_dir)
        if args.format == "json":
            output = format_clk_json(report)
        else:
            output = format_clk_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Clock manipulation analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "env-manipulation":
        events = _load_em_events(str(args.evidence_dir))
        report = analyze_env_manipulation(events)
        if args.format == "json":
            output = format_em_json(report)
        else:
            output = format_em_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Environment manipulation analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "shadow-api":
        events = _load_sapi_events(str(args.evidence_dir))
        report = analyze_shadow_apis(events)
        if args.format == "json":
            output = format_sapi_json(report)
        else:
            output = format_sapi_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Shadow API analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "llm-jailbreak":
        events = _load_jb_events(str(args.evidence_dir))
        report = analyze_jailbreaks(events)
        if args.format == "json":
            output = format_jb_json(report)
        else:
            output = format_jb_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"LLM jailbreak analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "api-key-leak":
        events = _load_akl_events(str(args.evidence_dir))
        report = analyze_api_key_leaks(events)
        if args.format == "json":
            output = format_akl_json(report)
        else:
            output = format_akl_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"API key leak analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "container-escape":
        events = _load_ce_events(str(args.evidence_dir))
        report = analyze_container_escapes(events)
        if args.format == "json":
            output = format_ce_json(report)
        else:
            output = format_ce_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Container escape analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "auth-bypass":
        events = _load_ab_events(str(args.evidence_dir))
        report = analyze_auth_bypass(events)
        if args.format == "json":
            output = format_ab_json(report)
        else:
            output = format_ab_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Authentication bypass analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "resource-leak":
        events = _load_rl_events(str(args.evidence_dir))
        report = analyze_resource_leaks(events)
        if args.format == "json":
            output = format_rl_json(report)
        else:
            output = format_rl_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Resource leak analysis written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return
    elif args.command == "role-impersonation":
        events = _load_ri_events(str(args.evidence_dir))
        report = analyze_role_impersonation(events)
        if args.format == "json":
            output = format_ri_json(report)
        else:
            output = format_ri_text(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"Role impersonation analysis written to {args.output}", file=sys.stderr)
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
