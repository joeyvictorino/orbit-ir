"""Crypto mining detection module for orbit-ir."""

CATEGORIES = {
    "cryptojack_process": {
        "description": "Unauthorized cryptocurrency mining process execution",
        "indicators": [
            "xmrig_binary_execution",
            "stratum_protocol_connection",
            "mining_pool_communication",
            "cpu_intensive_unknown_process",
            "gpu_utilization_spike",
            "coinhive_script_injection",
            "minerd_process_detected",
            "cryptonight_algorithm_usage",
            "ethash_computation_pattern",
            "equihash_solver_activity",
        ],
    },
    "resource_abuse": {
        "description": "System resource abuse indicative of mining",
        "indicators": [
            "sustained_high_cpu_usage",
            "abnormal_gpu_memory_allocation",
            "power_consumption_anomaly",
            "thermal_throttling_event",
            "fan_speed_maximum_sustained",
            "memory_pressure_from_hashing",
            "disk_io_for_dag_generation",
            "network_bandwidth_to_pool",
            "container_resource_limit_breach",
            "cgroup_cpu_quota_exhaustion",
        ],
    },
    "pool_connection": {
        "description": "Connection to known mining pool infrastructure",
        "indicators": [
            "stratum_tcp_handshake",
            "mining_pool_domain_resolution",
            "json_rpc_mining_method",
            "pool_authentication_exchange",
            "share_submission_pattern",
            "difficulty_adjustment_message",
            "nonce_range_distribution",
            "getwork_protocol_usage",
            "pool_keepalive_heartbeat",
            "hashrate_reporting_message",
        ],
    },
    "browser_mining": {
        "description": "In-browser cryptocurrency mining via WebAssembly or JavaScript",
        "indicators": [
            "coinhive_js_inclusion",
            "cryptoloot_script_detected",
            "webassembly_mining_module",
            "web_worker_hash_computation",
            "websocket_to_mining_proxy",
            "service_worker_mining_loop",
            "wasm_cryptonight_instantiation",
            "shared_array_buffer_mining",
            "javascript_sha256_loop",
            "iframe_hidden_miner_embed",
        ],
    },
    "evasion_technique": {
        "description": "Mining evasion and stealth techniques",
        "indicators": [
            "process_name_masquerading",
            "cpu_throttle_on_user_activity",
            "mining_pause_on_task_manager",
            "rootkit_hidden_miner_process",
            "library_injection_for_mining",
            "fileless_mining_via_powershell",
            "scheduled_task_miner_persistence",
            "docker_container_hidden_miner",
            "cron_job_mining_schedule",
            "memory_only_mining_payload",
        ],
    },
    "wallet_activity": {
        "description": "Cryptocurrency wallet and transaction indicators",
        "indicators": [
            "wallet_address_in_config",
            "monero_address_pattern",
            "bitcoin_address_pattern",
            "ethereum_address_pattern",
            "wallet_balance_check_api",
            "transaction_broadcast_attempt",
            "mining_payout_threshold",
            "multi_wallet_rotation",
            "wallet_address_in_environment",
            "hardcoded_pool_credentials",
        ],
    },
}


def classify_event(event):
    """Classify a single event against crypto mining indicators."""
    results = {}
    desc = (event.get("description", "") + " " + event.get("raw", "")).lower()
    for category, info in CATEGORIES.items():
        matched = []
        for indicator in info["indicators"]:
            tokens = indicator.replace("_", " ")
            words = tokens.split()
            if len(words) >= 2 and all(w in desc for w in words):
                matched.append(indicator)
        if matched:
            results[category] = {
                "matched_indicators": matched,
                "count": len(matched),
                "description": info["description"],
            }
    return results


def _severity(count):
    if count > 10:
        return "critical"
    if count > 5:
        return "high"
    if count > 0:
        return "medium"
    return "none"


def analyze(events):
    """Analyze a list of events for crypto mining patterns."""
    category_counts = {c: 0 for c in CATEGORIES}
    event_results = []
    for ev in events:
        cl = classify_event(ev)
        if cl:
            event_results.append({"event": ev, "classifications": cl})
            for cat in cl:
                category_counts[cat] += cl[cat]["count"]
    total = sum(category_counts.values())
    return {
        "module": "crypto_mining",
        "total_indicators": total,
        "severity": _severity(total),
        "category_counts": category_counts,
        "flagged_events": event_results,
    }


def format_report(results):
    """Format analysis results as human-readable text."""
    lines = [
        "Crypto Mining Detection Report",
        "=" * 40,
        f"Severity: {results['severity']}",
        f"Total indicators: {results['total_indicators']}",
        "",
        "Category breakdown:",
    ]
    for cat, count in results["category_counts"].items():
        if count > 0:
            lines.append(f"  {cat}: {count}")
    lines.append("")
    lines.append(f"Flagged events: {len(results['flagged_events'])}")
    for fe in results["flagged_events"]:
        eid = fe["event"].get("id", "unknown")
        cats = ", ".join(fe["classifications"].keys())
        lines.append(f"  [{eid}] {cats}")
    return "\n".join(lines)


def load_events(path):
    """Load events from a JSON file."""
    import json

    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return data.get("events", [])
