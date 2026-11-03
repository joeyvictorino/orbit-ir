"""DNS tunneling detection module for orbit-ir."""

CATEGORIES = {
    "dns_exfil": {
        "description": "DNS-based data exfiltration via encoded subdomains",
        "indicators": [
            "high_entropy_subdomain",
            "unusually_long_dns_query",
            "base64_encoded_subdomain",
            "hex_encoded_subdomain",
            "excessive_txt_record_queries",
            "dns_query_to_known_tunnel_domain",
            "rapid_sequential_dns_lookups",
            "subdomain_length_exceeds_threshold",
            "non_standard_dns_record_type",
            "dns_response_with_encoded_payload",
        ],
    },
    "dns_c2": {
        "description": "Command and control communication over DNS",
        "indicators": [
            "periodic_dns_beacon",
            "dns_txt_record_command_response",
            "alternating_query_response_pattern",
            "dns_query_with_encoded_instruction",
            "consistent_interval_dns_polling",
            "dns_response_payload_variation",
            "dns_cname_chain_redirection",
            "dns_mx_record_abuse",
            "query_to_dynamic_dns_provider",
            "dns_ns_record_delegation_abuse",
        ],
    },
    "dns_rebinding": {
        "description": "DNS rebinding attacks to bypass same-origin policy",
        "indicators": [
            "rapid_dns_ttl_change",
            "dns_response_ip_oscillation",
            "short_ttl_followed_by_internal_ip",
            "dns_resolution_to_private_range",
            "multiple_a_records_with_mixed_scope",
            "ttl_zero_dns_response",
            "dns_rebind_to_localhost",
            "rapid_ip_change_for_same_domain",
            "dns_response_with_rfc1918_address",
            "alternating_public_private_resolution",
        ],
    },
    "dns_amplification": {
        "description": "DNS amplification and reflection attacks",
        "indicators": [
            "large_dns_response_to_small_query",
            "any_query_type_abuse",
            "open_resolver_exploitation",
            "spoofed_source_dns_query",
            "amplification_ratio_exceeded",
            "dns_response_size_anomaly",
            "recursive_query_from_external",
            "edns0_buffer_size_abuse",
            "dns_reflection_pattern",
            "high_volume_dns_to_single_target",
        ],
    },
    "dns_hijack": {
        "description": "DNS hijacking and poisoning attempts",
        "indicators": [
            "unexpected_dns_response_source",
            "dns_response_mismatch",
            "cache_poisoning_attempt",
            "dns_id_prediction_pattern",
            "kaminsky_attack_pattern",
            "glue_record_injection",
            "dns_response_from_non_resolver",
            "dnssec_validation_failure",
            "phantom_domain_attack",
            "nxdomain_hijacking",
        ],
    },
    "dns_covert_channel": {
        "description": "Covert communication channels using DNS protocol",
        "indicators": [
            "steganographic_dns_payload",
            "dns_query_timing_pattern",
            "iodine_tunnel_signature",
            "dnscat2_protocol_signature",
            "dns2tcp_tunnel_pattern",
            "custom_dns_protocol_encoding",
            "dns_over_icmp_encapsulation",
            "null_byte_padding_in_dns",
            "fragmented_dns_message_chain",
            "dns_label_encoding_anomaly",
        ],
    },
}


def classify_event(event):
    """Classify a single event against DNS tunneling indicators."""
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
    """Analyze a list of events for DNS tunneling patterns."""
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
        "module": "dns_tunneling",
        "total_indicators": total,
        "severity": _severity(total),
        "category_counts": category_counts,
        "flagged_events": event_results,
    }


def format_report(results):
    """Format analysis results as human-readable text."""
    lines = [
        "DNS Tunneling Detection Report",
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
