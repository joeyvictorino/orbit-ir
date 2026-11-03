"""Statistical anomaly detection module for agent incident reconstruction."""

import json
import math


def _mean(values):
    if not values:
        return 0.0
    return sum(values) / len(values)


def _stddev(values):
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    variance = sum((x - m) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)


def _z_score(value, mean, stddev):
    if stddev == 0:
        return 0.0
    return abs(value - mean) / stddev


def _extract_numeric(event):
    if isinstance(event, (int, float)):
        return {"value": float(event)}
    if isinstance(event, str):
        return {}
    if not isinstance(event, dict):
        return {}

    numerics = {}
    for k, v in event.items():
        if isinstance(v, (int, float)):
            numerics[k] = float(v)
    return numerics


def _extract_category(event):
    if isinstance(event, str):
        return event.strip().lower()[:50] if event.strip() else None
    if isinstance(event, dict):
        for key in ("category", "type", "event_type", "action", "kind"):
            val = event.get(key)
            if val and isinstance(val, str):
                return val.strip().lower()
    return None


def compute_baseline(events):
    numeric_values = {}
    category_counts = {}
    timestamps = []

    for event in events:
        if event is None:
            continue

        nums = _extract_numeric(event)
        for k, v in nums.items():
            numeric_values.setdefault(k, []).append(v)

        cat = _extract_category(event)
        if cat:
            category_counts[cat] = category_counts.get(cat, 0) + 1

        if isinstance(event, dict):
            ts = event.get("timestamp") or event.get("time") or event.get("ts")
            if isinstance(ts, (int, float)):
                timestamps.append(float(ts))

    numeric_stats = {}
    for k, vals in numeric_values.items():
        numeric_stats[k] = {"mean": _mean(vals), "stddev": _stddev(vals), "count": len(vals)}

    cat_values = list(category_counts.values())
    cat_stats = {
        "counts": category_counts,
        "mean_freq": _mean(cat_values) if cat_values else 0.0,
        "stddev_freq": _stddev(cat_values) if cat_values else 0.0,
    }

    timing_stats = {}
    if len(timestamps) >= 2:
        timestamps.sort()
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        timing_stats = {
            "mean_interval": _mean(intervals),
            "stddev_interval": _stddev(intervals),
            "count": len(intervals),
        }

    return {
        "numeric": numeric_stats,
        "categories": cat_stats,
        "timing": timing_stats,
        "total_events": len(events),
    }


def detect_anomalies(events, baseline=None, z_threshold=2.0):
    if baseline is None:
        baseline = compute_baseline(events)

    anomalies = []
    numeric_stats = baseline.get("numeric", {})
    cat_stats = baseline.get("categories", {})
    timing_stats = baseline.get("timing", {})

    prev_ts = None

    for i, event in enumerate(events):
        if event is None:
            continue

        reasons = []

        nums = _extract_numeric(event)
        for k, v in nums.items():
            if k in numeric_stats:
                s = numeric_stats[k]
                z = _z_score(v, s["mean"], s["stddev"])
                if z > z_threshold:
                    reasons.append(f"numeric '{k}' z={z:.2f} (value={v}, mean={s['mean']:.2f}, std={s['stddev']:.2f})")

        cat = _extract_category(event)
        if cat and cat_stats.get("counts"):
            freq = cat_stats["counts"].get(cat, 0)
            z = _z_score(freq, cat_stats["mean_freq"], cat_stats["stddev_freq"])
            if z > z_threshold:
                reasons.append(f"category '{cat}' freq={freq} z={z:.2f}")

        if isinstance(event, dict) and timing_stats:
            ts = event.get("timestamp") or event.get("time") or event.get("ts")
            if isinstance(ts, (int, float)):
                ts = float(ts)
                if prev_ts is not None:
                    interval = ts - prev_ts
                    z = _z_score(interval, timing_stats["mean_interval"], timing_stats["stddev_interval"])
                    if z > z_threshold:
                        reasons.append(f"timing interval={interval:.2f}s z={z:.2f}")
                prev_ts = ts

        if reasons:
            anomalies.append({"index": i, "event": event, "reasons": reasons})

    severity = "none"
    if len(anomalies) > 10:
        severity = "critical"
    elif len(anomalies) > 5:
        severity = "high"
    elif len(anomalies) > 0:
        severity = "medium"

    return {
        "total_events": len(events),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "severity": severity,
        "z_threshold": z_threshold,
        "baseline_summary": {
            "numeric_fields": list(baseline.get("numeric", {}).keys()),
            "categories_tracked": len(baseline.get("categories", {}).get("counts", {})),
            "has_timing": bool(baseline.get("timing")),
        },
    }


def format_report(result):
    lines = [
        "Statistical Anomaly Detection Report",
        "=" * 40,
        "",
        f"  Total events:      {result['total_events']}",
        f"  Anomalies found:   {result['anomaly_count']}",
        f"  Severity:          {result['severity']}",
        f"  Z-score threshold: {result['z_threshold']}",
        "",
    ]

    bs = result.get("baseline_summary", {})
    if bs:
        lines.append("  Baseline:")
        lines.append(f"    Numeric fields:    {', '.join(bs.get('numeric_fields', [])) or 'none'}")
        lines.append(f"    Categories tracked: {bs.get('categories_tracked', 0)}")
        lines.append(f"    Timing data:       {'yes' if bs.get('has_timing') else 'no'}")
        lines.append("")

    shown = result["anomalies"][:10]
    if shown:
        lines.append("  Anomalies:")
        for entry in shown:
            evt = str(entry["event"])[:60]
            lines.append(f"    [{entry['index']}] {evt}")
            for reason in entry["reasons"]:
                lines.append(f"         -> {reason}")
    if result["anomaly_count"] > 10:
        lines.append(f"    ... and {result['anomaly_count'] - 10} more")
    lines.append("")
    return "\n".join(lines)


def load_events(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "events" in data:
            return data["events"]
        return [data]
    return [data]
