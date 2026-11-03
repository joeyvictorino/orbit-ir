"""Deepfake and synthetic media detection in agent communications."""

import json
from pathlib import Path

CATEGORIES = {
    "voice_synthesis": [
        "voice clone",
        "speech synthesis",
        "voice deepfake",
        "audio manipulation",
        "voice generation",
        "text to speech attack",
        "voice impersonation",
    ],
    "image_manipulation": [
        "face swap",
        "image synthesis",
        "gan generated",
        "deepfake image",
        "synthetic face",
        "face generation",
        "image forgery",
    ],
    "video_deepfake": [
        "video manipulation",
        "face reenactment",
        "deepfake video",
        "synthetic video",
        "lip sync manipulation",
        "video forgery",
        "motion transfer",
    ],
    "text_generation": [
        "ai generated text",
        "synthetic content",
        "automated writing",
        "bot-generated",
        "machine-written",
        "llm generated",
        "auto-generated message",
    ],
    "identity_impersonation": [
        "identity theft",
        "impersonation attack",
        "synthetic identity",
        "fake profile",
        "social engineering deepfake",
        "credential fabrication",
        "persona cloning",
    ],
}


def classify_event(event: dict) -> list[str]:
    text = json.dumps(event).lower()
    return [cat for cat, patterns in CATEGORIES.items()
            if any(p in text for p in patterns)]


def analyze(events: list[dict]) -> dict:
    categories: dict = {}
    flagged = 0
    for ev in events:
        cats = classify_event(ev)
        if cats:
            flagged += 1
        for c in cats:
            categories.setdefault(c, {"count": 0, "events": []})
            categories[c]["count"] += 1
            categories[c]["events"].append(ev)
    risk = "low"
    if flagged > len(events) * 0.5:
        risk = "critical"
    elif flagged > len(events) * 0.3:
        risk = "high"
    elif flagged > len(events) * 0.1:
        risk = "medium"
    return {
        "categories": categories,
        "summary": {
            "total_events": len(events),
            "flagged_events": flagged,
            "risk_level": risk,
        },
    }


def format_report(analysis: dict) -> str:
    lines = ["Deepfake Detection Report", "=" * 40]
    s = analysis["summary"]
    lines.append(f"Total events: {s['total_events']}")
    lines.append(f"Flagged: {s['flagged_events']}")
    lines.append(f"Risk: {s['risk_level']}")
    lines.append("")
    for cat, info in sorted(analysis["categories"].items()):
        lines.append(f"  {cat}: {info['count']} events")
    return "\n".join(lines)


def load_events(path: str) -> list[dict]:
    return json.loads(Path(path).read_text())
