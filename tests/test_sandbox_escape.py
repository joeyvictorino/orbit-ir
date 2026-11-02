"""Tests for sandbox escape attempt detection."""
from orbit_ir.sandbox_escape import (
    analyze_sandbox_escape,
    format_text,
    format_json,
    _severity_for_escape,
)


def test_empty_events():
    r = analyze_sandbox_escape([])
    assert r.summary.total_detections == 0
    assert r.agent_risk_scores == []
    assert r.summary.highest_severity == "none"


def test_no_escape():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    assert r.summary.total_detections == 0


def test_privileged_syscall():
    events = [
        {"agent_id": "a1", "tool": "syscall", "resource": "mount /dev/sda1",
         "syscall": "mount", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    assert r.summary.total_detections >= 1
    assert any(d.escape_type == "privileged-op" for d in r.detections)


def test_privileged_op_in_tool_name():
    events = [
        {"agent_id": "a1", "tool": "ptrace_attach", "resource": "pid 1234",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    priv = [d for d in r.detections if d.escape_type == "privileged-op"]
    assert len(priv) >= 1
    assert "ptrace" in priv[0].description.lower()


def test_privileged_op_sandbox_false_ok():
    events = [
        {"agent_id": "a1", "tool": "syscall", "resource": "mount /tmp",
         "syscall": "mount", "sandbox": False,
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    priv = [d for d in r.detections if d.escape_type == "privileged-op"]
    assert len(priv) == 0


def test_mount_escape_proc():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "/proc/1/root/etc/shadow",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    mounts = [d for d in r.detections if d.escape_type == "mount-escape"]
    assert len(mounts) >= 1


def test_mount_escape_docker_sock():
    events = [
        {"agent_id": "a1", "tool": "bind_mount", "resource": "/var/run/docker.sock",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    assert r.summary.total_detections >= 1


def test_mount_escape_normal_ok():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "/app/data/output.txt",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    mounts = [d for d in r.detections if d.escape_type == "mount-escape"]
    assert len(mounts) == 0


def test_kernel_exploit_dirty_pipe():
    events = [
        {"agent_id": "a1", "tool": "exploit", "resource": "dirty_pipe",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    kernel = [d for d in r.detections if d.escape_type == "kernel-exploit"]
    assert len(kernel) >= 1
    assert kernel[0].severity == "critical"


def test_kernel_exploit_cve():
    events = [
        {"agent_id": "a1", "tool": "execute", "resource": "cve-2022-0847 payload",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    kernel = [d for d in r.detections if d.escape_type == "kernel-exploit"]
    assert len(kernel) >= 1


def test_container_breakout_docker_sock():
    events = [
        {"agent_id": "a1", "tool": "http_post", "resource": "docker.sock /containers/create",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    breakout = [d for d in r.detections if d.escape_type == "container-breakout"]
    assert len(breakout) >= 1


def test_container_breakout_nsenter():
    events = [
        {"agent_id": "a1", "tool": "nsenter", "resource": "--target 1 --mount",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    assert r.summary.total_detections >= 1


def test_container_breakout_normal_ok():
    events = [
        {"agent_id": "a1", "tool": "http_get", "resource": "https://api.com/data",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    breakout = [d for d in r.detections if d.escape_type == "container-breakout"]
    assert len(breakout) == 0


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "exploit", "resource": "dirty_cow",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "read_file", "resource": "/proc/1/root/etc/passwd",
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    assert r.summary.agents_involved == 2


def test_agent_risk_scores():
    events = [
        {"agent_id": "a1", "tool": "exploit", "resource": "dirty_pipe",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "read_file", "resource": "/var/run/docker.sock",
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    assert len(r.agent_risk_scores) >= 1
    assert r.agent_risk_scores[0].risk_score > 0
    assert r.agent_risk_scores[0].total_attempts >= 2


def test_severity_for_escape():
    assert _severity_for_escape("kernel-exploit", "") == "critical"
    assert _severity_for_escape("container-breakout", "docker.sock") == "critical"
    assert _severity_for_escape("mount-escape", "/etc/shadow") == "critical"
    assert _severity_for_escape("privileged-op", "some_resource") == "high"


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "exploit", "resource": "dirty_pipe",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    text = format_text(r)
    assert "Sandbox Escape" in text
    assert "ESC-" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "exploit", "resource": "dirty_pipe",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "detections" in data
    assert "summary" in data
    assert data["summary"]["total_detections"] >= 1


def test_format_text_empty():
    r = analyze_sandbox_escape([])
    text = format_text(r)
    assert "Sandbox Escape" in text
    assert "0" in text


def test_params_detection():
    events = [
        {"agent_id": "a1", "tool": "execute_command", "resource": "run",
         "parameters": {"cmd": "nsenter --target 1"},
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_sandbox_escape(events)
    assert r.summary.total_detections >= 1
