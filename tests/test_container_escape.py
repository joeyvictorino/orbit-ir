"""Tests for container escape detection."""
from orbit_ir.container_escape import (
    analyze_container_escapes,
    format_text,
    format_json,
    _extract_action,
    _is_relevant_event,
)


def test_empty_events():
    r = analyze_container_escapes([])
    assert r.summary.total_findings == 0
    assert r.agents_involved == []


def test_no_escape():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "/app/data.txt",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_container_escapes(events)
    assert r.summary.total_findings == 0


def test_docker_socket():
    events = [
        {"agent_id": "a1", "tool": "file_access",
         "resource": "/var/run/docker.sock",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_container_escapes(events)
    assert r.summary.docker_socket_access >= 1
    assert r.findings[0].pattern == "container_docker_socket"
    assert r.findings[0].confidence == "high"


def test_proc_escape():
    events = [
        {"agent_id": "a1", "tool": "exec",
         "command": "cat /proc/1/root/etc/shadow",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_container_escapes(events)
    assert r.summary.proc_escape >= 1
    assert r.findings[0].pattern == "container_proc_escape"


def test_mount_manipulation():
    events = [
        {"agent_id": "a1", "tool": "exec",
         "command": "mount --bind /host /mnt",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_container_escapes(events)
    assert r.summary.mount_manipulation >= 1
    assert r.findings[0].pattern == "container_mount_manipulation"


def test_kernel_exploit():
    events = [
        {"agent_id": "a1", "tool": "exec",
         "command": "cat /dev/mem",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_container_escapes(events)
    assert r.summary.kernel_exploit >= 1
    assert r.findings[0].pattern == "container_kernel_exploit"


def test_cgroup_escape():
    events = [
        {"agent_id": "a1", "tool": "write_file",
         "resource": "/sys/fs/cgroup/x/release_agent",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_container_escapes(events)
    assert r.summary.cgroup_escape >= 1
    assert r.findings[0].pattern == "container_cgroup_escape"


def test_namespace_escape():
    events = [
        {"agent_id": "a1", "tool": "exec",
         "command": "nsenter --target 1 --mount --uts --ipc --net --pid",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_container_escapes(events)
    assert r.summary.namespace_escape >= 1
    assert r.findings[0].pattern == "container_namespace_escape"


def test_extract_action():
    assert _extract_action({"resource": "/foo"}) == "/foo"
    assert _extract_action({"command": "ls -la"}) == "ls -la"
    assert _extract_action({}) == ""


def test_is_relevant_event():
    assert _is_relevant_event({"tool": "exec_command"}) is True
    assert _is_relevant_event({"tool": "x", "resource": "/proc/1/root"}) is True


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "access",
         "resource": "/var/run/docker.sock",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_container_escapes(events)
    text = format_text(r)
    assert "Container Escape" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "access",
         "resource": "/var/run/docker.sock",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_container_escapes(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "findings" in data
    assert "summary" in data


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "exec",
         "command": "cat /var/run/docker.sock",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "exec",
         "command": "nsenter --target 1 --mount",
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_container_escapes(events)
    assert r.summary.agents_involved == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]
