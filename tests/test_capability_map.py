"""Tests for capability_map module."""
import json
import os
import tempfile

from orbit_ir.capability_map import (
    AgentCapability,
    AgentCapabilityProfile,
    CapabilityMapReport,
    CapabilityMapSummary,
    classify_capability,
    compute_risk_score,
    analyze_capability_map,
    format_text,
    format_json,
    _load_events,
    CAPABILITY_CATEGORIES,
    RISK_TIERS,
)


class TestClassifyCapability:
    def test_read_tools(self):
        assert classify_capability("read_file") == "read"
        assert classify_capability("list_dir") == "read"
        assert classify_capability("search_index") == "read"

    def test_write_tools(self):
        assert classify_capability("write_file") == "write"
        assert classify_capability("create_record") == "write"
        assert classify_capability("update_config") == "write"

    def test_delete_tools(self):
        assert classify_capability("delete_record") == "delete"
        assert classify_capability("remove_file") == "delete"
        assert classify_capability("drop_table") == "delete"

    def test_execute_tools(self):
        assert classify_capability("execute_command") == "execute"
        assert classify_capability("run_shell") == "execute"
        assert classify_capability("bash") == "execute"

    def test_network_tools(self):
        assert classify_capability("http_request") == "network"
        assert classify_capability("curl_api") == "network"
        assert classify_capability("fetch_url") == "network"

    def test_auth_tools(self):
        assert classify_capability("login_user") == "auth"
        assert classify_capability("get_token") == "auth"

    def test_deploy_tools(self):
        assert classify_capability("deploy_app") == "deploy"
        assert classify_capability("publish_image") == "deploy"

    def test_admin_tools(self):
        assert classify_capability("create_user") == "admin"
        assert classify_capability("grant_access") == "admin"
        assert classify_capability("sudo_exec") == "admin"

    def test_unknown_defaults_read(self):
        assert classify_capability("some_unknown_tool") == "read"


class TestComputeRiskScore:
    def test_empty(self):
        assert compute_risk_score([]) == 0.0

    def test_read_only(self):
        caps = [AgentCapability(category="read", invocation_count=5)]
        score = compute_risk_score(caps)
        assert 0.0 < score < 0.1

    def test_admin_high_risk(self):
        caps = [AgentCapability(category="admin", invocation_count=10)]
        score = compute_risk_score(caps)
        assert score >= 0.3

    def test_mixed_capabilities(self):
        caps = [
            AgentCapability(category="read", invocation_count=5),
            AgentCapability(category="write", invocation_count=3),
            AgentCapability(category="execute", invocation_count=2),
        ]
        score = compute_risk_score(caps)
        assert 0.0 < score <= 1.0

    def test_capped_at_one(self):
        caps = [
            AgentCapability(category="admin", invocation_count=100),
            AgentCapability(category="deploy", invocation_count=100),
            AgentCapability(category="execute", invocation_count=100),
            AgentCapability(category="delete", invocation_count=100),
            AgentCapability(category="write", invocation_count=100),
            AgentCapability(category="auth", invocation_count=100),
            AgentCapability(category="network", invocation_count=100),
            AgentCapability(category="read", invocation_count=100),
        ]
        score = compute_risk_score(caps)
        assert score <= 1.0


class TestAnalyzeCapabilityMap:
    def test_empty_events(self):
        report = analyze_capability_map([])
        assert report.summary.total_agents == 0
        assert report.profiles == []

    def test_single_agent(self):
        events = [
            {"agent_id": "a1", "tool": "read_file", "resource": "/etc/config"},
            {"agent_id": "a1", "tool": "write_file", "resource": "/tmp/out"},
        ]
        report = analyze_capability_map(events)
        assert report.summary.total_agents == 1
        assert report.profiles[0].agent_id == "a1"
        assert report.profiles[0].unique_tools == 2

    def test_multiple_agents(self):
        events = [
            {"agent_id": "safe", "tool": "read_file"},
            {"agent_id": "risky", "tool": "execute_command"},
            {"agent_id": "risky", "tool": "sudo_action"},
        ]
        report = analyze_capability_map(events)
        assert report.summary.total_agents == 2
        assert report.profiles[0].risk_score >= report.profiles[1].risk_score

    def test_over_privileged_detection(self):
        events = [
            {"agent_id": "admin_bot", "tool": "create_user"},
            {"agent_id": "admin_bot", "tool": "grant_access"},
            {"agent_id": "admin_bot", "tool": "deploy_service"},
        ]
        report = analyze_capability_map(events)
        profile = report.profiles[0]
        assert len(profile.over_privileged) > 0
        assert "admin" in profile.over_privileged

    def test_tool_deduplication(self):
        events = [
            {"agent_id": "a1", "tool": "read_file"},
            {"agent_id": "a1", "tool": "read_file"},
            {"agent_id": "a1", "tool": "read_file"},
        ]
        report = analyze_capability_map(events)
        assert report.profiles[0].unique_tools == 1
        cap = report.profiles[0].capabilities[0]
        assert cap.invocation_count == 3

    def test_resource_tracking(self):
        events = [
            {"agent_id": "a1", "tool": "read_file", "resource": "/etc/passwd"},
            {"agent_id": "a1", "tool": "read_file", "resource": "/etc/shadow"},
        ]
        report = analyze_capability_map(events)
        cap = report.profiles[0].capabilities[0]
        assert len(cap.resources) == 2

    def test_events_without_tool(self):
        events = [
            {"agent_id": "a1"},
            {"agent_id": "a1", "tool": "read_file"},
        ]
        report = analyze_capability_map(events)
        assert report.profiles[0].total_invocations == 1

    def test_agent_field_fallback(self):
        events = [{"agent": "bot1", "tool": "read_file"}]
        report = analyze_capability_map(events)
        assert report.profiles[0].agent_id == "bot1"

    def test_unknown_agent(self):
        events = [{"tool": "read_file"}]
        report = analyze_capability_map(events)
        assert report.profiles[0].agent_id == "unknown"

    def test_summary_admin_count(self):
        events = [
            {"agent_id": "a1", "tool": "create_user"},
            {"agent_id": "a2", "tool": "read_file"},
        ]
        report = analyze_capability_map(events)
        assert report.summary.agents_with_admin == 1

    def test_summary_delete_count(self):
        events = [
            {"agent_id": "a1", "tool": "delete_record"},
            {"agent_id": "a2", "tool": "remove_all"},
        ]
        report = analyze_capability_map(events)
        assert report.summary.agents_with_delete == 2

    def test_highest_risk_agent(self):
        events = [
            {"agent_id": "safe", "tool": "read_file"},
            {"agent_id": "danger", "tool": "execute_command"},
            {"agent_id": "danger", "tool": "sudo_run"},
            {"agent_id": "danger", "tool": "deploy_app"},
        ]
        report = analyze_capability_map(events)
        assert report.summary.highest_risk_agent == "danger"


class TestFormatText:
    def test_header(self):
        report = analyze_capability_map([{"agent_id": "a1", "tool": "read_file"}])
        text = format_text(report)
        assert "Agent Capability Map" in text
        assert "a1" in text

    def test_over_privileged_flag(self):
        events = [{"agent_id": "admin", "tool": "create_user"}]
        report = analyze_capability_map(events)
        text = format_text(report)
        assert "OVER-PRIVILEGED" in text

    def test_empty_report(self):
        report = analyze_capability_map([])
        text = format_text(report)
        assert "0 agents" in text


class TestFormatJson:
    def test_valid_json(self):
        events = [{"agent_id": "a1", "tool": "read_file"}]
        report = analyze_capability_map(events)
        raw = format_json(report)
        data = json.loads(raw)
        assert "profiles" in data
        assert "summary" in data

    def test_round_trip(self):
        events = [
            {"agent_id": "a1", "tool": "read_file"},
            {"agent_id": "a2", "tool": "execute_command"},
        ]
        report = analyze_capability_map(events)
        raw = format_json(report)
        data = json.loads(raw)
        assert len(data["profiles"]) == 2


class TestLoadEvents:
    def test_load_json_files(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "events.json")
            with open(p, "w") as f:
                json.dump([{"agent_id": "a1", "tool": "read_file"}], f)
            events = _load_events(td)
            assert len(events) == 1

    def test_load_single_object(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "event.json")
            with open(p, "w") as f:
                json.dump({"agent_id": "a1", "tool": "write_file"}, f)
            events = _load_events(td)
            assert len(events) == 1

    def test_skip_invalid_json(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "bad.json")
            with open(p, "w") as f:
                f.write("not json")
            events = _load_events(td)
            assert events == []

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as td:
            events = _load_events(td)
            assert events == []
