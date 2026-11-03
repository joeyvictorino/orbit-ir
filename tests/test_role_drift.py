"""Tests for role_drift module."""
import json

from orbit_ir.role_drift import (
    analyze_role_drift,
    format_text,
    format_json,
    _extract_action,
    _infer_role,
    _action_risk,
    ROLE_EXPECTATIONS,
    RISK_LEVELS,
    DriftViolation,
    AgentRoleDrift,
    RoleDriftReport,
    RoleDriftSummary,
)


class TestExtractAction:
    def test_explicit_action(self):
        assert _extract_action({"action": "read"}) == "read"

    def test_action_case_insensitive(self):
        assert _extract_action({"action": "DELETE"}) == "delete"

    def test_tool_based_read(self):
        assert _extract_action({"tool": "read_file"}) == "read"
        assert _extract_action({"tool": "list_dir"}) == "read"
        assert _extract_action({"tool": "search_index"}) == "read"

    def test_tool_based_write(self):
        assert _extract_action({"tool": "write_file"}) == "write"
        assert _extract_action({"tool": "create_record"}) == "write"
        assert _extract_action({"tool": "update_config"}) == "write"

    def test_tool_based_delete(self):
        assert _extract_action({"tool": "delete_record"}) == "delete"
        assert _extract_action({"tool": "remove_file"}) == "delete"

    def test_tool_based_execute(self):
        assert _extract_action({"tool": "execute_command"}) == "execute"
        assert _extract_action({"tool": "bash"}) == "execute"

    def test_tool_based_deploy(self):
        assert _extract_action({"tool": "deploy_app"}) == "deploy"

    def test_tool_based_admin(self):
        assert _extract_action({"tool": "grant_access_all"}) == "grant_access"

    def test_unknown_action(self):
        assert _extract_action({}) == "unknown"

    def test_tool_name_fallback(self):
        assert _extract_action({"tool_name": "read_config"}) == "read"


class TestInferRole:
    def test_read_only_is_recon(self):
        assert _infer_role({"read": 10}) == "recon"

    def test_write_is_remediate(self):
        assert _infer_role({"read": 5, "write": 3}) == "remediate"

    def test_execute_is_validate(self):
        assert _infer_role({"read": 5, "execute": 3}) == "validate"

    def test_execute_and_write_is_probe(self):
        assert _infer_role({"read": 5, "execute": 2, "write": 1}) == "probe"

    def test_admin_with_create_user(self):
        assert _infer_role({"read": 5, "create_user": 1}) == "admin"

    def test_admin_with_deploy(self):
        assert _infer_role({"read": 5, "deploy": 1}) == "admin"

    def test_admin_with_delete_and_write(self):
        assert _infer_role({"read": 5, "delete": 1, "write": 1}) == "admin"

    def test_empty_is_recon(self):
        assert _infer_role({}) == "recon"


class TestActionRisk:
    def test_read_is_zero(self):
        assert _action_risk("read") == 0

    def test_write_is_one(self):
        assert _action_risk("write") == 1

    def test_execute_is_two(self):
        assert _action_risk("execute") == 2

    def test_deploy_is_three(self):
        assert _action_risk("deploy") == 3

    def test_admin_is_three(self):
        assert _action_risk("create_user") == 3
        assert _action_risk("grant_access") == 3

    def test_unknown_is_zero(self):
        assert _action_risk("anything_else") == 0


class TestAnalyzeRoleDrift:
    def test_empty_events(self):
        report = analyze_role_drift([])
        assert report.summary.total_agents == 0

    def test_compliant_recon_agent(self):
        events = [
            {"agent_id": "scanner", "role": "recon", "tool": "read_file"},
            {"agent_id": "scanner", "role": "recon", "tool": "search_index"},
            {"agent_id": "scanner", "role": "recon", "tool": "list_dir"},
        ]
        report = analyze_role_drift(events)
        assert report.summary.total_agents == 1
        agent = report.agents[0]
        assert agent.declared_role == "recon"
        assert agent.drift_score == 0.0
        assert agent.violating_actions == 0

    def test_drifted_recon_agent(self):
        events = [
            {"agent_id": "scanner", "role": "recon", "tool": "read_file"},
            {"agent_id": "scanner", "role": "recon", "tool": "write_file"},
            {"agent_id": "scanner", "role": "recon", "tool": "execute_command"},
        ]
        report = analyze_role_drift(events)
        agent = report.agents[0]
        assert agent.drift_score > 0
        assert agent.violating_actions > 0

    def test_role_map_override(self):
        events = [
            {"agent_id": "bot", "tool": "delete_record"},
        ]
        report = analyze_role_drift(events, role_map={"bot": "recon"})
        agent = report.agents[0]
        assert agent.declared_role == "recon"
        assert agent.violating_actions > 0

    def test_role_from_event_field(self):
        events = [
            {"agent_id": "a1", "agent_role": "monitor", "tool": "list_items"},
        ]
        report = analyze_role_drift(events)
        assert report.agents[0].declared_role == "monitor"

    def test_inferred_when_no_role(self):
        events = [
            {"agent_id": "a1", "tool": "read_file"},
        ]
        report = analyze_role_drift(events)
        assert report.agents[0].declared_role == "recon"
        assert report.agents[0].inferred_role == "recon"

    def test_multiple_agents(self):
        events = [
            {"agent_id": "safe", "role": "recon", "tool": "read_file"},
            {"agent_id": "risky", "role": "recon", "tool": "execute_command"},
            {"agent_id": "risky", "role": "recon", "tool": "deploy_app"},
        ]
        report = analyze_role_drift(events)
        assert report.summary.total_agents == 2
        assert report.summary.agents_with_drift >= 1

    def test_sorted_by_drift_score(self):
        events = [
            {"agent_id": "safe", "role": "admin", "tool": "read_file"},
            {"agent_id": "risky", "role": "recon", "tool": "execute_command"},
            {"agent_id": "risky", "role": "recon", "tool": "deploy_app"},
        ]
        report = analyze_role_drift(events)
        scores = [a.drift_score for a in report.agents]
        assert scores == sorted(scores, reverse=True)

    def test_violation_details(self):
        events = [
            {"agent_id": "a1", "role": "recon", "tool": "delete_record", "resource": "/db/users"},
        ]
        report = analyze_role_drift(events)
        agent = report.agents[0]
        assert len(agent.violations) == 1
        v = agent.violations[0]
        assert v.action == "delete"
        assert v.tool == "delete_record"
        assert v.resource == "/db/users"
        assert "forbidden" in v.reason

    def test_admin_agent_no_drift(self):
        events = [
            {"agent_id": "root", "role": "admin", "tool": "create_user_account"},
            {"agent_id": "root", "role": "admin", "tool": "deploy_app"},
            {"agent_id": "root", "role": "admin", "tool": "execute_command"},
            {"agent_id": "root", "role": "admin", "tool": "delete_record"},
        ]
        report = analyze_role_drift(events)
        agent = report.agents[0]
        assert agent.drift_score == 0.0

    def test_summary_highest_drift(self):
        events = [
            {"agent_id": "good", "role": "admin", "tool": "read_file"},
            {"agent_id": "bad", "role": "monitor", "tool": "execute_command"},
            {"agent_id": "bad", "role": "monitor", "tool": "deploy_app"},
        ]
        report = analyze_role_drift(events)
        assert report.summary.highest_drift_agent == "bad"

    def test_agent_fallback_identity(self):
        events = [{"agent": "bot1", "tool": "read_file"}]
        report = analyze_role_drift(events)
        assert report.agents[0].agent_id == "bot1"

    def test_unknown_agent(self):
        events = [{"tool": "read_file"}]
        report = analyze_role_drift(events)
        assert report.agents[0].agent_id == "unknown"


class TestFormatText:
    def test_header(self):
        report = analyze_role_drift([{"agent_id": "a1", "role": "recon", "tool": "read_file"}])
        text = format_text(report)
        assert "Role Drift Analysis" in text
        assert "a1" in text

    def test_drifted_flag(self):
        events = [{"agent_id": "a1", "role": "recon", "tool": "execute_command"}]
        report = analyze_role_drift(events)
        text = format_text(report)
        assert "DRIFTED" in text

    def test_empty(self):
        report = analyze_role_drift([])
        text = format_text(report)
        assert "0 agents" in text


class TestFormatJson:
    def test_valid_json(self):
        events = [{"agent_id": "a1", "role": "recon", "tool": "read_file"}]
        report = analyze_role_drift(events)
        raw = format_json(report)
        data = json.loads(raw)
        assert "agents" in data
        assert "summary" in data

    def test_round_trip(self):
        events = [
            {"agent_id": "a1", "role": "recon", "tool": "read_file"},
            {"agent_id": "a2", "role": "probe", "tool": "execute_command"},
        ]
        report = analyze_role_drift(events)
        raw = format_json(report)
        data = json.loads(raw)
        assert len(data["agents"]) == 2


class TestRoleExpectations:
    def test_all_roles_have_expectations(self):
        for role in ["recon", "probe", "validate", "remediate", "admin", "monitor"]:
            assert role in ROLE_EXPECTATIONS

    def test_admin_no_forbidden(self):
        assert len(ROLE_EXPECTATIONS["admin"]["forbidden_actions"]) == 0

    def test_recon_forbids_write(self):
        assert "write" in ROLE_EXPECTATIONS["recon"]["forbidden_actions"]

    def test_risk_levels_ordered(self):
        assert RISK_LEVELS["low"] < RISK_LEVELS["medium"] < RISK_LEVELS["high"] < RISK_LEVELS["critical"]
