import json
import os
import tempfile
import pytest
from orbit_ir.api_key_leak import classify_event, analyze, format_report, load_events, CATEGORIES


class TestClassifyEvent:
    def test_aws_access_key(self):
        assert classify_event("aws access key found in commit") == "cloud_key_leak"

    def test_azure_api_key(self):
        assert classify_event("azure api key leaked in build log") == "cloud_key_leak"

    def test_gcp_service_account_key(self):
        assert classify_event("gcp service account key exposed") == "cloud_key_leak"

    def test_api_token_exposed(self):
        assert classify_event("api token exposed in response body") == "token_exposure"

    def test_bearer_token_leaked(self):
        assert classify_event("bearer token leaked in logs") == "token_exposure"

    def test_jwt_secret_exposed(self):
        assert classify_event("jwt secret exposed in config") == "token_exposure"

    def test_personal_access_token(self):
        assert classify_event("personal access token committed to repo") == "token_exposure"

    def test_hardcoded_secret(self):
        assert classify_event("hardcoded secret found in source") == "secret_in_code"

    def test_secret_in_source_code(self):
        assert classify_event("secret in source code detected") == "secret_in_code"

    def test_credentials_in_repository(self):
        assert classify_event("credentials in repository history") == "secret_in_code"

    def test_api_key_abuse(self):
        assert classify_event("api key abuse detected from unusual location") == "key_misuse"

    def test_stolen_api_key(self):
        assert classify_event("stolen api key used for access") == "key_misuse"

    def test_key_used_after_revocation(self):
        assert classify_event("key used after revocation attempt") == "key_misuse"

    def test_env_file_exposed(self):
        assert classify_event("env file exposed on public server") == "env_leak"

    def test_dotenv_exposed(self):
        assert classify_event("dotenv exposed in web root") == "env_leak"

    def test_env_in_public_repo(self):
        assert classify_event(".env in public repo discovered") == "env_leak"

    def test_webhook_secret_exposed(self):
        assert classify_event("webhook secret exposed in dashboard") == "webhook_secret"

    def test_hmac_secret_leaked(self):
        assert classify_event("hmac secret leaked in error message") == "webhook_secret"

    def test_signing_secret_compromised(self):
        assert classify_event("signing secret compromised via log") == "webhook_secret"

    def test_unknown(self):
        assert classify_event("normal api request completed") == "unknown"

    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_whitespace_only(self):
        assert classify_event("   ") == "unknown"

    def test_dict_event(self):
        assert classify_event({"alert": "aws access key found"}) == "cloud_key_leak"

    def test_case_insensitive(self):
        assert classify_event("AWS ACCESS KEY Detected") == "cloud_key_leak"

    def test_non_string_non_dict(self):
        assert classify_event(42) == "unknown"


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        result = analyze(["aws access key leaked"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_no_matches(self):
        result = analyze(["normal api call", "standard response"])
        assert result["flagged_count"] == 0

    def test_severity_high(self):
        events = [f"api token exposed in log {i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = [f"api token exposed in log {i}" for i in range(11)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_category_counts(self):
        events = ["aws access key found", "bearer token leaked", "aws secret key exposed"]
        result = analyze(events)
        assert result["category_counts"]["cloud_key_leak"] == 2
        assert result["category_counts"]["token_exposure"] == 1

    def test_detection_rate(self):
        result = analyze(["aws access key", "normal", "bearer token leaked", "safe"])
        assert result["detection_rate"] == 0.5

    def test_flagged_structure(self):
        result = analyze(["hardcoded secret detected"])
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "secret_in_code"
        assert entry["event"] == "hardcoded secret detected"


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        text = format_report(result)
        assert "API Key Leak" in text

    def test_format_with_findings(self):
        result = analyze(["aws access key exposed"])
        text = format_report(result)
        assert "cloud_key_leak" in text

    def test_format_truncation(self):
        events = [f"api token exposed event {i}" for i in range(15)]
        result = analyze(events)
        text = format_report(result)
        assert "... and 5 more" in text

    def test_format_detection_rate(self):
        result = analyze(["aws access key", "normal event"])
        text = format_report(result)
        assert "50.0%" in text


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["event1", "event2"], f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": ["a", "b"]}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"action": "test"}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1


class TestCategories:
    def test_all_categories_have_patterns(self):
        for cat, patterns in CATEGORIES.items():
            assert len(patterns) > 0, f"category {cat} has no patterns"

    def test_category_names(self):
        expected = {"cloud_key_leak", "token_exposure", "secret_in_code", "key_misuse", "env_leak", "webhook_secret"}
        assert set(CATEGORIES.keys()) == expected
