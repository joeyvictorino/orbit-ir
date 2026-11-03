"""Tests for firmware_tamper detection module."""

import json
import tempfile
from pathlib import Path

from orbit_ir.firmware_tamper import (
    CATEGORIES,
    _classify_event,
    _detect_chains,
    _load_events,
    analyze_firmware_tamper,
    format_json,
    format_text,
)


class TestClassifyEvent:
    def test_empty_event(self):
        assert _classify_event({}) == []

    def test_no_match(self):
        assert _classify_event({"message": "normal operation completed"}) == []

    def test_firmware_modify(self):
        ev = {"message": "modify firmware bios image to inject backdoor code"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "firmware_modify" in cats

    def test_bootloader_tamper(self):
        ev = {"message": "tamper bootloader grub to inject malicious backdoor code"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "bootloader_tamper" in cats

    def test_secure_boot_bypass(self):
        ev = {"message": "bypass secure boot mechanism using exploit vulnerability"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "secure_boot_bypass" in cats

    def test_firmware_implant(self):
        ev = {"message": "plant persistent implant in firmware uefi for stealth persistence"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "firmware_implant" in cats

    def test_tpm_attack(self):
        ev = {"message": "attack tpm trusted platform module key to extract secret measurement"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "tpm_attack" in cats

    def test_supply_chain_firmware(self):
        ev = {"message": "inject malicious code during firmware supply chain manufacturing process"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "supply_chain_firmware" in cats

    def test_bootkit_attack(self):
        ev = {"message": "bootkit attack implant deployed on target system device"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "bootloader_tamper" in cats

    def test_spi_flash_write(self):
        ev = {"message": "write to firmware spi flash chip region with malicious data"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "firmware_modify" in cats

    def test_uefi_rootkit(self):
        ev = {"message": "firmware uefi implant backdoor that persists across os reinstall using spi flash"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "firmware_implant" in cats

    def test_multiple_categories(self):
        ev = {"message": "modify firmware bios image to inject backdoor and bypass secure boot mechanism using vulnerability"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2


class TestDetectChains:
    def test_empty(self):
        assert _detect_chains([]) == []

    def test_single_event_no_chain(self):
        events = [{"agent_id": "a1", "message": "modify firmware bios image to inject code"}]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "modify firmware bios image to inject backdoor code"},
            {"agent_id": "a1", "message": "plant persistent implant in firmware uefi for stealth"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 1
        assert chains[0].agent == "a1"

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "modify firmware bios image to inject code"},
            {"agent_id": "a1", "message": "bypass secure boot mechanism using exploit"},
            {"agent_id": "a1", "message": "plant persistent implant in firmware uefi for stealth"},
        ]
        chains = _detect_chains(events)
        assert chains[0].violation_score > 0

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "modify firmware bios image to inject backdoor code"},
            {"agent_id": "a1", "message": "plant persistent implant in firmware uefi for stealth"},
            {"agent_id": "a2", "message": "tamper bootloader grub to inject malicious code"},
            {"agent_id": "a2", "message": "bypass secure boot mechanism using exploit vulnerability"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 2


class TestAnalyze:
    def test_empty(self):
        r = analyze_firmware_tamper([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_no_violations(self):
        r = analyze_firmware_tamper([{"message": "normal operation"}])
        assert r.total_events == 1
        assert r.violation_events == 0

    def test_with_violations(self):
        events = [
            {"agent_id": "a1", "message": "modify firmware bios image to inject backdoor code"},
            {"message": "normal event"},
        ]
        r = analyze_firmware_tamper(events)
        assert r.total_events == 2
        assert r.violation_events == 1

    def test_risk_score(self):
        events = [
            {"agent_id": "a1", "message": "modify firmware bios image to inject backdoor code"},
            {"agent_id": "a1", "message": "plant persistent implant in firmware uefi for stealth"},
        ]
        r = analyze_firmware_tamper(events)
        assert r.risk_score > 0

    def test_agents_involved(self):
        events = [
            {"agent_id": "a1", "message": "modify firmware bios image to inject backdoor code"},
            {"agent_id": "a2", "message": "tamper bootloader grub to inject malicious code"},
        ]
        r = analyze_firmware_tamper(events)
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_categories_populated(self):
        r = analyze_firmware_tamper([{"message": "normal"}])
        assert len(r.categories) == len(CATEGORIES)

    def test_risk_level_with_violations(self):
        events = [
            {"agent_id": "a1", "message": "modify firmware bios image to inject backdoor code"},
        ]
        r = analyze_firmware_tamper(events)
        assert r.risk_level in ("critical", "high", "medium", "low")
        assert r.risk_score > 0

    def test_risk_level_none(self):
        r = analyze_firmware_tamper([{"message": "normal operation"}])
        assert r.risk_level == "none"


class TestLoadEvents:
    def test_nonexistent_dir(self):
        assert _load_events("/nonexistent/path") == []

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as d:
            assert _load_events(d) == []

    def test_json_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "events.json"
            p.write_text(json.dumps([{"message": "test"}]))
            events = _load_events(d)
            assert len(events) == 1

    def test_single_object(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "event.json"
            p.write_text(json.dumps({"message": "test"}))
            events = _load_events(d)
            assert len(events) == 1

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text("not json")
            events = _load_events(d)
            assert len(events) == 0

    def test_directory_input(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "data.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "modify firmware bios image to inject backdoor code"},
            ]))
            r = analyze_firmware_tamper(d)
            assert r.total_events == 1


class TestFormat:
    def test_format_text_header(self):
        r = analyze_firmware_tamper([])
        text = format_text(r)
        assert "Firmware Tampering" in text

    def test_format_text_with_data(self):
        events = [
            {"agent_id": "a1", "message": "modify firmware bios image to inject backdoor code"},
            {"agent_id": "a1", "message": "plant persistent implant in firmware uefi for stealth"},
        ]
        r = analyze_firmware_tamper(events)
        text = format_text(r)
        assert "violation" in text.lower() or "Violation" in text

    def test_format_json_valid(self):
        r = analyze_firmware_tamper([{"message": "test"}])
        j = format_json(r)
        data = json.loads(j)
        assert "total_events" in data
        assert "risk_score" in data

    def test_format_json_no_raw(self):
        events = [{"agent_id": "a1", "message": "modify firmware bios image to inject backdoor code"}]
        r = analyze_firmware_tamper(events)
        j = format_json(r)
        assert '"raw"' not in j

    def test_format_text_categories(self):
        events = [{"agent_id": "a1", "message": "modify firmware bios image to inject backdoor code"}]
        r = analyze_firmware_tamper(events)
        text = format_text(r)
        assert "firmware_modify" in text
