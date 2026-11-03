"""Tests for orbit_ir.ingest — multi-format evidence ingestion."""
from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path

import pytest
from orbit_ir.ingest import EvidenceIngester, format_ingest_text


@pytest.fixture
def tmp(tmp_path):
    return tmp_path


def _write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


# --- JSON ingestion ---

def test_ingest_json_single_file(tmp):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "agent": "a1", "action": "read", "target": "db", "severity": "low"},
        {"timestamp": "2025-01-01T01:00:00Z", "agent": "a2", "action": "write", "target": "fs"},
    ]
    f = tmp / "events.json"
    _write_json(f, events)
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="json")
    assert len(result) == 2
    assert result[0]["agent"] == "a1"
    assert result[0]["source_format"] == "json"
    assert result[1]["severity"] == "info"  # default when missing


def test_ingest_json_directory(tmp):
    d = tmp / "evidence"
    d.mkdir()
    _write_json(d / "a.json", {"timestamp": "t1", "agent": "x", "action": "a"})
    _write_json(d / "b.json", [{"timestamp": "t2", "agent": "y", "action": "b"}])
    ing = EvidenceIngester()
    result = ing.ingest(d, fmt="json")
    assert len(result) == 2


def test_ingest_json_invalid_skipped(tmp):
    f = tmp / "bad.json"
    f.write_text("not json!", encoding="utf-8")
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="json")
    assert len(result) == 0
    assert len(ing.errors) == 1


# --- CSV ingestion ---

def test_ingest_csv_default_columns(tmp):
    f = tmp / "data.csv"
    f.write_text("timestamp,agent,action,target,severity\n2025-01-01,a1,read,db,high\n2025-01-02,a2,write,fs,low\n", encoding="utf-8")
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="csv")
    assert len(result) == 2
    assert result[0]["severity"] == "high"
    assert result[0]["source_format"] == "csv"


def test_ingest_csv_custom_column_map(tmp):
    f = tmp / "data.csv"
    f.write_text("ts,actor,event,resource,level\n2025-01-01,a1,read,db,medium\n", encoding="utf-8")
    cmap = {"timestamp": "ts", "agent": "actor", "action": "event", "target": "resource", "severity": "level"}
    ing = EvidenceIngester(column_map=cmap)
    result = ing.ingest(f, fmt="csv")
    assert len(result) == 1
    assert result[0]["agent"] == "a1"
    assert result[0]["action"] == "read"


def test_ingest_csv_extra_columns_in_details(tmp):
    f = tmp / "data.csv"
    f.write_text("timestamp,agent,action,target,severity,extra\n2025-01-01,a1,read,db,low,bonus\n", encoding="utf-8")
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="csv")
    assert result[0]["details"]["extra"] == "bonus"


# --- Syslog ingestion ---

def test_ingest_syslog_rfc5424(tmp):
    f = tmp / "syslog.log"
    f.write_text("<134>1 2025-01-01T00:00:00Z myhost myapp[1234]: something happened\n", encoding="utf-8")
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="syslog")
    assert len(result) == 1
    assert result[0]["agent"] == "myhost"
    assert result[0]["action"] == "something happened"
    assert result[0]["source_format"] == "syslog"


def test_ingest_syslog_bsd(tmp):
    f = tmp / "bsd.log"
    f.write_text("Jan  1 00:00:00 myhost sshd[999]: Accepted publickey for user\n", encoding="utf-8")
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="syslog")
    assert len(result) == 1
    assert "Accepted publickey" in result[0]["action"]


def test_ingest_syslog_unrecognized_line(tmp):
    f = tmp / "odd.log"
    f.write_text("just a plain line\n", encoding="utf-8")
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="syslog")
    assert len(result) == 1
    assert result[0]["agent"] == "unknown"


# --- CloudTrail ingestion ---

def test_ingest_cloudtrail_records(tmp):
    ct = {
        "Records": [
            {
                "eventTime": "2025-01-01T00:00:00Z",
                "userIdentity": {"userName": "admin"},
                "eventName": "CreateBucket",
                "eventSource": "s3.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
            }
        ]
    }
    f = tmp / "ct.json"
    _write_json(f, ct)
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="cloudtrail")
    assert len(result) == 1
    assert result[0]["agent"] == "admin"
    assert result[0]["action"] == "CreateBucket"
    assert result[0]["source_format"] == "cloudtrail"
    assert result[0]["details"]["awsRegion"] == "us-east-1"


def test_ingest_cloudtrail_error_event(tmp):
    ct = {
        "Records": [
            {
                "eventTime": "2025-01-01T00:00:00Z",
                "userIdentity": {"arn": "arn:aws:iam::root"},
                "eventName": "GetObject",
                "errorCode": "AccessDenied",
            }
        ]
    }
    f = tmp / "ct.json"
    _write_json(f, ct)
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="cloudtrail")
    assert result[0]["severity"] == "high"


# --- Auto-detection ---

def test_autodetect_json(tmp):
    f = tmp / "events.json"
    _write_json(f, [{"timestamp": "t", "agent": "a", "action": "x"}])
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="auto")
    assert len(result) == 1
    assert result[0]["source_format"] == "json"


def test_autodetect_csv(tmp):
    f = tmp / "data.csv"
    f.write_text("timestamp,agent,action\n2025-01-01,a1,read\n", encoding="utf-8")
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="auto")
    assert len(result) == 1
    assert result[0]["source_format"] == "csv"


def test_autodetect_cloudtrail(tmp):
    f = tmp / "ct.json"
    _write_json(f, {"Records": [{"eventTime": "t", "userIdentity": {"userName": "u"}, "eventName": "e"}]})
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="auto")
    assert len(result) == 1
    assert result[0]["source_format"] == "cloudtrail"


# --- Output ---

def test_output_dir_writes_files(tmp):
    f = tmp / "in.json"
    _write_json(f, [{"timestamp": "t1", "agent": "a", "action": "x"}, {"timestamp": "t2", "agent": "b", "action": "y"}])
    out = tmp / "out"
    ing = EvidenceIngester()
    ing.ingest(f, fmt="json", output_dir=out)
    files = sorted(out.glob("*.json"))
    assert len(files) == 2


def test_summary(tmp):
    f = tmp / "data.csv"
    f.write_text("timestamp,agent,action\nt1,a,x\nt2,b,y\n", encoding="utf-8")
    ing = EvidenceIngester()
    ing.ingest(f, fmt="csv")
    s = ing.summary()
    assert s["total_events"] == 2
    assert s["by_format"]["csv"] == 2


def test_format_ingest_text(tmp):
    f = tmp / "data.csv"
    f.write_text("timestamp,agent,action\nt1,a,x\n", encoding="utf-8")
    ing = EvidenceIngester()
    ing.ingest(f, fmt="csv")
    text = format_ingest_text(ing.summary())
    assert "Ingested 1 events" in text
    assert "csv: 1" in text


# --- Unsupported format ---

def test_unsupported_format_raises(tmp):
    f = tmp / "x.txt"
    f.write_text("hello", encoding="utf-8")
    ing = EvidenceIngester()
    with pytest.raises(ValueError, match="Unsupported format"):
        ing.ingest(f, fmt="xml")


# --- Severity normalization ---

def test_invalid_severity_normalized(tmp):
    f = tmp / "e.json"
    _write_json(f, {"timestamp": "t", "agent": "a", "action": "x", "severity": "BOGUS"})
    ing = EvidenceIngester()
    result = ing.ingest(f, fmt="json")
    assert result[0]["severity"] == "info"
