"""Tests for orbit_ir.html_report."""

from orbit_ir.html_report import markdown_to_html, render_html_report


def test_render_html_report_structure():
    md = "# Title\n\nSome text.\n"
    html = render_html_report(md, title="Test Report")
    assert html.startswith("<!DOCTYPE html>")
    assert "<title>Test Report</title>" in html
    assert "prefers-color-scheme: dark" in html
    assert "<h1>Title</h1>" in html
    assert "<p>Some text.</p>" in html
    assert "</html>" in html


def test_render_html_report_escapes_title():
    html = render_html_report("# T\n", title='XSS <script>alert("x")</script>')
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_markdown_to_html_headings():
    html = markdown_to_html("# H1\n\n## H2\n\n### H3\n")
    assert "<h1>H1</h1>" in html
    assert "<h2>H2</h2>" in html
    assert "<h3>H3</h3>" in html


def test_markdown_to_html_paragraph():
    html = markdown_to_html("Simple paragraph.\n")
    assert "<p>Simple paragraph.</p>" in html


def test_markdown_to_html_code_block():
    md = "```\nprint('hello')\n```\n"
    html = markdown_to_html(md)
    assert "<pre><code>" in html
    assert "print(&#x27;hello&#x27;)" in html


def test_markdown_to_html_inline_code():
    html = markdown_to_html("Use `foo` here.\n")
    assert "<code>foo</code>" in html


def test_markdown_to_html_bold():
    html = markdown_to_html("This is **bold** text.\n")
    assert "<strong>bold</strong>" in html


def test_markdown_to_html_unordered_list():
    md = "- one\n- two\n- three\n"
    html = markdown_to_html(md)
    assert "<ul>" in html
    assert "<li>one</li>" in html
    assert "<li>two</li>" in html
    assert "<li>three</li>" in html
    assert "</ul>" in html


def test_markdown_to_html_ordered_list():
    md = "1. first\n2. second\n"
    html = markdown_to_html(md)
    assert "<ol>" in html
    assert "<li>first</li>" in html
    assert "<li>second</li>" in html
    assert "</ol>" in html


def test_markdown_to_html_table():
    md = "| A | B |\n| --- | --- |\n| 1 | 2 |\n| 3 | 4 |\n"
    html = markdown_to_html(md)
    assert "<table>" in html
    assert "<th>A</th>" in html
    assert "<th>B</th>" in html
    assert "<td>1</td>" in html
    assert "<td>4</td>" in html
    assert "</table>" in html


def test_markdown_to_html_blockquote():
    html = markdown_to_html("> Quoted text here.\n")
    assert "<blockquote>" in html
    assert "Quoted text here." in html
    assert "</blockquote>" in html


def test_markdown_to_html_link():
    html = markdown_to_html("[Click](https://example.com)\n")
    assert '<a href="https://example.com">Click</a>' in html


def test_markdown_to_html_angle_link():
    html = markdown_to_html("See <https://example.com> for info.\n")
    assert '<a href="https://example.com">' in html


def test_full_report_integration():
    """The analyze pipeline always writes report.html now."""
    import json
    import tempfile
    from pathlib import Path
    from orbit_ir.generator import LabConfig, generate_dataset
    from orbit_ir.analyzer import analyze_dataset

    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(tmp) / "evidence"
        result_dir = Path(tmp) / "results"
        config = LabConfig(
            agents=10, messages=50, transcripts=20, participants=8,
            spoofed_tool_calls=2, coordinators=2,
            unbacked_completions=2, oracle_modifications=1,
            lateral_accesses=1, seed=42,
        )
        generate_dataset(data_dir, config)
        analyze_dataset(
            data_dir, result_dir,
            ground_truth_path=data_dir / "ground_truth.json",
        )

        html_path = result_dir / "report.html"
        assert html_path.exists(), "report.html should be written by analyze_dataset"
        content = html_path.read_text(encoding="utf-8")
        assert content.startswith("<!DOCTYPE html>")
        assert "ORBIT" in content
        assert "<table>" in content
        assert "prefers-color-scheme: dark" in content
