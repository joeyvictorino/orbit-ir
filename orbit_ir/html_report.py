"""Self-contained HTML report renderer for ORBIT analysis results.

Converts the Markdown report to a styled HTML page with inline CSS,
dark mode support, and responsive tables.  No external dependencies.
"""

from __future__ import annotations

import html
import re


def render_html_report(markdown: str, title: str = "ORBIT Analysis Report") -> str:
    body = markdown_to_html(markdown)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{
  --bg: #fff; --fg: #1a1a2e; --muted: #6b7280; --border: #e5e7eb;
  --accent: #2563eb; --code-bg: #f3f4f6; --table-stripe: #f9fafb;
  --pass: #16a34a; --fail: #dc2626; --warn: #d97706;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #0f172a; --fg: #e2e8f0; --muted: #94a3b8; --border: #334155;
    --accent: #60a5fa; --code-bg: #1e293b; --table-stripe: #1e293b;
    --pass: #4ade80; --fail: #f87171; --warn: #fbbf24;
  }}
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  color: var(--fg); background: var(--bg);
  max-width: 960px; margin: 0 auto; padding: 2rem 1rem; line-height: 1.6;
}}
h1 {{ font-size: 1.5rem; margin: 1.5rem 0 0.75rem; border-bottom: 2px solid var(--accent); padding-bottom: 0.25rem; }}
h2 {{ font-size: 1.25rem; margin: 1.25rem 0 0.5rem; color: var(--accent); }}
h3 {{ font-size: 1.1rem; margin: 1rem 0 0.5rem; }}
p {{ margin: 0.5rem 0; }}
ul, ol {{ margin: 0.5rem 0 0.5rem 1.5rem; }}
li {{ margin: 0.25rem 0; }}
code {{ font-family: "SF Mono", "Fira Code", monospace; font-size: 0.875em; background: var(--code-bg); padding: 0.125rem 0.375rem; border-radius: 3px; }}
pre {{ background: var(--code-bg); padding: 1rem; border-radius: 6px; overflow-x: auto; margin: 0.75rem 0; font-size: 0.85rem; }}
pre code {{ background: none; padding: 0; }}
blockquote {{ border-left: 3px solid var(--accent); padding: 0.5rem 1rem; margin: 0.5rem 0; color: var(--muted); }}
table {{ width: 100%; border-collapse: collapse; margin: 0.75rem 0; font-size: 0.9rem; }}
th {{ background: var(--code-bg); text-align: left; padding: 0.5rem 0.75rem; border: 1px solid var(--border); font-weight: 600; }}
td {{ padding: 0.5rem 0.75rem; border: 1px solid var(--border); }}
tr:nth-child(even) td {{ background: var(--table-stripe); }}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
strong {{ font-weight: 600; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def markdown_to_html(md: str) -> str:
    lines = md.split("\n")
    out: list[str] = []
    in_table = False
    in_list = False
    in_code = False
    in_blockquote = False
    in_ol = False

    for line in lines:
        # Fenced code blocks.
        if line.startswith("```"):
            if in_code:
                out.append("</code></pre>")
                in_code = False
            else:
                _close_blocks(out, in_table, in_list, in_blockquote, in_ol)
                in_table = in_list = in_blockquote = in_ol = False
                out.append("<pre><code>")
                in_code = True
            continue
        if in_code:
            out.append(html.escape(line))
            continue

        stripped = line.strip()
        if not stripped:
            if in_table:
                out.append("</tbody></table>")
                in_table = False
            if in_list:
                out.append("</ul>")
                in_list = False
            if in_ol:
                out.append("</ol>")
                in_ol = False
            if in_blockquote:
                out.append("</blockquote>")
                in_blockquote = False
            continue

        # Headings.
        m = re.match(r"^(#{1,6})\s+(.*)", stripped)
        if m:
            _close_blocks(out, in_table, in_list, in_blockquote, in_ol)
            in_table = in_list = in_blockquote = in_ol = False
            level = len(m.group(1))
            text = _inline(m.group(2))
            out.append(f"<h{level}>{text}</h{level}>")
            continue

        # Blockquote.
        if stripped.startswith("> "):
            if not in_blockquote:
                _close_blocks(out, in_table, in_list, in_blockquote, in_ol)
                in_table = in_list = in_ol = False
                out.append("<blockquote>")
                in_blockquote = True
            out.append(f"<p>{_inline(stripped[2:])}</p>")
            continue

        # Table rows.
        if stripped.startswith("|") and stripped.endswith("|"):
            cells = _parse_table_row(stripped)
            if _is_align_row(stripped):
                continue
            if not in_table:
                _close_blocks(out, in_table, in_list, in_blockquote, in_ol)
                in_list = in_blockquote = in_ol = False
                out.append("<table>\n<thead><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in cells) + "</tr></thead>\n<tbody>")
                in_table = True
            else:
                out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
            continue

        # Unordered list.
        if stripped.startswith("- "):
            if not in_list:
                _close_blocks(out, in_table, in_list, in_blockquote, in_ol)
                in_table = in_blockquote = in_ol = False
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(stripped[2:])}</li>")
            continue

        # Ordered list.
        om = re.match(r"^(\d+)\.\s+(.*)", stripped)
        if om:
            if not in_ol:
                _close_blocks(out, in_table, in_list, in_blockquote, in_ol)
                in_table = in_list = in_blockquote = False
                out.append("<ol>")
                in_ol = True
            out.append(f"<li>{_inline(om.group(2))}</li>")
            continue

        # Paragraph.
        _close_blocks(out, in_table, in_list, in_blockquote, in_ol)
        in_table = in_list = in_blockquote = in_ol = False
        out.append(f"<p>{_inline(stripped)}</p>")

    _close_blocks(out, in_table, in_list, in_blockquote, in_ol)
    if in_code:
        out.append("</code></pre>")

    return "\n".join(out)


def _close_blocks(
    out: list[str],
    in_table: bool,
    in_list: bool,
    in_blockquote: bool,
    in_ol: bool,
) -> None:
    if in_table:
        out.append("</tbody></table>")
    if in_list:
        out.append("</ul>")
    if in_ol:
        out.append("</ol>")
    if in_blockquote:
        out.append("</blockquote>")


def _inline(text: str) -> str:
    text = html.escape(text)
    # Inline code: `...`
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    # Bold: **...**
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    # Links: [text](url)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    # Angle-bracket links: <url>
    text = re.sub(r"&lt;(https?://[^&]+)&gt;", r'<a href="\1">\1</a>', text)
    return text


def _parse_table_row(row: str) -> list[str]:
    row = row.strip().strip("|")
    return [cell.strip() for cell in row.split("|")]


def _is_align_row(row: str) -> bool:
    cells = _parse_table_row(row)
    return all(re.fullmatch(r"[-:]+", c) for c in cells if c)
