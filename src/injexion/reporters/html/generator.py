"""
Standalone zero-CDN HTML report generator for InjeXion.
Self-contained, responsive, dark-themed dashboard with evidence inspection.
"""

import html
from pathlib import Path
from typing import List
from injexion.core.models import Finding, ScanMetadata
from injexion.reporters.base import BaseReporter


class HTMLReporter(BaseReporter):
    def generate(
        self,
        findings: List[Finding],
        metadata: ScanMetadata,
        output_path: Path
    ) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")
        info_count = sum(1 for f in findings if f.severity == "INFO")

        cards_html = []
        for idx, f in enumerate(findings):
            sev_class = f.severity.value.lower()
            evidence_block = ""
            if f.evidence:
                evidence_block = f"""
                <div class="evidence-box">
                    <h4>HTTP Request Evidence</h4>
                    <pre><code>{html.escape(f.evidence.request_method)} {html.escape(f.evidence.request_url)}
{html.escape(str(f.evidence.request_headers))}
{html.escape(f.evidence.request_body or '')}</code></pre>
                    <h4>HTTP Response (Status: {f.evidence.response_status}, Time: {f.evidence.response_time_ms}ms)</h4>
                    <pre><code>{html.escape(f.evidence.response_snippet)}</code></pre>
                </div>
                """

            cards_html.append(f"""
            <div class="finding-card {sev_class}" data-severity="{sev_class}">
                <div class="finding-header" onclick="toggleDetails('{idx}')">
                    <span class="badge {sev_class}">{f.severity.value}</span>
                    <span class="title">{html.escape(f.title)}</span>
                    <span class="cwe">{html.escape(f.cwe_id)} (CVSS {f.cvss_score})</span>
                    <span class="expand-icon" id="icon-{idx}">▼</span>
                </div>
                <div class="finding-body" id="body-{idx}">
                    <p><strong>Target:</strong> <code>{html.escape(f.target_url)}</code></p>
                    <p><strong>Parameter:</strong> <code>{html.escape(f.parameter or 'N/A')}</code> ({f.parameter_type.value if f.parameter_type else 'N/A'})</p>
                    <p><strong>Payload:</strong> <code class="payload">{html.escape(f.payload)}</code></p>
                    <p><strong>Description:</strong> {html.escape(f.description)}</p>
                    <div class="remediation-box">
                        <strong>🛡️ Recommended Remediation:</strong>
                        <p>{html.escape(f.remediation)}</p>
                    </div>
                    {evidence_block}
                </div>
            </div>
            """)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
    <title>InjeXion Audit Report - {html.escape(metadata.target)}</title>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #121826;
            --bg-card: #1a2236;
            --text-primary: #f0f4f8;
            --text-secondary: #9ba3af;
            --border: #28334e;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #10b981;
            --accent: #6366f1;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding: 24px;
            line-height: 1.5;
        }}
        .header {{
            background: linear-gradient(135deg, #1e1b4b 0%, #172554 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 24px;
        }}
        .header h1 {{ font-size: 28px; margin-bottom: 8px; color: #fff; }}
        .header p {{ color: var(--text-secondary); font-size: 14px; }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        .kpi-card .num {{ font-size: 32px; font-weight: bold; margin-bottom: 4px; }}
        .kpi-card.critical .num {{ color: var(--critical); }}
        .kpi-card.high .num {{ color: var(--high); }}
        .kpi-card.medium .num {{ color: var(--medium); }}
        .kpi-card.low .num {{ color: var(--low); }}
        .kpi-card.total .num {{ color: var(--accent); }}
        .filter-bar {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: var(--bg-secondary);
            color: var(--text-primary);
            border: 1px solid var(--border);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
        }}
        .filter-btn.active {{ background: var(--accent); border-color: var(--accent); }}
        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-left: 4px solid var(--accent);
            border-radius: 8px;
            margin-bottom: 12px;
            overflow: hidden;
        }}
        .finding-card.critical {{ border-left-color: var(--critical); }}
        .finding-card.high {{ border-left-color: var(--high); }}
        .finding-card.medium {{ border-left-color: var(--medium); }}
        .finding-card.low {{ border-left-color: var(--low); }}
        .finding-header {{
            padding: 16px 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            cursor: pointer;
            user-select: none;
        }}
        .finding-header .title {{ font-weight: 600; flex: 1; }}
        .finding-header .cwe {{ font-size: 12px; color: var(--text-secondary); }}
        .finding-header .expand-icon {{ font-size: 12px; color: var(--text-secondary); transition: transform 0.2s; }}
        .finding-body {{
            padding: 0 20px 20px 20px;
            display: none;
            border-top: 1px solid var(--border);
            padding-top: 16px;
        }}
        .finding-body p {{ margin-bottom: 10px; font-size: 14px; }}
        code {{
            background: #0f172a;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 13px;
            color: #38bdf8;
        }}
        code.payload {{ color: #f43f5e; font-weight: bold; }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge.critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); }}
        .badge.high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); }}
        .badge.medium {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); }}
        .badge.low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); }}
        .remediation-box {{
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-radius: 6px;
            padding: 12px;
            margin: 12px 0;
            color: #e0e7ff;
        }}
        .evidence-box {{
            background: #090d16;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 12px;
            margin-top: 12px;
        }}
        .evidence-box h4 {{ font-size: 12px; color: var(--text-secondary); margin-bottom: 6px; text-transform: uppercase; }}
        .evidence-box pre {{ overflow-x: auto; font-size: 12px; color: #a5b4fc; max-height: 250px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ InjeXion Security Audit Report</h1>
        <p>Target: <strong>{html.escape(metadata.target)}</strong> | Profile: {metadata.profile} | Generated: {metadata.start_time} | InjeXion v{metadata.tool_version}</p>
    </div>

    <div class="kpi-grid">
        <div class="kpi-card total">
            <div class="num">{len(findings)}</div>
            <div class="lbl">Total Findings</div>
        </div>
        <div class="kpi-card critical">
            <div class="num">{critical_count}</div>
            <div class="lbl">Critical</div>
        </div>
        <div class="kpi-card high">
            <div class="num">{high_count}</div>
            <div class="lbl">High</div>
        </div>
        <div class="kpi-card medium">
            <div class="num">{medium_count}</div>
            <div class="lbl">Medium</div>
        </div>
        <div class="kpi-card low">
            <div class="num">{low_count}</div>
            <div class="lbl">Low / Info</div>
        </div>
    </div>

    <div class="filter-bar">
        <button class="filter-btn active" onclick="filterFindings('all', this)">All ({len(findings)})</button>
        <button class="filter-btn" onclick="filterFindings('critical', this)">Critical ({critical_count})</button>
        <button class="filter-btn" onclick="filterFindings('high', this)">High ({high_count})</button>
        <button class="filter-btn" onclick="filterFindings('medium', this)">Medium ({medium_count})</button>
        <button class="filter-btn" onclick="filterFindings('low', this)">Low ({low_count})</button>
    </div>

    <div class="findings-list">
        {''.join(cards_html) if cards_html else '<p style="text-align:center;color:var(--text-secondary);padding:40px;">No vulnerabilities detected on target.</p>'}
    </div>

    <script>
        function toggleDetails(idx) {{
            const body = document.getElementById('body-' + idx);
            const icon = document.getElementById('icon-' + idx);
            if (body.style.display === 'block') {{
                body.style.display = 'none';
                icon.textContent = '▼';
            }} else {{
                body.style.display = 'block';
                icon.textContent = '▲';
            }}
        }}

        function filterFindings(sev, btn) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.finding-card').forEach(card => {{
                if (sev === 'all' || card.getAttribute('data-severity') === sev) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""

        with open(output_path, "w", encoding="utf-8") as out:
            out.write(html_template)

        return output_path

