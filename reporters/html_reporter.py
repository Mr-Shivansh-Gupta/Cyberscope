"""HTML report generator for Cyberscope."""

from typing import Optional
from datetime import datetime
from html import escape
from .base import BaseReporter
from models.scan_result import ScanResult
from models.vulnerability import Severity


class HTMLReporter(BaseReporter):
    """Generate professional HTML format vulnerability reports."""
    
    def __init__(
        self,
        scan_result: ScanResult,
        output_file: Optional[str] = None
    ) -> None:
        """
        Initialize HTML reporter.
        
        Args:
            scan_result: ScanResult object
            output_file: Optional output file path
        """
        super().__init__(scan_result, output_file)
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity level."""
        colors = {
            Severity.CRITICAL: "#dc3545",
            Severity.HIGH: "#fd7e14",
            Severity.MEDIUM: "#ffc107",
            Severity.LOW: "#20c997",
            Severity.INFO: "#17a2b8",
        }
        return colors.get(severity, "#6c757d")
    
    def _get_severity_badge(self, severity: str) -> str:
        """Get HTML badge for severity."""
        color = self._get_severity_color(severity)
        safe_severity = escape(severity.upper())
        return f'<span style="background-color: {color}; color: white; padding: 5px 10px; border-radius: 3px; font-weight: bold;">{safe_severity}</span>'
    
    def generate(self) -> str:
        """
        Generate professional HTML report.
        
        Returns:
            HTML string
        """
        summary = self.get_summary_stats()
        severity_dist = summary['severity_distribution']
        target = escape(str(summary["target"]))
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyberscope Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}
        
        .summary-card h3 {{
            color: #667eea;
            margin-bottom: 10px;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        
        .severity-chart {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 10px;
            margin-bottom: 30px;
        }}
        
        .severity-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            border-top: 3px solid #6c757d;
        }}
        
        .severity-item.critical {{ border-top-color: #dc3545; }}
        .severity-item.high {{ border-top-color: #fd7e14; }}
        .severity-item.medium {{ border-top-color: #ffc107; }}
        .severity-item.low {{ border-top-color: #20c997; }}
        .severity-item.info {{ border-top-color: #17a2b8; }}
        
        .severity-item strong {{
            display: block;
            font-size: 1.8em;
            margin-bottom: 5px;
        }}
        
        .section {{
            margin-bottom: 30px;
        }}
        
        .section h2 {{
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
            color: #333;
        }}
        
        table {{
            width: 100%;
            background: white;
            border-collapse: collapse;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        table thead {{
            background: #f8f9fa;
            border-bottom: 2px solid #dee2e6;
        }}
        
        table th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #333;
            text-transform: uppercase;
            font-size: 0.85em;
        }}
        
        table td {{
            padding: 12px 15px;
            border-bottom: 1px solid #dee2e6;
        }}
        
        table tbody tr:hover {{
            background: #f8f9fa;
        }}
        
        .vulnerability-row {{
            display: flex;
            flex-direction: column;
        }}
        
        .vuln-url {{
            color: #667eea;
            word-break: break-all;
            font-family: monospace;
            font-size: 0.9em;
        }}
        
        .vuln-payload {{
            background: #f8f9fa;
            padding: 8px;
            border-radius: 3px;
            font-family: monospace;
            font-size: 0.85em;
            margin-top: 5px;
            word-break: break-all;
            max-width: 400px;
            overflow: auto;
        }}

        .analysis-block {{
            margin-top: 8px;
            max-width: 520px;
        }}

        .analysis-block strong {{
            color: #495057;
        }}

        .analysis-block p {{
            margin: 4px 0;
            font-size: 0.9em;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        
        .badge-critical {{
            background: #dc3545;
            color: white;
        }}
        
        .badge-high {{
            background: #fd7e14;
            color: white;
        }}
        
        .badge-medium {{
            background: #ffc107;
            color: black;
        }}
        
        .badge-low {{
            background: #20c997;
            color: white;
        }}
        
        .badge-info {{
            background: #17a2b8;
            color: white;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #dee2e6;
            margin-top: 30px;
        }}
        
        .risk-score {{
            font-size: 3em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .no-vulnerabilities {{
            background: #d4edda;
            color: #155724;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔍 Cyberscope Vulnerability Report</h1>
            <p>Professional Web Security Assessment</p>
        </div>
        
        <!-- Summary Cards -->
        <div class="summary">
            <div class="summary-card">
                <h3>Target URL</h3>
                <div class="value" style="font-size: 1em; word-break: break-all;">{target}</div>
            </div>
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{summary['total_vulnerabilities']}</div>
            </div>
            <div class="summary-card">
                <h3>Risk Score</h3>
                <div class="risk-score">{summary['risk_score']}/100</div>
            </div>
            <div class="summary-card">
                <h3>Scan Duration</h3>
                <div class="value">{summary['scan_duration']}</div>
            </div>
        </div>
        
        <!-- Severity Distribution -->
        <div class="section">
            <h2>Severity Distribution</h2>
            <div class="severity-chart">
                <div class="severity-item critical">
                    <strong>{severity_dist.get('critical', 0)}</strong>
                    Critical
                </div>
                <div class="severity-item high">
                    <strong>{severity_dist.get('high', 0)}</strong>
                    High
                </div>
                <div class="severity-item medium">
                    <strong>{severity_dist.get('medium', 0)}</strong>
                    Medium
                </div>
                <div class="severity-item low">
                    <strong>{severity_dist.get('low', 0)}</strong>
                    Low
                </div>
                <div class="severity-item info">
                    <strong>{severity_dist.get('info', 0)}</strong>
                    Info
                </div>
            </div>
        </div>
        
        <!-- Vulnerabilities Table -->
        <div class="section">
            <h2>Discovered Vulnerabilities</h2>
"""
        
        if self.scan_result.vulnerabilities:
            html += """
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>URL</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            for idx, vuln in enumerate(
                self.scan_result.get_prioritized_vulnerabilities(),
                1,
            ):
                severity_badge = self._get_severity_badge(vuln.severity)
                vuln_type = escape(str(vuln.vuln_type))
                vuln_url = escape(str(vuln.url))
                method = escape(str(vuln.method))
                parameter = escape(str(vuln.parameter)) if vuln.parameter else ""
                payload = escape(str(vuln.payload[:100]))
                confidence = escape(str(vuln.confidence).upper())
                impact = escape(str(vuln.impact or vuln.get_impact()))
                remediation = escape(str(vuln.remediation or vuln.get_remediation()))
                evidence = escape(vuln.get_evidence_summary())
                html += f"""
                    <tr>
                        <td>#{idx}</td>
                        <td>{severity_badge}</td>
                        <td>{vuln_type}</td>
                        <td class="vuln-url">{vuln_url}</td>
                        <td>
                            <div class="vulnerability-row">
                                <span><strong>Method:</strong> {method}</span>
"""
                
                if vuln.parameter:
                    html += f"<span><strong>Parameter:</strong> {parameter}</span>\n"
                
                html += f"""
                                <div class="vuln-payload"><strong>Payload:</strong> {payload}</div>
                                <div class="analysis-block">
                                    <p><strong>Confidence:</strong> {confidence}</p>
                                    <p><strong>Impact:</strong> {impact}</p>
                                    <p><strong>Evidence:</strong> {evidence}</p>
                                    <p><strong>Fix:</strong> {remediation}</p>
                                </div>
                            </div>
                        </td>
                    </tr>
"""
            
            html += """
                </tbody>
            </table>
"""
        else:
            html += """
            <div class="no-vulnerabilities">
                ✓ No vulnerabilities discovered
            </div>
"""
        
        html += f"""
        </div>
        
        <!-- Scan Details -->
        <div class="section">
            <h2>Scan Information</h2>
            <table>
                <tr>
                    <td><strong>Start Time:</strong></td>
                    <td>{self.scan_result.start_time.isoformat()}</td>
                </tr>
                <tr>
                    <td><strong>End Time:</strong></td>
                    <td>{self.scan_result.end_time.isoformat() if self.scan_result.end_time else 'N/A'}</td>
                </tr>
                <tr>
                    <td><strong>Endpoints Discovered:</strong></td>
                    <td>{summary['endpoints_discovered']}</td>
                </tr>
                <tr>
                    <td><strong>Endpoints Scanned:</strong></td>
                    <td>{summary['endpoints_scanned']}</td>
                </tr>
                <tr>
                    <td><strong>Tool:</strong></td>
                    <td>Cyberscope v2.0.0</td>
                </tr>
            </table>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by Cyberscope on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>For security assessment purposes only</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
