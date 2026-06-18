"""CSV report generator for Cyberscope."""

import csv
from typing import Optional
from io import StringIO
from .base import BaseReporter
from models.scan_result import ScanResult


class CSVReporter(BaseReporter):
    """Generate CSV format vulnerability reports."""
    
    def __init__(
        self,
        scan_result: ScanResult,
        output_file: Optional[str] = None
    ) -> None:
        """
        Initialize CSV reporter.
        
        Args:
            scan_result: ScanResult object
            output_file: Optional output file path
        """
        super().__init__(scan_result, output_file)
    
    def generate(self) -> str:
        """
        Generate CSV report.
        
        Returns:
            CSV formatted string
        """
        output = StringIO()
        
        # Write summary section as comments
        summary = self.get_summary_stats()
        output.write("# Cyberscope Vulnerability Report (CSV Format)\n")
        output.write(f"# Target: {summary['target']}\n")
        output.write(f"# Endpoints Discovered: {summary['endpoints_discovered']}\n")
        output.write(f"# Endpoints Scanned: {summary['endpoints_scanned']}\n")
        output.write(f"# Total Vulnerabilities: {summary['total_vulnerabilities']}\n")
        output.write(f"# Scan Duration: {summary['scan_duration']}\n")
        output.write("#\n")
        
        # Write vulnerability details
        output.write(
            "ID,Type,Severity,Confidence,URL,Method,Parameter,HTTP Status,"
            "Payload,Impact,Evidence,Remediation,Timestamp\n"
        )
        
        writer = csv.writer(output)
        
        prioritized_vulnerabilities = self.scan_result.get_prioritized_vulnerabilities()

        for idx, vuln in enumerate(prioritized_vulnerabilities, 1):
            writer.writerow([
                idx,
                vuln.vuln_type,
                vuln.severity.upper(),
                vuln.confidence.upper(),
                vuln.url,
                vuln.method,
                vuln.parameter or "N/A",
                vuln.response_code or "N/A",
                vuln.payload,
                vuln.impact or vuln.get_impact(),
                vuln.get_evidence_summary(),
                vuln.remediation or vuln.get_remediation(),
                vuln.timestamp.isoformat(),
            ])
        
        return output.getvalue()
