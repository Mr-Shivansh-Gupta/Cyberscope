"""JSON report generator for Cyberscope."""

import json
from typing import Optional
from datetime import datetime
from .base import BaseReporter
from models.scan_result import ScanResult


class JSONReporter(BaseReporter):
    """Generate JSON format vulnerability reports."""
    
    def __init__(
        self,
        scan_result: ScanResult,
        output_file: Optional[str] = None,
        pretty: bool = True
    ) -> None:
        """
        Initialize JSON reporter.
        
        Args:
            scan_result: ScanResult object
            output_file: Optional output file path
            pretty: Whether to pretty-print JSON
        """
        super().__init__(scan_result, output_file)
        self.pretty: bool = pretty
    
    def generate(self) -> str:
        """
        Generate JSON report.
        
        Returns:
            JSON string
        """
        report_data = {
            "report": {
                "generated_at": datetime.now().isoformat(),
                "version": "2.0.0",
                "tool": "Cyberscope",
            },
            "scan": {
                "target_url": self.scan_result.target_url,
                "start_time": self.scan_result.start_time.isoformat(),
                "end_time": self.scan_result.end_time.isoformat() if self.scan_result.end_time else None,
                "duration_seconds": self.scan_result.scan_duration,
                "endpoints_discovered": self.scan_result.endpoints_discovered,
                "endpoints_scanned": self.scan_result.endpoints_scanned,
            },
            "summary": {
                "total_vulnerabilities": len(self.scan_result.vulnerabilities),
                "risk_score": self.scan_result.get_risk_score(),
                "severity_distribution": self.scan_result.get_severity_distribution(),
                "vulnerability_types": self.scan_result.count_by_type(),
            },
            "vulnerabilities": [
                vuln.to_dict()
                for vuln in self.scan_result.get_prioritized_vulnerabilities()
            ]
        }
        
        if self.pretty:
            return json.dumps(report_data, indent=2, default=str)
        else:
            return json.dumps(report_data, default=str)
