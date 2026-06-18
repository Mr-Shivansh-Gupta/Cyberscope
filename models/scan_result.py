"""
Scan result data model for Cyberscope.

Represents the complete results of a vulnerability scan.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from .vulnerability import Vulnerability, Severity


@dataclass
class ScanResult:
    """
    Represents the results of a complete vulnerability scan.
    
    Attributes:
        target_url: Base URL that was scanned
        start_time: When scan started
        end_time: When scan completed
        endpoints_discovered: Number of endpoints found
        endpoints_scanned: Number of endpoints scanned
        vulnerabilities: List of found vulnerabilities
        scan_duration: Duration of scan in seconds
    """
    
    target_url: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    endpoints_discovered: int = 0
    endpoints_scanned: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_duration: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """
        Add a discovered vulnerability to results.
        
        Args:
            vuln: Vulnerability instance to add
        """
        if not isinstance(vuln, Vulnerability):
            raise TypeError("Expected Vulnerability instance")
        
        self.vulnerabilities.append(vuln)
    
    def get_vulnerabilities_by_type(self, vuln_type: str) -> List[Vulnerability]:
        """
        Get vulnerabilities filtered by type.
        
        Args:
            vuln_type: Type of vulnerability to filter by
            
        Returns:
            List of vulnerabilities of specified type
        """
        return [v for v in self.vulnerabilities if v.vuln_type == vuln_type]
    
    def get_vulnerabilities_by_severity(self, severity: str) -> List[Vulnerability]:
        """
        Get vulnerabilities filtered by severity.
        
        Args:
            severity: Severity level to filter by
            
        Returns:
            List of vulnerabilities with specified severity
        """
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_critical_vulnerabilities(self) -> List[Vulnerability]:
        """Get all critical vulnerabilities."""
        return self.get_vulnerabilities_by_severity(Severity.CRITICAL)
    
    def get_high_vulnerabilities(self) -> List[Vulnerability]:
        """Get all high severity vulnerabilities."""
        return self.get_vulnerabilities_by_severity(Severity.HIGH)
    
    def get_medium_vulnerabilities(self) -> List[Vulnerability]:
        """Get all medium severity vulnerabilities."""
        return self.get_vulnerabilities_by_severity(Severity.MEDIUM)
    
    def get_low_vulnerabilities(self) -> List[Vulnerability]:
        """Get all low severity vulnerabilities."""
        return self.get_vulnerabilities_by_severity(Severity.LOW)
    
    def get_info_vulnerabilities(self) -> List[Vulnerability]:
        """Get all info level vulnerabilities."""
        return self.get_vulnerabilities_by_severity(Severity.INFO)

    def get_prioritized_vulnerabilities(self) -> List[Vulnerability]:
        """
        Get vulnerabilities ordered by practical risk.

        Returns:
            List of vulnerabilities sorted by severity score and confidence
        """
        confidence_weight = {"high": 1.0, "medium": 0.85, "low": 0.65}

        return sorted(
            self.vulnerabilities,
            key=lambda vuln: (
                vuln.severity_score * confidence_weight.get(vuln.confidence, 0.85),
                vuln.timestamp,
            ),
            reverse=True,
        )

    def get_risk_score(self) -> int:
        """
        Calculate a capped 0-100 risk score from severity and confidence.

        Returns:
            int: Risk score between 0 and 100
        """
        confidence_weight = {"high": 1.0, "medium": 0.85, "low": 0.65}
        score = sum(
            vuln.severity_score * 10 * confidence_weight.get(vuln.confidence, 0.85)
            for vuln in self.vulnerabilities
        )
        return min(100, round(score))
    
    def count_by_type(self) -> Dict[str, int]:
        """
        Count vulnerabilities by type.
        
        Returns:
            Dictionary with vulnerability types as keys and counts as values
        """
        counts: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            counts[vuln.vuln_type] = counts.get(vuln.vuln_type, 0) + 1
        return counts
    
    def count_by_severity(self) -> Dict[str, int]:
        """
        Count vulnerabilities by severity.
        
        Returns:
            Dictionary with severity levels as keys and counts as values
        """
        counts: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
        return counts
    
    def get_severity_distribution(self) -> Dict[str, int]:
        """
        Get vulnerability count by severity level.
        
        Returns:
            Dictionary with severity distribution
        """
        return {
            Severity.CRITICAL: len(self.get_critical_vulnerabilities()),
            Severity.HIGH: len(self.get_high_vulnerabilities()),
            Severity.MEDIUM: len(self.get_medium_vulnerabilities()),
            Severity.LOW: len(self.get_low_vulnerabilities()),
            Severity.INFO: len(self.get_info_vulnerabilities()),
        }
    
    def get_summary(self) -> str:
        """
        Get human-readable summary of results.
        
        Returns:
            String summary of scan results
        """
        critical = len(self.get_critical_vulnerabilities())
        high = len(self.get_high_vulnerabilities())
        medium = len(self.get_medium_vulnerabilities())
        low = len(self.get_low_vulnerabilities())
        info = len(self.get_info_vulnerabilities())
        
        summary = f"""
SCAN SUMMARY
============
Target: {self.target_url}
Endpoints Discovered: {self.endpoints_discovered}
Endpoints Scanned: {self.endpoints_scanned}
Scan Duration: {self.scan_duration:.2f}s

VULNERABILITY SUMMARY
=====================
Critical: {critical}
High: {high}
Medium: {medium}
Low: {low}
Info: {info}
---
Total: {len(self.vulnerabilities)}

BREAKDOWN BY TYPE
=================
"""
        
        for vuln_type, count in self.count_by_type().items():
            summary += f"{vuln_type}: {count}\n"
        
        return summary
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert scan results to dictionary.
        
        Returns:
            Dictionary representation of results
        """
        return {
            "target_url": self.target_url,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "scan_duration": self.scan_duration,
            "risk_score": self.get_risk_score(),
            "endpoints_discovered": self.endpoints_discovered,
            "endpoints_scanned": self.endpoints_scanned,
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_distribution": self.get_severity_distribution(),
            "type_distribution": self.count_by_type(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "metadata": self.metadata,
        }
    
    def __str__(self) -> str:
        """Return string representation."""
        return f"ScanResult({self.target_url}, {len(self.vulnerabilities)} vulns)"
    
    def finish(self) -> None:
        """Mark scan as complete and calculate duration."""
        self.end_time = datetime.now()
        self.scan_duration = (self.end_time - self.start_time).total_seconds()
