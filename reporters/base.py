"""Base reporter class for Cyberscope."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
from models.scan_result import ScanResult
import logging

logger = logging.getLogger(__name__)


class BaseReporter(ABC):
    """
    Abstract base class for vulnerability report generators.
    
    Subclasses must implement the generate() method to produce
    reports in specific formats.
    """
    
    def __init__(
        self,
        scan_result: ScanResult,
        output_file: Optional[str] = None
    ) -> None:
        """
        Initialize reporter.
        
        Args:
            scan_result: ScanResult object with findings
            output_file: Optional path to save report
        """
        self.scan_result: ScanResult = scan_result
        self.output_file: Optional[str] = output_file
    
    @abstractmethod
    def generate(self) -> str:
        """
        Generate report content.
        
        Returns:
            Report content as string
        """
        pass
    
    def save(self, output_file: Optional[str] = None) -> str:
        """
        Generate and save report to file.
        
        Args:
            output_file: Path to save report (overrides __init__ value)
            
        Returns:
            Path to saved file
        """
        output_path = output_file or self.output_file
        
        if not output_path:
            raise ValueError("No output file specified")
        
        try:
            content = self.generate()
            
            # Create output directory if needed
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write report
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"Report saved to {output_path}")
            print(f"[+] Report saved to {output_path}")
            
            return str(path)
            
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            raise
    
    def get_summary_stats(self) -> dict:
        """Get summary statistics for report."""
        return {
            "target": self.scan_result.target_url,
            "endpoints_discovered": self.scan_result.endpoints_discovered,
            "endpoints_scanned": self.scan_result.endpoints_scanned,
            "total_vulnerabilities": len(self.scan_result.vulnerabilities),
            "risk_score": self.scan_result.get_risk_score(),
            "scan_duration": f"{self.scan_result.scan_duration:.2f}s",
            "severity_distribution": self.scan_result.get_severity_distribution(),
            "type_distribution": self.scan_result.count_by_type(),
        }
