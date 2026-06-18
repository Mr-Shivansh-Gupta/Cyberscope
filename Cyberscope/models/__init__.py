"""Models package for Cyberscope data structures."""

from .vulnerability import Vulnerability, VulnerabilityType
from .scan_result import ScanResult

__all__ = [
    'Vulnerability',
    'VulnerabilityType',
    'ScanResult'
]
