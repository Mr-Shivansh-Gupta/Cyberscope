"""Unit tests for data models."""

import pytest
from models.vulnerability import Vulnerability, VulnerabilityType, Severity
from models.scan_result import ScanResult
from datetime import datetime


class TestVulnerability:
    """Test Vulnerability model."""
    
    def test_vulnerability_creation(self):
        """Test vulnerability creation."""
        vuln = Vulnerability(
            vuln_type=VulnerabilityType.XSS,
            url="http://example.com/search",
            payload="<script>alert('XSS')</script>",
            severity=Severity.HIGH
        )
        
        assert vuln.vuln_type == VulnerabilityType.XSS
        assert vuln.severity == Severity.HIGH
        assert vuln.url == "http://example.com/search"
    
    def test_vulnerability_invalid_severity(self):
        """Test vulnerability with invalid severity."""
        with pytest.raises(ValueError):
            Vulnerability(
                vuln_type=VulnerabilityType.XSS,
                url="http://example.com",
                payload="test",
                severity="invalid"
            )
    
    def test_vulnerability_invalid_type(self):
        """Test vulnerability with invalid type."""
        with pytest.raises(ValueError):
            Vulnerability(
                vuln_type="INVALID",
                url="http://example.com",
                payload="test"
            )
    
    def test_vulnerability_severity_score(self):
        """Test vulnerability severity scoring."""
        vuln_critical = Vulnerability(
            VulnerabilityType.SQL_INJECTION,
            "http://example.com",
            "test",
            severity=Severity.CRITICAL
        )
        
        vuln_low = Vulnerability(
            VulnerabilityType.INSECURE_HEADERS,
            "http://example.com",
            "test",
            severity=Severity.LOW
        )
        
        assert vuln_critical.severity_score == 9.0
        assert vuln_low.severity_score == 3.0
    
    def test_vulnerability_to_dict(self):
        """Test vulnerability to_dict conversion."""
        vuln = Vulnerability(
            vuln_type=VulnerabilityType.XSS,
            url="http://example.com",
            payload="<script>alert('XSS')</script>",
            severity=Severity.HIGH,
            method="GET",
            parameter="q",
            response_code=200
        )
        
        vuln_dict = vuln.to_dict()
        
        assert vuln_dict['type'] == VulnerabilityType.XSS
        assert vuln_dict['severity'] == Severity.HIGH
        assert vuln_dict['url'] == "http://example.com"
        assert vuln_dict['method'] == "GET"
    
    def test_vulnerability_to_json(self):
        """Test vulnerability to_json conversion."""
        vuln = Vulnerability(
            vuln_type=VulnerabilityType.XSS,
            url="http://example.com",
            payload="test",
            severity=Severity.MEDIUM
        )
        
        json_str = vuln.to_json()
        assert isinstance(json_str, str)
        assert "XSS" in json_str
    
    def test_vulnerability_is_critical(self):
        """Test is_critical check."""
        vuln_critical = Vulnerability(
            VulnerabilityType.SQL_INJECTION,
            "http://example.com",
            "test",
            severity=Severity.CRITICAL
        )
        
        vuln_low = Vulnerability(
            VulnerabilityType.INSECURE_HEADERS,
            "http://example.com",
            "test",
            severity=Severity.LOW
        )
        
        assert vuln_critical.is_critical() is True
        assert vuln_low.is_critical() is False
    
    def test_vulnerability_get_remediation(self):
        """Test remediation advice."""
        vuln = Vulnerability(
            VulnerabilityType.XSS,
            "http://example.com",
            "test"
        )
        
        remediation = vuln.get_remediation()
        assert isinstance(remediation, str)
        assert len(remediation) > 0
        assert "input validation" in remediation.lower()

    def test_vulnerability_auto_analysis_fields(self):
        """Test impact, remediation, confidence, and evidence are available."""
        vuln = Vulnerability(
            VulnerabilityType.SQL_INJECTION,
            "http://example.com/user",
            "' OR '1'='1",
            severity=Severity.CRITICAL,
            parameter="id",
            response_code=500,
            metadata={"matched_pattern": "SQL syntax"},
        )

        vuln_dict = vuln.to_dict()

        assert vuln.confidence == "medium"
        assert "database" in vuln.impact.lower()
        assert "parameterized" in vuln.remediation.lower()
        assert "SQL syntax" in vuln.get_evidence_summary()
        assert vuln_dict["impact"] == vuln.impact
        assert vuln_dict["confidence"] == "medium"
        assert "evidence" in vuln_dict

    def test_vulnerability_invalid_confidence(self):
        """Test invalid confidence values are rejected."""
        with pytest.raises(ValueError):
            Vulnerability(
                VulnerabilityType.XSS,
                "http://example.com",
                "test",
                confidence="certain",
            )


class TestScanResult:
    """Test ScanResult model."""
    
    def test_scan_result_creation(self):
        """Test scan result creation."""
        result = ScanResult("http://example.com")
        
        assert result.target_url == "http://example.com"
        assert len(result.vulnerabilities) == 0
    
    def test_add_vulnerability(self):
        """Test adding vulnerability to result."""
        result = ScanResult("http://example.com")
        vuln = Vulnerability(
            VulnerabilityType.XSS,
            "http://example.com",
            "test"
        )
        
        result.add_vulnerability(vuln)
        
        assert len(result.vulnerabilities) == 1
    
    def test_add_invalid_vulnerability(self):
        """Test adding invalid vulnerability."""
        result = ScanResult("http://example.com")
        
        with pytest.raises(TypeError):
            result.add_vulnerability("not a vulnerability")
    
    def test_get_vulnerabilities_by_type(self):
        """Test filtering by type."""
        result = ScanResult("http://example.com")
        
        xss_vuln = Vulnerability(VulnerabilityType.XSS, "http://example.com", "test")
        sqli_vuln = Vulnerability(VulnerabilityType.SQL_INJECTION, "http://example.com", "test")
        
        result.add_vulnerability(xss_vuln)
        result.add_vulnerability(sqli_vuln)
        
        xss_vulns = result.get_vulnerabilities_by_type(VulnerabilityType.XSS)
        assert len(xss_vulns) == 1
    
    def test_get_vulnerabilities_by_severity(self):
        """Test filtering by severity."""
        result = ScanResult("http://example.com")
        
        critical_vuln = Vulnerability(
            VulnerabilityType.SQL_INJECTION,
            "http://example.com",
            "test",
            severity=Severity.CRITICAL
        )
        low_vuln = Vulnerability(
            VulnerabilityType.INSECURE_HEADERS,
            "http://example.com",
            "test",
            severity=Severity.LOW
        )
        
        result.add_vulnerability(critical_vuln)
        result.add_vulnerability(low_vuln)
        
        critical_vulns = result.get_critical_vulnerabilities()
        assert len(critical_vulns) == 1
    
    def test_count_by_type(self):
        """Test counting vulnerabilities by type."""
        result = ScanResult("http://example.com")
        
        result.add_vulnerability(Vulnerability(VulnerabilityType.XSS, "http://example.com", "test"))
        result.add_vulnerability(Vulnerability(VulnerabilityType.XSS, "http://example.com", "test"))
        result.add_vulnerability(Vulnerability(VulnerabilityType.SQL_INJECTION, "http://example.com", "test"))
        
        counts = result.count_by_type()
        
        assert counts[VulnerabilityType.XSS] == 2
        assert counts[VulnerabilityType.SQL_INJECTION] == 1
    
    def test_count_by_severity(self):
        """Test counting vulnerabilities by severity."""
        result = ScanResult("http://example.com")
        
        result.add_vulnerability(Vulnerability(
            VulnerabilityType.XSS,
            "http://example.com",
            "test",
            severity=Severity.HIGH
        ))
        result.add_vulnerability(Vulnerability(
            VulnerabilityType.XSS,
            "http://example.com",
            "test",
            severity=Severity.HIGH
        ))
        
        counts = result.count_by_severity()
        
        assert counts[Severity.HIGH] == 2
    
    def test_get_summary(self):
        """Test getting summary."""
        result = ScanResult("http://example.com")
        result.endpoints_discovered = 10
        result.endpoints_scanned = 10
        
        result.add_vulnerability(Vulnerability(
            VulnerabilityType.XSS,
            "http://example.com",
            "test",
            severity=Severity.HIGH
        ))
        
        summary = result.get_summary()
        
        assert "http://example.com" in summary
        assert "10" in summary
        assert "XSS" in summary
    
    def test_scan_result_finish(self):
        """Test marking scan complete."""
        result = ScanResult("http://example.com")
        
        result.finish()
        
        assert result.end_time is not None
        assert result.scan_duration > 0
    
    def test_scan_result_to_dict(self):
        """Test scan result to_dict."""
        result = ScanResult("http://example.com")
        result.endpoints_discovered = 5
        result.endpoints_scanned = 5
        result.add_vulnerability(Vulnerability(
            VulnerabilityType.XSS,
            "http://example.com",
            "test"
        ))
        
        result_dict = result.to_dict()
        
        assert result_dict['target_url'] == "http://example.com"
        assert result_dict['total_vulnerabilities'] == 1
        assert 'risk_score' in result_dict
        assert 'vulnerabilities' in result_dict

    def test_scan_result_risk_score_and_prioritization(self):
        """Test risk scoring and prioritized vulnerability ordering."""
        result = ScanResult("http://example.com")
        low_vuln = Vulnerability(
            VulnerabilityType.INSECURE_HEADERS,
            "http://example.com",
            "Missing X-Frame-Options",
            severity=Severity.LOW,
            confidence="high",
        )
        critical_vuln = Vulnerability(
            VulnerabilityType.SQL_INJECTION,
            "http://example.com/user",
            "' OR '1'='1",
            severity=Severity.CRITICAL,
            confidence="high",
        )

        result.add_vulnerability(low_vuln)
        result.add_vulnerability(critical_vuln)

        prioritized = result.get_prioritized_vulnerabilities()

        assert result.get_risk_score() > 0
        assert prioritized[0] == critical_vuln
