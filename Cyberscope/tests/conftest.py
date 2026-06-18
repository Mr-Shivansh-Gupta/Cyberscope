"""Pytest configuration and shared fixtures."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from io import StringIO
from scanner import Scanner
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability, VulnerabilityType, Severity


@pytest.fixture
def mock_session():
    """Mock requests session."""
    session = MagicMock()
    return session


@pytest.fixture
def sample_html():
    """Sample HTML for testing."""
    return """
    <html>
    <head><title>Test</title></head>
    <body>
        <h1>Test Page</h1>
        <a href="/page1">Link 1</a>
        <a href="/page2">Link 2</a>
        <form action="/login" method="post">
            <input name="username" type="text">
            <input name="password" type="password">
            <input name="csrf_token" type="hidden" value="abc123">
            <input type="submit" value="Login">
        </form>
    </body>
    </html>
    """


@pytest.fixture
def sql_error_html():
    """HTML with SQL error."""
    return """
    <html>
    <body>
        <h1>Database Error</h1>
        <p>SQL syntax error in query</p>
    </body>
    </html>
    """


@pytest.fixture
def xss_vulnerable_html():
    """HTML reflecting XSS payload."""
    return """
    <html>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: <script>alert('XSS')</script></p>
    </body>
    </html>
    """


@pytest.fixture
def scanner():
    """Create a Scanner instance for testing."""
    return Scanner("http://example.com", timeout=5)


@pytest.fixture
def scan_result():
    """Create a ScanResult instance."""
    result = ScanResult("http://example.com")
    result.endpoints_discovered = 5
    result.endpoints_scanned = 5
    return result


@pytest.fixture
def sample_vulnerability():
    """Create a sample Vulnerability instance."""
    return Vulnerability(
        vuln_type=VulnerabilityType.XSS,
        url="http://example.com/search?q=test",
        payload="<script>alert('XSS')</script>",
        severity=Severity.HIGH,
        method="GET",
        parameter="q",
        response_code=200
    )


@pytest.fixture
def mock_requests_get(monkeypatch):
    """Mock requests.get."""
    def mock_get(url, *args, **kwargs):
        response = Mock()
        response.status_code = 200
        response.content = b"<html><body>Test</body></html>"
        response.text = "<html><body>Test</body></html>"
        return response
    
    return monkeypatch.setattr("requests.get", mock_get)


@pytest.fixture
def mock_requests_post(monkeypatch):
    """Mock requests.post."""
    def mock_post(url, *args, **kwargs):
        response = Mock()
        response.status_code = 200
        response.content = b"<html><body>Success</body></html>"
        return response
    
    return monkeypatch.setattr("requests.post", mock_post)
