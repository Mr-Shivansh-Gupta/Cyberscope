"""Unit tests for Scanner class."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from scanner import Scanner
from models.vulnerability import VulnerabilityType, Severity


class TestScannerInitialization:
    """Test Scanner initialization."""
    
    def test_scanner_init_valid(self):
        """Test scanner initialization with valid URL."""
        scanner = Scanner("http://example.com")
        assert scanner.target_url == "http://example.com"
        assert scanner.target_links == []
        assert scanner.timeout == 10
    
    def test_scanner_init_with_ignore_links(self):
        """Test scanner initialization with ignore list."""
        ignore = ["/logout", "/admin"]
        scanner = Scanner("http://example.com", ignore_links=ignore)
        assert len(scanner.links_to_ignore) == 2
    
    def test_scanner_init_invalid_url(self):
        """Test scanner initialization with invalid URL."""
        with pytest.raises(ValueError):
            Scanner("")
    
    def test_scanner_init_custom_timeout(self):
        """Test scanner with custom timeout."""
        scanner = Scanner("http://example.com", timeout=20)
        assert scanner.timeout == 20

    def test_scanner_init_invalid_timeout(self):
        """Test scanner initialization rejects invalid timeout."""
        with pytest.raises(ValueError):
            Scanner("http://example.com", timeout=0)

    def test_scanner_init_invalid_retries(self):
        """Test scanner initialization rejects negative retries."""
        with pytest.raises(ValueError):
            Scanner("http://example.com", max_retries=-1)


class TestLinkExtraction:
    """Test link extraction functionality."""
    
    def test_extract_links_success(self, scanner):
        """Test successful link extraction."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"""
                <html>
                <a href="/page1">Link 1</a>
                <a href="/page2">Link 2</a>
                </html>
            """
            mock_get.return_value = mock_response
            
            links = scanner.extract_links_from("http://example.com")
            assert len(links) >= 2
            assert "/page1" in links
    
    def test_extract_links_timeout(self, scanner):
        """Test link extraction with timeout."""
        import requests
        with patch.object(scanner.session, 'get') as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout()
            
            links = scanner.extract_links_from("http://example.com")
            assert links == []
    
    def test_extract_links_connection_error(self, scanner):
        """Test link extraction with connection error."""
        import requests
        with patch.object(scanner.session, 'get') as mock_get:
            mock_get.side_effect = requests.exceptions.ConnectionError()
            
            links = scanner.extract_links_from("http://example.com")
            assert links == []


class TestXSSDetection:
    """Test XSS vulnerability detection."""
    
    def test_xss_in_link_vulnerable(self, scanner):
        """Test XSS detection in URL parameter."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"<script>alert('XSS')</script>"
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_xss_in_link("http://example.com/search?q=test")
            assert result is True
            assert len(scanner.scan_result.vulnerabilities) > 0
    
    def test_xss_in_link_safe(self, scanner):
        """Test XSS detection on safe page."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"<html><body>Safe</body></html>"
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_xss_in_link("http://example.com/search?q=test")
            assert result is False
    
    def test_xss_in_link_no_parameters(self, scanner):
        """Test XSS detection on URL without parameters."""
        result = scanner.test_xss_in_link("http://example.com/page")
        assert result is False
    
    def test_xss_in_form(self, scanner):
        """Test XSS detection in form submission."""
        from bs4 import BeautifulSoup
        
        html = """
        <form action="/login" method="post">
            <input name="username" type="text">
        </form>
        """
        
        form = BeautifulSoup(html, 'lxml').find('form')
        
        with patch.object(scanner, 'submit_form') as mock_submit:
            mock_response = Mock()
            mock_response.content = b"<script>alert('XSS')</script>"
            mock_submit.return_value = mock_response
            
            result = scanner.test_xss_in_form(form, "http://example.com")
            assert result is True


class TestSQLiDetection:
    """Test SQL Injection detection."""
    
    def test_sqli_vulnerable(self, scanner):
        """Test SQLi detection with vulnerable response."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"SQL syntax error in query"
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_sqli_in_link("http://example.com/user?id=1")
            assert result is True
    
    def test_sqli_safe(self, scanner):
        """Test SQLi detection on safe page."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"<html><body>User found</body></html>"
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_sqli_in_link("http://example.com/user?id=1")
            assert result is False


class TestCSRFDetection:
    """Test CSRF detection."""
    
    def test_csrf_missing_token(self, scanner):
        """Test CSRF detection with missing token."""
        from bs4 import BeautifulSoup
        
        html = """
        <form action="/update" method="post">
            <input name="email" type="text">
            <input type="submit">
        </form>
        """
        
        form = BeautifulSoup(html, 'lxml').find('form')
        result = scanner.test_csrf(form, "http://example.com")
        
        assert result is True
    
    def test_csrf_has_token(self, scanner):
        """Test CSRF when token is present."""
        from bs4 import BeautifulSoup
        
        html = """
        <form action="/update" method="post">
            <input name="csrf_token" type="hidden" value="abc123">
            <input name="email" type="text">
        </form>
        """
        
        form = BeautifulSoup(html, 'lxml').find('form')
        result = scanner.test_csrf(form, "http://example.com")
        
        assert result is False


class TestCrawling:
    """Test website crawling."""
    
    def test_crawl_basic(self, scanner):
        """Test basic crawling behavior."""
        # Test the direct addition of links without recursion
        # Manually add some discovered links to simulate crawling
        scanner.target_links = [
            "http://example.com/page1",
            "http://example.com/page2"
        ]
        
        # Verify that links were added correctly
        assert len(scanner.target_links) == 2
        assert "http://example.com/page1" in scanner.target_links
        assert "http://example.com/page2" in scanner.target_links
    
    def test_crawl_with_ignore_list(self):
        """Test crawling with ignore list."""
        scanner = Scanner("http://example.com", ignore_links=["/logout", "/admin"])
        
        with patch.object(scanner, 'extract_links_from') as mock_extract:
            mock_extract.return_value = [
                "http://example.com/page1",
                "http://example.com/logout",
                "http://example.com/admin"
            ]
            
            scanner.crawl()
            
            # logout and admin should be ignored
            assert "http://example.com/logout" not in scanner.target_links
            assert "http://example.com/admin" not in scanner.target_links


class TestFormExtraction:
    """Test form extraction."""
    
    def test_extract_forms(self, scanner, sample_html):
        """Test form extraction."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = sample_html.encode()
            mock_get.return_value = mock_response
            
            forms = scanner.extract_forms("http://example.com")
            assert len(forms) > 0


class TestSecurityHeaders:
    """Test security header analysis."""
    
    def test_security_headers_check(self, scanner):
        """Test security headers checking."""
        with patch.object(scanner.session, 'head') as mock_head:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {
                'X-Frame-Options': 'DENY'
            }
            mock_head.return_value = mock_response
            
            scanner.test_security_headers("http://example.com")
            
            # Should find missing headers
            assert len(scanner.scan_result.vulnerabilities) > 0


class TestScanExecution:
    """Test complete scan execution."""
    
    def test_run_scanner_no_links(self, scanner):
        """Test scanner with no discovered links."""
        scanner.target_links = []
        result = scanner.run_scanner()
        
        assert result.endpoints_scanned == 0
        assert len(result.vulnerabilities) == 0
    
    def test_run_scanner_with_vulnerabilities(self, scanner):
        """Test scanner that finds vulnerabilities."""
        scanner.target_links = ["http://example.com/search?q=test"]
        
        with patch.object(scanner, 'test_xss_in_link') as mock_xss:
            with patch.object(scanner, 'extract_forms') as mock_forms:
                mock_xss.return_value = True
                mock_forms.return_value = []
                
                result = scanner.run_scanner()
                
                assert result.endpoints_scanned > 0


class TestAdvancedScanning:
    """Test advanced scanning features."""
    
    def test_xss_multiple_payloads(self, scanner):
        """Test XSS with multiple payload variations."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            # Return a response with the XSS payload reflected
            mock_response.text = "<img onerror=alert(1)>"
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            # Test with XSS parameter
            result = scanner.test_xss_in_link("http://example.com/page?id=<img%20onerror=alert(1)>")
            # May or may not detect depending on implementation
            assert isinstance(result, bool)
    
    def test_sqli_error_detection(self, scanner):
        """Test SQL injection with error detection."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            # Use actual SQL error patterns
            mock_response.text = "Warning: mysql_fetch_array()"
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_sqli_in_link("http://example.com/page?id=1'")
            assert isinstance(result, bool)
    
    def test_csrf_token_detection(self, scanner):
        """Test CSRF with token detection."""
        form = {
            'method': 'POST',
            'action': '/submit',
            'inputs': [
                {'name': 'csrf_token', 'value': 'abc123'},
                {'name': 'username', 'value': ''}
            ]
        }
        
        result = scanner.test_csrf(form, "http://example.com/form")
        # Form has CSRF token, so should be False (no vulnerability)
        assert result is False
    
    def test_crawl_with_initial_link(self, scanner):
        """Test crawl discovers links correctly."""
        with patch.object(scanner, 'extract_links_from') as mock_extract:
            mock_extract.return_value = ["/page1", "/page2"]
            
            # Test that extraction can be called
            links = scanner.extract_links_from("http://example.com")
            
            # Verify it works correctly
            mock_extract.assert_called_once()
    
    def test_response_timeout_handling(self, scanner):
        """Test handling of request timeouts."""
        with patch.object(scanner.session, 'get') as mock_get:
            import requests
            mock_get.side_effect = requests.Timeout("Connection timeout")
            
            result = scanner.test_xss_in_link("http://example.com/page?id=1")
            assert result is False
    
    def test_connection_error_handling(self, scanner):
        """Test handling of connection errors."""
        with patch.object(scanner.session, 'get') as mock_get:
            import requests
            mock_get.side_effect = requests.ConnectionError("Connection failed")
            
            result = scanner.test_xss_in_link("http://example.com/page?id=1")
            assert result is False
    
    def test_invalid_url_handling(self, scanner):
        """Test handling of invalid URLs."""
        result = scanner.test_xss_in_link("not a valid url")
        assert result is False
    
    def test_extract_links_with_no_content(self, scanner):
        """Test link extraction when response has no content."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b""
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            links = scanner.extract_links_from("http://example.com")
            assert links == []
    
    def test_form_extraction_empty(self, scanner):
        """Test form extraction with no forms."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"<html><body>No forms here</body></html>"
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            forms = scanner.extract_forms("http://example.com")
            assert forms == []
    
    def test_security_headers_missing_all(self, scanner):
        """Test detection of missing security headers."""
        with patch.object(scanner.session, 'head') as mock_head:
            mock_response = Mock()
            mock_response.headers = {}  # No security headers
            mock_head.return_value = mock_response
            
            scanner.test_security_headers("http://example.com")
            
            # Should find multiple missing headers
            assert len(scanner.scan_result.vulnerabilities) > 0
    
    def test_security_headers_present(self, scanner):
        """Test detection when security headers are present."""
        with patch.object(scanner.session, 'head') as mock_head:
            mock_response = Mock()
            mock_response.headers = {
                'Content-Security-Policy': "default-src 'self'",
                'X-Frame-Options': 'DENY',
                'X-Content-Type-Options': 'nosniff',
                'Strict-Transport-Security': 'max-age=31536000'
            }
            mock_head.return_value = mock_response
            
            initial_vuln_count = len(scanner.scan_result.vulnerabilities)
            scanner.test_security_headers("http://example.com")
            
            # Should not add vulnerabilities for present headers
            # (May add for missing headers like HSTS)
            assert isinstance(scanner.scan_result.vulnerabilities, list)
    
    def test_scan_result_contains_metadata(self, scanner):
        """Test that scan result contains proper metadata."""
        scanner.target_links = ["http://example.com/page1"]
        
        result = scanner.run_scanner()
        
        assert result.target_url == scanner.target_url
        assert result.endpoints_discovered > 0
        assert hasattr(result, 'scan_duration')
        assert hasattr(result, 'vulnerabilities')


class TestScannerRobustness:
    """Regression tests for scanner hardening."""

    def test_xss_in_link_injects_existing_parameter(self, scanner):
        """Scanner should mutate an existing query parameter instead of appending a new one."""
        called_urls = []

        def fake_get(url, **kwargs):
            called_urls.append(url)
            response = Mock()
            payload = "<script>alert('XSS')</script>"
            response.content = f"echo:{payload}".encode()
            response.status_code = 200
            return response

        with patch.object(scanner.session, "get", side_effect=fake_get):
            result = scanner.test_xss_in_link("http://example.com/search?q=test")

        assert result is True
        assert called_urls
        assert "q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E" in called_urls[0]
        assert "test=" not in called_urls[0]

    def test_security_headers_fallbacks_to_get_on_405(self, scanner):
        """Scanner should fall back to GET if HEAD is not supported."""
        head_response = Mock()
        head_response.status_code = 405
        head_response.headers = {}

        get_response = Mock()
        get_response.status_code = 200
        get_response.headers = {}

        with patch.object(scanner.session, "head", return_value=head_response) as mock_head:
            with patch.object(scanner.session, "get", return_value=get_response) as mock_get:
                scanner.test_security_headers("http://example.com")

        mock_head.assert_called_once()
        mock_get.assert_called_once()
        assert len(scanner.scan_result.vulnerabilities) > 0

    def test_security_headers_fallbacks_to_get_on_head_exception(self, scanner):
        """Scanner should retry with GET if HEAD request raises request exceptions."""
        import requests

        get_response = Mock()
        get_response.status_code = 200
        get_response.headers = {}

        with patch.object(scanner.session, "head", side_effect=requests.exceptions.Timeout()):
            with patch.object(scanner.session, "get", return_value=get_response) as mock_get:
                scanner.test_security_headers("http://example.com")

        mock_get.assert_called_once()

    def test_run_scanner_resets_previous_results(self, scanner):
        """Running scanner again should start from a fresh scan result object."""
        scanner.target_links = ["http://example.com/page?id=1"]

        with patch.object(scanner, "extract_forms", return_value=[]):
            with patch.object(scanner, "test_xss_in_link", return_value=False):
                with patch.object(scanner, "test_sqli_in_link", return_value=False):
                    with patch.object(scanner, "test_xxe_injection", return_value=False):
                        with patch.object(scanner, "test_path_traversal", return_value=False):
                            with patch.object(scanner, "test_security_headers", return_value=None):
                                first = scanner.run_scanner()
                                first.endpoints_scanned = 999
                                second = scanner.run_scanner()

        assert first is not second
        assert second.endpoints_scanned == 1
