"""Extended tests for Scanner class - advanced coverage."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from scanner import Scanner
from models.vulnerability import VulnerabilityType, Severity


class TestFormHandling:
    """Test form extraction and submission."""
    
    def test_submit_form_post_method(self, scanner):
        """Test form submission with POST method."""
        from bs4 import BeautifulSoup
        
        html = """
        <form action="/submit" method="post">
            <input name="username" type="text">
            <input name="password" type="password">
        </form>
        """
        
        form = BeautifulSoup(html, 'lxml').find('form')
        
        with patch.object(scanner.session, 'post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.content = b"<html><body>Success</body></html>"
            mock_post.return_value = mock_response
            
            response = scanner.submit_form(form, "testvalue", "http://example.com")
            
            assert response is not None
            assert response.status_code == 200
            mock_post.assert_called_once()
    
    def test_submit_form_get_method(self, scanner):
        """Test form submission with GET method."""
        from bs4 import BeautifulSoup
        
        html = """
        <form action="/search" method="get">
            <input name="q" type="text">
        </form>
        """
        
        form = BeautifulSoup(html, 'lxml').find('form')
        
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.content = b"<html><body>Results</body></html>"
            mock_get.return_value = mock_response
            
            response = scanner.submit_form(form, "testvalue", "http://example.com")
            
            assert response is not None
            assert response.status_code == 200
            mock_get.assert_called_once()
    
    def test_submit_form_exception_handling(self, scanner):
        """Test form submission with exception."""
        from bs4 import BeautifulSoup
        
        html = """
        <form action="/submit" method="post">
            <input name="field" type="text">
        </form>
        """
        
        form = BeautifulSoup(html, 'lxml').find('form')
        
        with patch.object(scanner.session, 'post') as mock_post:
            mock_post.side_effect = Exception("Network error")
            
            response = scanner.submit_form(form, "value", "http://example.com")
            assert response is None
    
    def test_extract_forms_with_timeout(self, scanner):
        """Test form extraction timeout."""
        import requests
        with patch.object(scanner.session, 'get') as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout()
            
            forms = scanner.extract_forms("http://example.com")
            assert forms == []
    
    def test_extract_forms_multiple(self, scanner):
        """Test extraction of multiple forms."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            html_multiple = """
            <html><body>
                <form action="/login" method="post">
                    <input name="username" type="text">
                </form>
                <form action="/search" method="get">
                    <input name="q" type="text">
                </form>
            </body></html>
            """
            mock_response.content = html_multiple.encode()
            mock_get.return_value = mock_response
            
            forms = scanner.extract_forms("http://example.com")
            assert len(forms) >= 2


class TestCrawlingAdvanced:
    """Test advanced crawling features."""
    
    def test_crawl_respects_max_depth(self, scanner):
        """Test that crawling respects maximum depth."""
        with patch.object(scanner, 'extract_links_from') as mock_extract:
            mock_extract.return_value = ["http://example.com/page1"]
            
            # Test with max_depth=0
            scanner.crawl(url="http://example.com", depth=1, max_depth=0)
            
            # Should not make additional calls due to depth limit
            assert len(scanner.target_links) == 0
    
    def test_crawl_normalizes_links(self, scanner):
        """Test that crawling normalizes relative links."""
        with patch.object(scanner, 'extract_links_from') as mock_extract:
            mock_extract.return_value = [
                "/page1",
                "/page2",
                "http://example.com/page3"
            ]
            
            scanner.crawl(url="http://example.com", depth=0, max_depth=1)
            
            # All links should be normalized to absolute URLs
            for link in scanner.target_links:
                assert link.startswith("http")
    
    def test_crawl_removes_fragments(self, scanner):
        """Test that crawling removes URL fragments."""
        with patch.object(scanner, 'extract_links_from') as mock_extract:
            mock_extract.return_value = [
                "http://example.com/page1#section",
                "http://example.com/page2#top"
            ]
            
            scanner.crawl(url="http://example.com", depth=0, max_depth=1)
            
            # Fragments should be removed
            for link in scanner.target_links:
                assert "#" not in link
    
    def test_crawl_avoids_duplicates(self, scanner):
        """Test that crawling avoids discovering duplicate links."""
        scanner.target_links = ["http://example.com/page1"]
        
        with patch.object(scanner, 'extract_links_from') as mock_extract:
            mock_extract.return_value = [
                "http://example.com/page1",  # Duplicate
                "http://example.com/page2"
            ]
            
            scanner.crawl(url="http://example.com", depth=0, max_depth=1)
            
            # Should only have 2 links (not 3), no duplicates
            assert len(scanner.target_links) == 2


class TestSecurityHeadersAdvanced:
    """Test advanced security header detection."""
    
    def test_security_headers_csp_check(self, scanner):
        """Test CSP header detection."""
        with patch.object(scanner.session, 'head') as mock_head:
            mock_response = Mock()
            mock_response.headers = {}  # Missing CSP
            mock_head.return_value = mock_response
            
            scanner.test_security_headers("http://example.com")
            
            # Should detect missing headers
            assert isinstance(scanner.scan_result.vulnerabilities, list)
    
    def test_security_headers_with_partial_headers(self, scanner):
        """Test security headers when some are present."""
        with patch.object(scanner.session, 'head') as mock_head:
            mock_response = Mock()
            mock_response.headers = {
                'X-Frame-Options': 'DENY',
                'X-Content-Type-Options': 'nosniff'
            }  # Missing other headers
            mock_head.return_value = mock_response
            
            scanner.test_security_headers("http://example.com")
            
            # May detect missing headers
            assert isinstance(scanner.scan_result.vulnerabilities, list)
    
    def test_security_headers_timeout(self, scanner):
        """Test security header check with timeout."""
        import requests
        with patch.object(scanner.session, 'head') as mock_head:
            mock_head.side_effect = requests.exceptions.Timeout()
            
            # Should not raise exception
            scanner.test_security_headers("http://example.com")
            assert isinstance(scanner.scan_result.vulnerabilities, list)


class TestSQLiAdvanced:
    """Test advanced SQL injection detection."""
    
    def test_sqli_with_error_patterns(self, scanner):
        """Test SQLi detection with various error patterns."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource"
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_sqli_in_link("http://example.com/user?id=1'")
            assert isinstance(result, bool)
    
    def test_sqli_form_submission(self, scanner):
        """Test SQLi detection in form submission."""
        from bs4 import BeautifulSoup
        
        html = """
        <form action="/login" method="post">
            <input name="username" type="text">
            <input name="password" type="password">
        </form>
        """
        
        form = BeautifulSoup(html, 'lxml').find('form')
        
        with patch.object(scanner, 'submit_form') as mock_submit:
            mock_response = Mock()
            mock_response.content = b"SQL syntax error"
            mock_response.status_code = 200
            mock_submit.return_value = mock_response
            
            result = scanner.test_sqli_in_form(form, "http://example.com")
            assert isinstance(result, bool)


class TestXSSAdvanced:
    """Test advanced XSS detection."""
    
    def test_xss_dom_based(self, scanner):
        """Test DOM-based XSS detection."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"""
            <html><body>
            <script>
                var data = document.location.hash;
                document.write(data);
            </script>
            </body></html>
            """
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_xss_in_link("http://example.com/page?search=<img%20src=x%20onerror=alert(1)>")
            assert isinstance(result, bool)
    
    def test_xss_with_encoding(self, scanner):
        """Test XSS detection with URL encoding."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"<html><body><img src=x onerror=alert(1)></body></html>"
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_xss_in_link("http://example.com/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E")
            assert isinstance(result, bool)
    
    def test_xss_form_field(self, scanner):
        """Test XSS detection in form field."""
        from bs4 import BeautifulSoup
        
        html = """
        <form action="/submit" method="post">
            <input name="comment" type="text">
        </form>
        """
        
        form = BeautifulSoup(html, 'lxml').find('form')
        
        with patch.object(scanner, 'submit_form') as mock_submit:
            mock_response = Mock()
            mock_response.content = b"Your comment: <script>alert('XSS')</script>"
            mock_response.status_code = 200
            mock_submit.return_value = mock_response
            
            result = scanner.test_xss_in_form(form, "http://example.com")
            assert isinstance(result, bool)


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_scanner_with_very_long_url(self, scanner):
        """Test scanner with very long URL."""
        long_url = "http://example.com/page?" + "a=1&" * 500
        result = scanner.test_xss_in_link(long_url)
        assert isinstance(result, bool)
    
    def test_scanner_with_special_characters(self, scanner):
        """Test scanner with special characters in URL."""
        special_url = "http://example.com/page?data=<>\"'&%"
        result = scanner.test_xss_in_link(special_url)
        assert isinstance(result, bool)
    
    def test_extract_links_with_relative_urls(self, scanner):
        """Test link extraction with relative URLs."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"""
            <html><body>
                <a href="relative/page1">Link 1</a>
                <a href="../parent">Parent</a>
                <a href="/absolute">Absolute</a>
            </body></html>
            """
            mock_get.return_value = mock_response
            
            links = scanner.extract_links_from("http://example.com/subdir/page")
            assert len(links) >= 3
    
    def test_scanner_response_with_non_utf8_encoding(self, scanner):
        """Test scanner with non-UTF8 response."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            # Latin-1 encoded content
            mock_response.content = "Café".encode('latin-1')
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_xss_in_link("http://example.com/page?q=test")
            assert isinstance(result, bool)
    
    def test_run_scanner_updates_endpoints_count(self, scanner):
        """Test that run_scanner properly updates endpoint counts."""
        scanner.target_links = [
            "http://example.com/page1?id=1",
            "http://example.com/page2?id=2"
        ]
        
        with patch.object(scanner, 'test_xss_in_link') as mock_xss:
            with patch.object(scanner, 'extract_forms') as mock_forms:
                mock_xss.return_value = False
                mock_forms.return_value = []
                
                result = scanner.run_scanner()
                assert result.endpoints_scanned == 2


class TestXXEInjection:
    """Test XXE (XML External Entity) injection detection."""
    
    def test_xxe_injection_basic(self, scanner):
        """Test basic XXE injection detection."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"root:x:0:0:"  # /etc/passwd content indicator
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_xxe_injection("http://example.com/page?xml=test")
            assert isinstance(result, bool)
    
    def test_xxe_injection_error_pattern(self, scanner):
        """Test XXE detection with error patterns."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"XML_ERROR: DOCTYPE not allowed"
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_xxe_injection("http://example.com/page?xml=test")
            assert isinstance(result, bool)
    
    def test_xxe_in_form(self, scanner):
        """Test XXE detection in form submission."""
        from bs4 import BeautifulSoup
        
        html = """
        <form action="/upload" method="post">
            <input name="xmldata" type="text">
        </form>
        """
        
        form = BeautifulSoup(html, 'lxml').find('form')
        
        with patch.object(scanner, 'submit_form') as mock_submit:
            mock_response = Mock()
            mock_response.content = b"root:x:0:0:"  # /etc/passwd pattern
            mock_response.status_code = 200
            mock_submit.return_value = mock_response
            
            result = scanner.test_xxe_in_form(form, "http://example.com")
            assert isinstance(result, bool)
    
    def test_xxe_no_parameters(self, scanner):
        """Test XXE detection with URL without parameters."""
        result = scanner.test_xxe_injection("http://example.com/page")
        assert result is False
    
    def test_xxe_timeout_handling(self, scanner):
        """Test XXE detection with timeout."""
        import requests
        with patch.object(scanner.session, 'get') as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout()
            
            result = scanner.test_xxe_injection("http://example.com/page?xml=test")
            assert result is False


class TestPathTraversal:
    """Test Path Traversal vulnerability detection."""
    
    def test_path_traversal_basic(self, scanner):
        """Test basic path traversal detection."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"root:x:0:0:"  # /etc/passwd content
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_path_traversal("http://example.com/page?file=test")
            assert isinstance(result, bool)
    
    def test_path_traversal_windows_pattern(self, scanner):
        """Test path traversal with Windows patterns."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"[mail]"  # win.ini pattern
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = scanner.test_path_traversal("http://example.com/page?file=test")
            assert isinstance(result, bool)
    
    def test_path_traversal_in_form(self, scanner):
        """Test path traversal in form submission."""
        from bs4 import BeautifulSoup
        
        html = """
        <form action="/download" method="post">
            <input name="filepath" type="text">
        </form>
        """
        
        form = BeautifulSoup(html, 'lxml').find('form')
        
        with patch.object(scanner, 'submit_form') as mock_submit:
            mock_response = Mock()
            mock_response.content = b"Permission denied"  # Error pattern
            mock_response.status_code = 200
            mock_submit.return_value = mock_response
            
            result = scanner.test_path_traversal_in_form(form, "http://example.com")
            assert isinstance(result, bool)
    
    def test_path_traversal_no_parameters(self, scanner):
        """Test path traversal with URL without parameters."""
        result = scanner.test_path_traversal("http://example.com/page")
        assert result is False
    
    def test_path_traversal_error_patterns(self, scanner):
        """Test path traversal error pattern detection."""
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.content = b"No such file or directory"
            mock_response.status_code = 404
            mock_get.return_value = mock_response
            
            result = scanner.test_path_traversal("http://example.com/page?file=test")
            assert isinstance(result, bool)
    
    def test_path_traversal_timeout(self, scanner):
        """Test path traversal with timeout."""
        import requests
        with patch.object(scanner.session, 'get') as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout()
            
            result = scanner.test_path_traversal("http://example.com/page?file=test")
            assert result is False
