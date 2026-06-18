#!/usr/bin/env python
"""
Cyberscope Scanner Module - Enhanced Version

Advanced scanning engine for detecting multiple web vulnerabilities including:
- Cross-Site Scripting (XSS) - Multiple payload variants
- SQL Injection - Multiple payload types  
- CSRF vulnerabilities
- Security header misconfigurations
- Path traversal attempts

Author: Cyberscope Contributors
License: MIT
"""

import requests
import re
import urllib.parse as urlparse
import html
from fnmatch import fnmatch
from bs4 import BeautifulSoup
from typing import List, Optional, Dict, Any, Set, Tuple
from requests.models import Response
import logging
from threading import Lock
from models.vulnerability import Vulnerability, VulnerabilityType, Severity
from models.scan_result import ScanResult
from config.constants import (
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    SQL_ERROR_PATTERNS,
    SECURE_HEADERS,
    CSRF_INDICATORS,
    XXE_PAYLOADS,
    XXE_ERROR_PATTERNS,
    PATH_TRAVERSAL_PAYLOADS,
    PATH_TRAVERSAL_PATTERNS
)

logger = logging.getLogger(__name__)


class Scanner:
    """
    Advanced web vulnerability scanner with multi-threaded support.
    
    This class provides comprehensive scanning for various web vulnerabilities
    with support for multiple payload variants and concurrent testing.
    
    Attributes:
        session: Persistent requests session
        target_url: Base URL to scan
        target_links: Discovered endpoints
        links_to_ignore: URLs to exclude
        scan_result: Aggregated scan results
        timeout: HTTP request timeout
        results_lock: Thread lock for thread-safe result collection
    """
    
    def __init__(
        self, 
        url: str, 
        ignore_links: Optional[List[str]] = None,
        timeout: int = 10,
        max_retries: int = 2
    ) -> None:
        """
        Initialize the Scanner.
        
        Args:
            url: Target URL to scan
            ignore_links: List of URLs to ignore
            timeout: HTTP request timeout in seconds
            max_retries: Number of retries for transient request failures
            
        Raises:
            ValueError: If URL is invalid
        """
        if not url or not url.strip():
            raise ValueError("Target URL cannot be empty")
        
        normalized_url = self._normalize_url(url)

        if timeout < 1:
            raise ValueError("Timeout must be greater than 0")
        if max_retries < 0:
            raise ValueError("max_retries must be 0 or greater")

        self.session: requests.Session = requests.Session()
        self.target_url: str = normalized_url
        self.target_links: List[str] = []
        self.links_to_ignore: Set[str] = {
            link.strip() for link in (ignore_links if ignore_links else []) if link and link.strip()
        }
        self.timeout: int = timeout
        self.max_retries: int = max_retries
        self.scan_result: ScanResult = ScanResult(normalized_url)
        self.results_lock: Lock = Lock()
        self._target_parts = urlparse.urlsplit(normalized_url)
        self._seen_vulnerability_keys: Set[Tuple[str, str, str, str, str, str]] = set()
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL for consistent comparisons and storage."""
        url = url.strip()
        parsed = urlparse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                "Target URL must start with http:// or https:// and include a host"
            )
        clean_path = parsed.path.rstrip("/")
        if clean_path == "/":
            clean_path = ""
        normalized = parsed._replace(path=clean_path, fragment="")
        return urlparse.urlunsplit(normalized)

    def _request(self, method: str, url: str, **kwargs: Any) -> Response:
        """
        Send HTTP request with bounded retries for transient network failures.

        Raises the last request exception when retries are exhausted.
        """
        request_method = getattr(self.session, method.lower())
        attempt = 0
        last_exc: Optional[Exception] = None

        while attempt <= self.max_retries:
            try:
                return request_method(url, timeout=self.timeout, **kwargs)
            except (
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
            ) as exc:
                last_exc = exc
                if attempt >= self.max_retries:
                    raise
                logger.debug(
                    "Transient %s on %s %s (attempt %s/%s)",
                    type(exc).__name__,
                    method,
                    url,
                    attempt + 1,
                    self.max_retries + 1,
                )
                attempt += 1
            except requests.exceptions.RequestException:
                raise

        if last_exc:
            raise last_exc
        raise RuntimeError("Unexpected request retry flow")

    def _decode_response_content(self, response: Response) -> str:
        """Decode HTTP response content safely."""
        encoding = getattr(response, "encoding", None)
        if isinstance(encoding, str) and encoding:
            return response.content.decode(response.encoding, errors="ignore")
        text = getattr(response, "text", None)
        if isinstance(text, str):
            return text
        return response.content.decode(errors="ignore")

    def _is_internal_url(self, url: str) -> bool:
        """Check if URL belongs to the same target host."""
        try:
            parsed = urlparse.urlsplit(url)
            if parsed.scheme not in ("http", "https"):
                return False
            return parsed.hostname == self._target_parts.hostname
        except Exception:
            return False

    def _should_ignore_link(self, link: str) -> bool:
        """Check if a link should be ignored by exact/path/glob matching."""
        parsed_link = urlparse.urlsplit(link)
        path = parsed_link.path or "/"

        for pattern in self.links_to_ignore:
            if link == pattern:
                return True
            if fnmatch(link, pattern):
                return True
            if pattern.startswith("/") and fnmatch(path, pattern):
                return True
            if pattern in link or pattern in path:
                return True
        return False

    @staticmethod
    def _inject_payload_into_url(
        url: str, preferred_param: str, payload: str
    ) -> Optional[Tuple[str, str]]:
        """Inject a payload into an existing query parameter."""
        parsed = urlparse.urlsplit(url)
        query_pairs = urlparse.parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            return None

        target_param = preferred_param if preferred_param else query_pairs[0][0]
        mutated_pairs = []
        replaced = False

        for key, value in query_pairs:
            if key == target_param:
                mutated_pairs.append((key, payload))
                replaced = True
            else:
                mutated_pairs.append((key, value))

        if not replaced:
            mutated_pairs[0] = (mutated_pairs[0][0], payload)
            target_param = mutated_pairs[0][0]

        new_query = urlparse.urlencode(mutated_pairs, doseq=True)
        return urlparse.urlunsplit(parsed._replace(query=new_query)), target_param

    @staticmethod
    def _find_matching_pattern(patterns: List[str], content: str) -> Optional[str]:
        """Return the first literal or regex pattern that appears in content."""
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return pattern
        return None

    @classmethod
    def _matches_any_pattern(cls, patterns: List[str], content: str) -> bool:
        """Return True when any literal or regex pattern appears in content."""
        return cls._find_matching_pattern(patterns, content) is not None

    @staticmethod
    def _reflected_payload_found(payload: str, content: str) -> bool:
        """Detect direct or HTML-decoded payload reflection."""
        return payload in content or payload in html.unescape(content)

    @staticmethod
    def _extract_form_fields(
        form: Any,
        payload: str,
    ) -> Tuple[Dict[str, str], Optional[str]]:
        """Build form submission data and identify the first tested field."""
        form_data: Dict[str, str] = {}
        tested_parameter: Optional[str] = None

        fields = form.find_all(["input", "textarea", "select"])
        for field in fields:
            field_name = field.get("name")
            if not field_name:
                continue

            tag_name = field.name.lower()
            input_type = field.get("type", "text").lower()

            if tag_name == "select":
                selected = field.find("option", selected=True) or field.find("option")
                form_data[field_name] = (
                    selected.get("value", selected.text) if selected else ""
                )
                continue

            if input_type in {"submit", "button", "reset", "image"}:
                value = field.get("value")
                if value is not None:
                    form_data[field_name] = value
                continue

            if (
                input_type in {"hidden", "checkbox", "radio"}
                and field.get("value") is not None
            ):
                form_data[field_name] = field.get("value", "")
                continue

            form_data[field_name] = payload
            if tested_parameter is None:
                tested_parameter = field_name

        return form_data, tested_parameter

    def _add_vulnerability_once(self, vuln: Vulnerability) -> None:
        """Add vulnerability if not already recorded."""
        key = (
            vuln.vuln_type,
            vuln.url,
            vuln.parameter or "",
            vuln.payload,
            vuln.method,
            vuln.severity,
        )

        with self.results_lock:
            if key in self._seen_vulnerability_keys:
                return
            self._seen_vulnerability_keys.add(key)
            self.scan_result.add_vulnerability(vuln)
    
    def extract_links_from(self, url: str) -> List[str]:
        """
        Extract hyperlinks from HTML content.
        
        Uses regex pattern matching with error handling for robust extraction.
        
        Args:
            url: URL to extract links from
            
        Returns:
            List of extracted and normalized links
        """
        try:
            response: Response = self._request("GET", url)
            response.raise_for_status()
            
            content: str = self._decode_response_content(response)
            
            # Enhanced regex for various href formats
            links: List[str] = re.findall(
                r'''(?:href|src)=["']([^"']+)["']''',
                content,
                re.IGNORECASE
            )
            
            logger.debug(f"Extracted {len(links)} links from {url}")
            return links
            
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout extracting links from {url}")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to extract links from {url}: {e}")
            return []
    
    def crawl(self, url: Optional[str] = None, depth: int = 0, max_depth: int = 10) -> None:
        """
        Recursively crawl website to discover endpoints.
        
        Args:
            url: URL to crawl (defaults to target_url)
            depth: Current recursion depth
            max_depth: Maximum recursion depth
            
        Note:
            - Works best on local vulnerable applications (DVWA, WebGoat)
            - Production websites may block crawler due to security measures
            - JavaScript-rendered sites won't be crawled (requires headless browser)
        """
        if depth > max_depth:
            return
        
        if url is None:
            url = self.target_url
        
        try:
            href_links: List[str] = self.extract_links_from(url)
            
            # Provide feedback if no links found at initial URL
            if depth == 0 and not href_links:
                logger.warning(
                    f"No links discovered at {url}. "
                    "This may indicate:\n"
                    "- Website blocks automated crawlers\n"
                    "- Links are rendered via JavaScript\n"
                    "- Static links not present in HTML\n"
                    "For testing, use local vulnerable apps (DVWA, WebGoat)"
                )
                print("[!] No links found. Consider testing with DVWA or similar vulnerable app.")
                print("[*] See README for DVWA setup guide.")
            
            for link in href_links:
                try:
                    # Normalize link
                    link = urlparse.urljoin(url, link)
                    
                    # Remove fragments
                    if "#" in link:
                        link = link.split("#")[0]
                    
                    # Skip empty links
                    if not link.strip():
                        continue
                    
                    # Check if should process
                    if (
                        self._is_internal_url(link)
                        and link not in self.target_links
                        and not self._should_ignore_link(link)
                    ):
                        self.target_links.append(link)
                        logger.info(f"Discovered: {link}")
                        print(f"[+] Discovered: {link}")
                        
                        # Recursive crawl
                        self.crawl(link, depth + 1, max_depth)
                        
                except Exception as e:
                    logger.debug(f"Error processing link {link}: {e}")
                    continue
                    
        except RecursionError:
            logger.warning("Maximum recursion depth reached")
    
    def extract_forms(self, url: str) -> List[Any]:
        """
        Extract HTML forms from a URL.
        
        Args:
            url: URL to extract forms from
            
        Returns:
            List of BeautifulSoup form elements
        """
        try:
            response: Response = self._request("GET", url)
            response.raise_for_status()
            
            parsed_html = BeautifulSoup(response.content, features="lxml")
            forms: List[Any] = parsed_html.find_all("form")
            
            logger.debug(f"Extracted {len(forms)} forms from {url}")
            return forms
            
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout extracting forms from {url}")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to extract forms from {url}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing HTML from {url}: {e}")
            return []
    
    def submit_form(
        self, 
        form: Any, 
        value: str, 
        url: str
    ) -> Optional[Response]:
        """
        Submit an HTML form with test payload.
        
        Args:
            form: BeautifulSoup form element
            value: Payload to inject
            url: Base URL
            
        Returns:
            Response object or None on error
        """
        try:
            action: str = form.get("action") or ""
            post_url: str = urlparse.urljoin(url, action)
            method: str = form.get("method", "get").lower()

            post_data, _ = self._extract_form_fields(form, value)
            
            # Submit form
            if method == "post":
                response: Response = self._request(
                    "POST",
                    post_url, 
                    data=post_data, 
                )
            else:
                response = self._request(
                    "GET",
                    post_url, 
                    params=post_data, 
                )
            
            logger.debug(f"Form submitted to {post_url}")
            return response
            
        except Exception as e:
            logger.error(f"Form submission error: {e}")
            return None
    
    # ========================================================================
    # XSS DETECTION METHODS
    # ========================================================================
    
    def test_xss_in_link(self, url: str) -> bool:
        """
        Test URL for XSS vulnerability using multiple payloads.
        
        Args:
            url: URL to test
            
        Returns:
            True if vulnerability found
        """
        parsed_url = urlparse.urlsplit(url)
        query_params = urlparse.parse_qsl(parsed_url.query, keep_blank_values=True)
        if not query_params:
            return False

        preferred_param = query_params[0][0]
        for payload in XSS_PAYLOADS[:5]:  # Test with first 5 payloads
            try:
                injected = self._inject_payload_into_url(url, preferred_param, payload)
                if not injected:
                    return False
                test_url, parameter = injected
                
                response = self._request("GET", test_url)
                response_content: str = self._decode_response_content(response)
                
                # Check if payload reflected
                if self._reflected_payload_found(payload, response_content):
                    logger.warning(f"XSS found in URL: {url}")
                    vuln = Vulnerability(
                        vuln_type=VulnerabilityType.XSS,
                        url=url,
                        payload=payload,
                        severity=Severity.HIGH,
                        method="GET",
                        parameter=parameter,
                        response_code=response.status_code,
                        response_content=response_content[:200],
                        confidence="medium",
                        metadata={"detection": "url_reflection"}
                    )
                    self._add_vulnerability_once(vuln)
                    
                    return True
                    
            except Exception as e:
                logger.debug(f"Error testing XSS payload {payload}: {e}")
                continue
        
        return False
    
    def _test_form_with_payloads(
        self, 
        form: Any, 
        url: str, 
        payloads: List[str],
        vuln_type: VulnerabilityType,
        severity: Severity,
        max_payloads: int = 5,
        check_patterns: Optional[List[str]] = None,
        check_payload: bool = False
    ) -> bool:
        """
        Generic method to test form for vulnerabilities.
        
        Reduces code duplication by providing a common interface for vulnerability testing.
        This method handles payload injection, response checking, and result recording.
        
        Args:
            form: BeautifulSoup form element to test
            url: Base URL of the form
            payloads: List of payloads to test
            vuln_type: Type of vulnerability being tested
            severity: Severity level of the vulnerability
            max_payloads: Maximum number of payloads to test (default: 5)
            check_patterns: Optional list of regex patterns to check in response
            check_payload: If True, check if payload is directly in response content
            
        Returns:
            True if vulnerability found and recorded, False otherwise
        """
        for payload in payloads[:max_payloads]:
            try:
                response: Optional[Response] = self.submit_form(form, payload, url)
                
                if response is None:
                    continue
                
                response_content: str = self._decode_response_content(response)
                _, parameter = self._extract_form_fields(form, payload)
                
                # Check vulnerability using patterns or payload reflection
                vulnerability_found: bool = False
                
                matched_pattern = None

                if check_payload:
                    vulnerability_found = self._reflected_payload_found(
                        payload,
                        response_content,
                    )
                elif check_patterns:
                    matched_pattern = self._find_matching_pattern(
                        check_patterns,
                        response_content,
                    )
                    vulnerability_found = matched_pattern is not None
                
                if vulnerability_found:
                    logger.warning(f"{vuln_type} found in form: {url}")
                    vuln = Vulnerability(
                        vuln_type=vuln_type,
                        url=url,
                        payload=payload,
                        severity=severity,
                        method=form.get("method", "get").upper(),
                        parameter=parameter,
                        response_code=response.status_code,
                        response_content=response_content[:200],
                        confidence="high" if matched_pattern else "medium",
                        metadata={
                            "matched_pattern": matched_pattern,
                            "detection": "form_payload_test",
                        }
                    )
                    self._add_vulnerability_once(vuln)
                    
                    return True
                    
            except Exception as e:
                logger.debug(f"Error testing {vuln_type} in form: {e}")
                continue
        
        return False
    
    def test_xss_in_form(self, form: Any, url: str, custom_payload: Optional[str] = None) -> bool:
        """
        Test form for XSS vulnerability.
        
        Args:
            form: BeautifulSoup form element
            url: Base URL
            
        Returns:
            True if vulnerability found
        """
        payloads = [custom_payload] if custom_payload else XSS_PAYLOADS
        return self._test_form_with_payloads(
            form=form,
            url=url,
            payloads=payloads,
            vuln_type=VulnerabilityType.XSS,
            severity=Severity.HIGH,
            max_payloads=1 if custom_payload else 5,
            check_payload=True
        )
    
    # ========================================================================
    # SQL INJECTION DETECTION METHODS
    # ========================================================================
    
    def test_sqli_in_link(self, url: str) -> bool:
        """
        Test URL for SQL injection vulnerability.
        
        Args:
            url: URL to test
            
        Returns:
            True if vulnerability found
        """
        parsed_url = urlparse.urlsplit(url)
        query_params = urlparse.parse_qsl(parsed_url.query, keep_blank_values=True)
        if not query_params:
            return False

        preferred_param = query_params[0][0]
        for payload in SQLI_PAYLOADS[:5]:
            try:
                injected = self._inject_payload_into_url(url, preferred_param, payload)
                if not injected:
                    return False
                test_url, parameter = injected
                
                response = self._request("GET", test_url)
                response_content: str = self._decode_response_content(response)
                
                # Check for SQL error patterns
                matched_pattern = self._find_matching_pattern(
                    SQL_ERROR_PATTERNS,
                    response_content,
                )
                if matched_pattern:
                    logger.warning(f"SQLi found in URL: {url}")
                    vuln = Vulnerability(
                        vuln_type=VulnerabilityType.SQL_INJECTION,
                        url=url,
                        payload=payload,
                        severity=Severity.CRITICAL,
                        method="GET",
                        parameter=parameter,
                        response_code=response.status_code,
                        response_content=response_content[:200],
                        confidence="high",
                        metadata={
                            "matched_pattern": matched_pattern,
                            "detection": "url_error_pattern",
                        }
                    )
                    self._add_vulnerability_once(vuln)
                    
                    return True
                    
            except Exception as e:
                logger.debug(f"Error testing SQLi: {e}")
                continue
        
        return False
    
    def test_sqli_in_form(self, form: Any, url: str) -> bool:
        """
        Test form for SQL injection vulnerability.
        
        Args:
            form: BeautifulSoup form element
            url: Base URL
            
        Returns:
            True if vulnerability found
        """
        return self._test_form_with_payloads(
            form=form,
            url=url,
            payloads=SQLI_PAYLOADS,
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            max_payloads=5,
            check_patterns=SQL_ERROR_PATTERNS
        )
    
    # ========================================================================
    # CSRF DETECTION METHODS
    # ========================================================================
    
    def test_csrf(self, form: Any, url: str) -> bool:
        """
        Test form for CSRF vulnerabilities.
        
        Args:
            form: BeautifulSoup form element
            url: Base URL
            
        Returns:
            True if CSRF vulnerability found
        """
        try:
            # Get form method
            method: str = form.get("method", "get").lower()
            
            # Check for CSRF token
            has_token = False
            inputs = form.find_all("input")
            
            for input_field in inputs:
                field_name = input_field.get("name", "").lower()
                if any(csrf_indicator in field_name 
                       for csrf_indicator in CSRF_INDICATORS["missing_tokens"]):
                    has_token = True
                    break
            
            # POST/PUT/DELETE without CSRF token is vulnerability
            if method in ["post", "put", "delete"] and not has_token:
                logger.warning(f"Possible CSRF vulnerability in form at {url}")
                vuln = Vulnerability(
                    vuln_type=VulnerabilityType.CSRF,
                    url=url,
                    payload="Missing CSRF token",
                    severity=Severity.MEDIUM,
                    method=method.upper(),
                    response_code=200,
                    confidence="medium",
                    metadata={"detection": "missing_csrf_token"}
                )
                self._add_vulnerability_once(vuln)
                
                return True
                
        except Exception as e:
            logger.debug(f"Error testing CSRF: {e}")
        
        return False
    
    # ========================================================================
    # SECURITY HEADER ANALYSIS
    # ========================================================================
    
    def test_security_headers(self, url: str) -> None:
        """
        Check for missing or misconfigured security headers.
        
        Args:
            url: URL to test
        """
        try:
            response: Response = self._request("HEAD", url, allow_redirects=True)
            method_used = "HEAD"
            if response.status_code in (405, 501):
                response = self._request("GET", url, allow_redirects=True)
                method_used = "GET"
            headers = response.headers
            
            for header in SECURE_HEADERS.keys():
                if header not in headers:
                    logger.warning(f"Missing security header: {header}")
                    vuln = Vulnerability(
                        vuln_type=VulnerabilityType.INSECURE_HEADERS,
                        url=url,
                        payload=f"Missing {header}",
                        severity=Severity.LOW,
                        method=method_used,
                        response_code=response.status_code,
                        confidence="high",
                        metadata={
                            "missing_header": header,
                            "recommendation": SECURE_HEADERS[header],
                            "detection": "missing_security_header",
                        }
                    )
                    self._add_vulnerability_once(vuln)
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"HEAD request failed for {url}, retrying with GET: {e}")
            try:
                response = self._request("GET", url, allow_redirects=True)
                headers = response.headers
                for header in SECURE_HEADERS.keys():
                    if header not in headers:
                        vuln = Vulnerability(
                            vuln_type=VulnerabilityType.INSECURE_HEADERS,
                            url=url,
                            payload=f"Missing {header}",
                            severity=Severity.LOW,
                            method="GET",
                            response_code=response.status_code,
                            confidence="high",
                            metadata={
                                "missing_header": header,
                                "recommendation": SECURE_HEADERS[header],
                                "detection": "missing_security_header",
                            }
                        )
                        self._add_vulnerability_once(vuln)
            except Exception as inner_exc:
                logger.debug(f"Error testing security headers: {inner_exc}")
        except Exception as e:
            logger.debug(f"Error testing security headers: {e}")
    
    # ========================================================================
    # XXE INJECTION DETECTION
    # ========================================================================
    
    def test_xxe_injection(self, url: str) -> bool:
        """
        Test URL for XXE (XML External Entity) vulnerability.
        
        Args:
            url: URL to test
            
        Returns:
            True if vulnerability found
        """
        parsed_url = urlparse.urlsplit(url)
        query_params = urlparse.parse_qsl(parsed_url.query, keep_blank_values=True)
        if not query_params:
            return False

        preferred_param = query_params[0][0]
        for payload in XXE_PAYLOADS[:3]:  # Test with first 3 XXE payloads
            try:
                injected = self._inject_payload_into_url(url, preferred_param, payload)
                if not injected:
                    return False
                test_url, parameter = injected
                
                response = self._request("GET", test_url)
                response_content: str = self._decode_response_content(response)
                
                matched_pattern = self._find_matching_pattern(
                    XXE_ERROR_PATTERNS,
                    response_content,
                )
                if matched_pattern:
                    logger.warning(f"XXE found in URL: {url}")
                    vuln = Vulnerability(
                        vuln_type=VulnerabilityType.XXE,
                        url=url,
                        payload=payload,
                        severity=Severity.CRITICAL,
                        method="GET",
                        parameter=parameter,
                        response_code=response.status_code,
                        response_content=response_content[:200],
                        confidence="high",
                        metadata={
                            "matched_pattern": matched_pattern,
                            "detection": "url_error_pattern",
                        }
                    )
                    self._add_vulnerability_once(vuln)
                    
                    return True
                        
            except Exception as e:
                logger.debug(f"Error testing XXE payload: {e}")
                continue
        
        return False
    
    def test_xxe_in_form(self, form: Any, url: str) -> bool:
        """
        Test form for XXE vulnerability.
        
        Args:
            form: BeautifulSoup form element
            url: Base URL
            
        Returns:
            True if vulnerability found
        """
        return self._test_form_with_payloads(
            form=form,
            url=url,
            payloads=XXE_PAYLOADS,
            vuln_type=VulnerabilityType.XXE,
            severity=Severity.CRITICAL,
            max_payloads=3,
            check_patterns=XXE_ERROR_PATTERNS
        )
    
    # ========================================================================
    # PATH TRAVERSAL DETECTION
    # ========================================================================
    
    def test_path_traversal(self, url: str) -> bool:
        """
        Test URL for Path Traversal vulnerability.
        
        Args:
            url: URL to test
            
        Returns:
            True if vulnerability found
        """
        parsed_url = urlparse.urlsplit(url)
        query_params = urlparse.parse_qsl(parsed_url.query, keep_blank_values=True)
        if not query_params:
            return False

        preferred_param = query_params[0][0]
        for payload in PATH_TRAVERSAL_PAYLOADS[:5]:  # Test with first 5 payloads
            try:
                injected = self._inject_payload_into_url(url, preferred_param, payload)
                if not injected:
                    return False
                test_url, parameter = injected
                
                response = self._request("GET", test_url)
                response_content: str = self._decode_response_content(response)
                
                matched_pattern = self._find_matching_pattern(
                    PATH_TRAVERSAL_PATTERNS,
                    response_content,
                )
                if matched_pattern:
                    logger.warning(f"Path Traversal found in URL: {url}")
                    vuln = Vulnerability(
                        vuln_type=VulnerabilityType.PATH_TRAVERSAL,
                        url=url,
                        payload=payload,
                        severity=Severity.HIGH,
                        method="GET",
                        parameter=parameter,
                        response_code=response.status_code,
                        response_content=response_content[:200],
                        confidence="high",
                        metadata={
                            "matched_pattern": matched_pattern,
                            "detection": "url_file_disclosure_pattern",
                        }
                    )
                    self._add_vulnerability_once(vuln)
                    
                    return True
                        
            except Exception as e:
                logger.debug(f"Error testing path traversal payload: {e}")
                continue
        
        return False
    
    def test_path_traversal_in_form(self, form: Any, url: str) -> bool:
        """
        Test form for Path Traversal vulnerability.
        
        Args:
            form: BeautifulSoup form element
            url: Base URL
            
        Returns:
            True if vulnerability found
        """
        return self._test_form_with_payloads(
            form=form,
            url=url,
            payloads=PATH_TRAVERSAL_PAYLOADS,
            vuln_type=VulnerabilityType.PATH_TRAVERSAL,
            severity=Severity.HIGH,
            max_payloads=5,
            check_patterns=PATH_TRAVERSAL_PATTERNS
        )
    
    # ========================================================================
    # MAIN SCANNING ORCHESTRATOR
    # ========================================================================
    
    def run_scanner(self) -> ScanResult:
        """
        Execute comprehensive vulnerability scan.
        
        Tests all discovered endpoints for:
        - XSS vulnerabilities (URL and form-based)
        - SQL injection (URL and form-based)
        - XXE (XML External Entity) injection
        - Path Traversal vulnerabilities
        - CSRF vulnerabilities
        - Security headers
        
        Returns:
            ScanResult with all findings
        """
        unique_links = list(dict.fromkeys(self.target_links))
        self.scan_result = ScanResult(self.target_url)
        self._seen_vulnerability_keys.clear()

        logger.info(f"Starting scan on {len(unique_links)} endpoints")
        print(f"\n[*] Scanning {len(unique_links)} endpoints for vulnerabilities...\n")
        
        self.scan_result.endpoints_discovered = len(unique_links)
        
        for i, link in enumerate(unique_links, 1):
            try:
                logger.info(f"Scanning [{i}/{len(unique_links)}] {link}")
                print(f"[*] [{i}/{len(unique_links)}] Scanning: {link}")
                
                self.scan_result.endpoints_scanned += 1
                
                # Extract and test forms
                forms = self.extract_forms(link)
                
                for form_idx, form in enumerate(forms):
                    print(f"  [+] Testing form {form_idx + 1}")
                    
                    # XSS in form
                    if self.test_xss_in_form(form, link):
                        print(f"  [***] XSS FOUND in form")
                    
                    # SQLi in form
                    if self.test_sqli_in_form(form, link):
                        print(f"  [***] SQL INJECTION FOUND in form")
                    
                    # XXE in form
                    if self.test_xxe_in_form(form, link):
                        print(f"  [***] XXE FOUND in form")
                    
                    # Path Traversal in form
                    if self.test_path_traversal_in_form(form, link):
                        print(f"  [***] PATH TRAVERSAL FOUND in form")
                    
                    # CSRF
                    if self.test_csrf(form, link):
                        print(f"  [***] CSRF VULNERABILITY FOUND")
                
                # URL-based tests
                if "=" in link:
                    if self.test_xss_in_link(link):
                        print(f"  [***] XSS FOUND in URL parameters")
                    
                    if self.test_sqli_in_link(link):
                        print(f"  [***] SQL INJECTION FOUND in URL parameters")
                    
                    if self.test_xxe_injection(link):
                        print(f"  [***] XXE FOUND in URL parameters")
                    
                    if self.test_path_traversal(link):
                        print(f"  [***] PATH TRAVERSAL FOUND in URL parameters")
                
                # Security headers
                self.test_security_headers(link)
                
            except Exception as e:
                logger.error(f"Error scanning {link}: {e}")
                continue
        
        # Mark scan complete
        self.scan_result.finish()
        
        logger.info(
            f"Scan complete. Found {len(self.scan_result.vulnerabilities)} vulnerabilities"
        )
        print(f"\n[*] Scan complete. Found {len(self.scan_result.vulnerabilities)} vulnerabilities")
        
        return self.scan_result
