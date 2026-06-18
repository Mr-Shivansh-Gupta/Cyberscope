"""Configuration package for Cyberscope."""

from .settings import load_config, DEFAULT_TIMEOUT, DEFAULT_THREADS
from .logging_config import setup_logging
from .constants import (
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    CSRF_INDICATORS,
    SECURE_HEADERS,
    SQL_ERROR_PATTERNS
)

__all__ = [
    'load_config',
    'setup_logging',
    'DEFAULT_TIMEOUT',
    'DEFAULT_THREADS',
    'XSS_PAYLOADS',
    'SQLI_PAYLOADS',
    'CSRF_INDICATORS',
    'SECURE_HEADERS',
    'SQL_ERROR_PATTERNS'
]
