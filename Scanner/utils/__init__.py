"""
Utils 패키지

스캔 스크립트용 공통 유틸리티
"""
from .http_client import SafeHttpClient, get_client, safe_get, safe_post, safe_head
from .result import ScanResult, ScanStatus, Severity, create_result
from .payloads import (
    SQLI_PAYLOADS, XSS_PAYLOADS, CMDI_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS, SQL_ERROR_PATTERNS,
    get_sqli_payloads, get_xss_payloads, get_cmdi_payloads
)
from .encoders import (
    url_encode, url_decode, double_url_encode,
    html_encode, html_decode, html_entity_encode,
    hex_encode, unicode_encode, base64_encode, base64_decode,
    mixed_case, generate_encoded_variants, waf_bypass_variants
)

__all__ = [
    # HTTP Client
    'SafeHttpClient', 'get_client', 'safe_get', 'safe_post', 'safe_head',
    
    # Result
    'ScanResult', 'ScanStatus', 'Severity', 'create_result',
    
    # Payloads
    'SQLI_PAYLOADS', 'XSS_PAYLOADS', 'CMDI_PAYLOADS',
    'PATH_TRAVERSAL_PAYLOADS', 'SQL_ERROR_PATTERNS',
    'get_sqli_payloads', 'get_xss_payloads', 'get_cmdi_payloads',
    
    # Encoders
    'url_encode', 'url_decode', 'double_url_encode',
    'html_encode', 'html_decode', 'html_entity_encode',
    'hex_encode', 'unicode_encode', 'base64_encode', 'base64_decode',
    'mixed_case', 'generate_encoded_variants', 'waf_bypass_variants',
]
