"""
인코딩 유틸리티

다양한 인코딩/디코딩 함수를 제공합니다.
WAF 우회 및 페이로드 변환에 사용됩니다.
"""
import urllib.parse
import html
import base64
from typing import List, Callable


def url_encode(text: str, safe: str = '') -> str:
    """URL 인코딩"""
    return urllib.parse.quote(text, safe=safe)


def url_decode(text: str) -> str:
    """URL 디코딩"""
    return urllib.parse.unquote(text)


def double_url_encode(text: str) -> str:
    """이중 URL 인코딩"""
    return url_encode(url_encode(text))


def html_encode(text: str) -> str:
    """HTML 엔티티 인코딩"""
    return html.escape(text)


def html_decode(text: str) -> str:
    """HTML 엔티티 디코딩"""
    return html.unescape(text)


def html_entity_encode(text: str) -> str:
    """HTML 숫자 엔티티 인코딩 (&#xx;)"""
    return ''.join(f'&#{ord(c)};' for c in text)


def hex_encode(text: str) -> str:
    """16진수 인코딩 (\\xHH)"""
    return ''.join(f'\\x{ord(c):02x}' for c in text)


def unicode_encode(text: str) -> str:
    """유니코드 인코딩 (\\uHHHH)"""
    return ''.join(f'\\u{ord(c):04x}' for c in text)


def base64_encode(text: str) -> str:
    """Base64 인코딩"""
    return base64.b64encode(text.encode()).decode()


def base64_decode(text: str) -> str:
    """Base64 디코딩"""
    try:
        return base64.b64decode(text).decode()
    except:
        return text


def mixed_case(text: str) -> str:
    """대소문자 혼합"""
    result = []
    for i, c in enumerate(text):
        result.append(c.upper() if i % 2 == 0 else c.lower())
    return ''.join(result)


def insert_null_bytes(text: str) -> str:
    """Null 바이트 삽입"""
    return text.replace(' ', '%00')


def insert_comments(text: str, comment: str = '/**/') -> str:
    """주석 삽입 (SQLi/XSS 우회)"""
    return comment.join(text)


# =============================================================================
# 다중 인코딩
# =============================================================================

def apply_encodings(payload: str, encoders: List[Callable[[str], str]]) -> str:
    """여러 인코딩을 순차 적용"""
    result = payload
    for encoder in encoders:
        result = encoder(result)
    return result


def generate_encoded_variants(payload: str) -> List[tuple]:
    """
    페이로드의 다양한 인코딩 변형 생성
    
    Returns:
        [(encoded_payload, encoding_name), ...]
    """
    variants = [
        (payload, "original"),
        (url_encode(payload), "url_encoded"),
        (double_url_encode(payload), "double_url_encoded"),
        (html_entity_encode(payload), "html_entity"),
        (hex_encode(payload), "hex"),
        (mixed_case(payload), "mixed_case"),
    ]
    
    # Base64는 특정 컨텍스트에서만 유효
    try:
        variants.append((base64_encode(payload), "base64"))
    except:
        pass
    
    return variants


# =============================================================================
# WAF 우회 변환
# =============================================================================

def waf_bypass_variants(payload: str) -> List[tuple]:
    """WAF 우회용 페이로드 변형"""
    variants = []
    
    # 1. 공백 대체
    space_replacements = [
        ('%20', 'space_url'),
        ('+', 'space_plus'),
        ('%09', 'space_tab'),
        ('%0a', 'space_newline'),
        ('/**/', 'space_comment'),
    ]
    
    for repl, name in space_replacements:
        variants.append((payload.replace(' ', repl), f"waf_{name}"))
    
    # 2. 대소문자 혼합
    variants.append((mixed_case(payload), "waf_mixedcase"))
    
    # 3. 주석 삽입
    if 'SELECT' in payload.upper():
        variants.append((
            payload.upper().replace('SELECT', 'SEL/**/ECT'),
            "waf_comment_split"
        ))
    
    return variants
