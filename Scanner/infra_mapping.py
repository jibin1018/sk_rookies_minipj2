"""
인프라-스크립트 매핑 설정

인프라 타입별로 실행할 스크립트를 정의합니다.
인프라 탐지 결과에 따라 해당 스크립트만 선별 실행됩니다.
"""

# KISA 취약점 분석·평가 가이드 기준 분류

# 웹 서버별 실행 스크립트 매핑 (W-01 ~ W-20)
WEB_SERVER_MAPPING = {
    'nginx': [
        'modules.web_server.nginx_config',  # W-06, W-07 등 포함
    ],
    'apache': [
        'modules.web_server.apache_config', # W-01 ~ W-05
    ],
    'iis': [
        'modules.was.iis_config',
    ],
}

# 데이터베이스별 실행 스크립트 매핑 (DB-01 ~ DB-10)
DATABASE_MAPPING = {
    'mysql': ['modules.db.mysql_config'],         # DB-01 ~ DB-04
    'postgresql': ['modules.db.postgresql_config'], # DB-11 ~
    'mongodb': ['modules.db.mongodb_config'],
    'mssql': ['modules.db.mssql_config'],
    'oracle': ['modules.db.oracle_config'],
    'redis': ['modules.db.redis_config'],
}

# WAS별 실행 스크립트 매핑 (WAS-01 ~ WAS-10)
WAS_MAPPING = {
    'tomcat': ['modules.was.tomcat_config'],  # WAS-01 ~ WAS-05
    'wildfly': [],
    'weblogic': [],
    'websphere': [],
}

# OS별 실행 스크립트 매핑 (U-01 ~ U-72)
OS_MAPPING = {
    'linux': [
        'modules.os.linux_account',          # U-01 ~ U-04
        'modules.os.linux_password',         # U-05 ~ U-18
        'modules.os.linux_file_permission',  # U-19 ~ U-25
        'modules.os.linux_service',          # U-26 ~ U-30
        'modules.os.linux_log',              # U-40 ~
        'modules.os.linux_firewall',
        'modules.os.linux_ssh',
    ],
    'windows': [],
}

# 프레임워크별 실행 스크립트 매핑
FRAMEWORK_MAPPING = {
    'spring': ['modules.framework.spring_actuator'],
    'django': ['modules.framework.django_settings'],
    'flask': ['modules.framework.flask_debug'],
    'laravel': [],
    'express': [],
}

# 클라우드/컨테이너별 실행 스크립트 매핑
CLOUD_MAPPING = {
    'docker': ['modules.cloud.docker_config'],
    'aws': ['modules.cloud.aws_s3'],
    'kubernetes': [],
}

# 공통 웹 취약점 스크립트 (OWASP Top 10)
COMMON_WEB_SCRIPTS = [
    'modules.web.sqli',
    'modules.web.xss',
    'modules.web.path_traversal',
    'modules.web.command_injection',
    'modules.web.xxe',
    'modules.web.deserialization',
    'modules.web.input_bypass',
    'modules.web.access_control',
    'modules.web.crypto_failures',
    'modules.web.auth_failures',
    'modules.web.security_misconfig',
    'modules.web.ssrf',
    'modules.web.cors_csrf',
    'modules.web.insecure_design',
    'modules.web.vulnerable_components',
    'modules.web.integrity_failures',
    'modules.web.logging_failures',
    'modules.web.security_headers',
    'modules.web.information_disclosure',
    'modules.web.idor',
    'modules.web.jwt_vulnerabilities',
    'modules.web.rate_limiting',
    'modules.web.file_upload_bypass',
    'modules.web.business_logic',
    'modules.web.mass_assignment',
    'modules.web.open_redirect',
    'modules.web.http_method_abuse',
    'modules.web.host_header_injection',
    'modules.web.http_parameter_pollution',
    'modules.web.graphql_security',
]

# 인프라 타입별 탐지 패턴
DETECTION_PATTERNS = {
    'web_server': {
        'nginx': ['nginx', 'openresty'],
        'apache': ['apache', 'httpd'],
        'iis': ['microsoft-iis', 'iis'],
    },
    'language': {
        'php': ['php', 'x-powered-by: php'],
        'java': ['java', 'servlet', 'jsp'],
        'python': ['python', 'wsgi', 'gunicorn', 'uvicorn'],
        'node': ['node', 'express', 'next.js'],
        'asp': ['asp.net', 'asp'],
    },
    'framework': {
        'spring': ['spring', 'x-application-context'],
        'django': ['django', 'csrftoken'],
        'laravel': ['laravel', 'laravel_session'],
        'rails': ['rails', 'x-rails'],
        'express': ['express'],
    },
    'database': {
        'mysql': ['mysql', 'mariadb'],
        'postgresql': ['postgresql', 'postgres'],
        'mongodb': ['mongodb', 'mongo'],
        'mssql': ['sql server', 'mssql'],
        'oracle': ['oracle'],
        'redis': ['redis'],
    },
    'was': {
        'tomcat': ['tomcat', 'coyote'],
        'wildfly': ['wildfly', 'jboss'],
        'weblogic': ['weblogic'],
        'websphere': ['websphere'],
    },
}


def get_scripts_for_infra(infra_profile: dict) -> list:
    """
    인프라 프로필에 따라 실행할 스크립트 목록을 반환합니다.
    
    Args:
        infra_profile: InfraDetector.detect()의 반환값
        
    Returns:
        실행할 스크립트 모듈 경로 리스트
    """
    scripts = set()
    
    # 공통 웹 스크립트는 항상 포함
    scripts.update(COMMON_WEB_SCRIPTS)
    
    # 웹 서버별 스크립트
    web_server = infra_profile.get('web_server')
    if web_server and web_server in WEB_SERVER_MAPPING:
        scripts.update(WEB_SERVER_MAPPING[web_server])
    
    # 데이터베이스별 스크립트
    database = infra_profile.get('database')
    if database and database in DATABASE_MAPPING:
        scripts.update(DATABASE_MAPPING[database])
    
    # WAS별 스크립트
    was = infra_profile.get('was')
    if was and was in WAS_MAPPING:
        scripts.update(WAS_MAPPING[was])
    
    # OS별 스크립트
    os_type = infra_profile.get('os')
    if os_type and os_type in OS_MAPPING:
        scripts.update(OS_MAPPING[os_type])
    
    # 프레임워크별 스크립트
    framework = infra_profile.get('framework')
    if framework and framework in FRAMEWORK_MAPPING:
        scripts.update(FRAMEWORK_MAPPING[framework])
    
    # 클라우드/컨테이너별 스크립트
    cloud = infra_profile.get('cloud')
    if cloud and cloud in CLOUD_MAPPING:
        scripts.update(CLOUD_MAPPING[cloud])
    
    return list(scripts)


def get_all_infra_scripts() -> list:
    """
    모든 인프라 관련 스크립트 목록을 반환합니다.
    (인프라 탐지 비활성화 시 전체 실행용)
    """
    all_scripts = set()
    
    for scripts in WEB_SERVER_MAPPING.values():
        all_scripts.update(scripts)
    
    for scripts in DATABASE_MAPPING.values():
        all_scripts.update(scripts)
    
    for scripts in WAS_MAPPING.values():
        all_scripts.update(scripts)
    
    for scripts in OS_MAPPING.values():
        all_scripts.update(scripts)
    
    all_scripts.update(COMMON_WEB_SCRIPTS)
    
    return list(all_scripts)
