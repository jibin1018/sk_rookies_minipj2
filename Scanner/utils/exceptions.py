"""
커스텀 예외 클래스 모듈

보안 스캐너의 다양한 에러 상황을 처리하기 위한 예외 클래스 정의
"""
from typing import Optional


class ScannerException(Exception):
    """스캐너 기본 예외 클래스"""
    
    def __init__(self, message: str, code: str = "SCANNER_ERROR", details: Optional[dict] = None):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> dict:
        """예외를 딕셔너리로 변환"""
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details
        }


class ConnectionError(ScannerException):
    """연결 관련 예외"""
    
    def __init__(self, target: str, message: str = "연결 실패", details: Optional[dict] = None):
        super().__init__(
            message=f"{target}: {message}",
            code="CONNECTION_ERROR",
            details={"target": target, **(details or {})}
        )


class TimeoutError(ScannerException):
    """타임아웃 예외"""
    
    def __init__(self, target: str, timeout: float, message: str = "요청 시간 초과"):
        super().__init__(
            message=f"{target}: {message} ({timeout}초)",
            code="TIMEOUT_ERROR",
            details={"target": target, "timeout": timeout}
        )


class AuthenticationError(ScannerException):
    """인증 관련 예외"""
    
    def __init__(self, target: str, message: str = "인증 실패"):
        super().__init__(
            message=f"{target}: {message}",
            code="AUTH_ERROR",
            details={"target": target}
        )


class InvalidTargetError(ScannerException):
    """잘못된 대상 예외"""
    
    def __init__(self, target: str, reason: str = "유효하지 않은 대상"):
        super().__init__(
            message=f"'{target}': {reason}",
            code="INVALID_TARGET",
            details={"target": target, "reason": reason}
        )


class ScriptExecutionError(ScannerException):
    """스크립트 실행 예외"""
    
    def __init__(self, script_name: str, error: Exception):
        super().__init__(
            message=f"스크립트 실행 실패: {script_name}",
            code="SCRIPT_ERROR",
            details={"script": script_name, "original_error": str(error)}
        )


class ResourceNotFoundError(ScannerException):
    """리소스 미발견 예외"""
    
    def __init__(self, resource_type: str, identifier: str):
        super().__init__(
            message=f"{resource_type}을(를) 찾을 수 없습니다: {identifier}",
            code="NOT_FOUND",
            details={"resource_type": resource_type, "identifier": identifier}
        )


class RateLimitError(ScannerException):
    """Rate Limit 예외"""
    
    def __init__(self, target: str, retry_after: Optional[int] = None):
        super().__init__(
            message=f"{target}: 요청 제한에 도달했습니다",
            code="RATE_LIMIT",
            details={"target": target, "retry_after": retry_after}
        )


class ConfigurationError(ScannerException):
    """설정 오류 예외"""
    
    def __init__(self, config_key: str, message: str = "설정 오류"):
        super().__init__(
            message=f"설정 오류 ({config_key}): {message}",
            code="CONFIG_ERROR",
            details={"config_key": config_key}
        )
