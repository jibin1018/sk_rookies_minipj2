"""
향상된 로깅 모듈

구조화된 로깅과 상세한 디버그 정보 제공
"""
import logging
import os
import sys
from datetime import datetime
from typing import Optional, Any
from functools import wraps
import time
import traceback


class ScannerFormatter(logging.Formatter):
    """커스텀 로그 포맷터"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'
    }
    
    def format(self, record: logging.LogRecord) -> str:
        # 색상 적용 (터미널용)
        if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
            color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
            reset = self.COLORS['RESET']
            record.levelname = f"{color}{record.levelname}{reset}"
        
        return super().format(record)


class ScannerLogger:
    """스캐너 전용 로거 클래스"""
    
    _instance: Optional['ScannerLogger'] = None
    
    def __new__(cls, *args, **kwargs):
        """싱글톤 패턴"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, name: str = "CyberSentinel", log_dir: str = "logs"):
        if hasattr(self, '_initialized'):
            return
        
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.log_dir = log_dir
        
        # 로그 디렉토리 생성
        os.makedirs(log_dir, exist_ok=True)
        
        # 콘솔 핸들러
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_format = ScannerFormatter(
            '%(asctime)s │ %(levelname)-8s │ %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        
        # 파일 핸들러
        log_file = os.path.join(log_dir, f"scanner_{datetime.now().strftime('%Y%m%d')}.log")
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s'
        )
        file_handler.setFormatter(file_format)
        
        # 핸들러가 없을 때만 추가
        if not self.logger.handlers:
            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)
        
        self._initialized = True
    
    def debug(self, message: str, **kwargs):
        """디버그 로그"""
        self._log(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """정보 로그"""
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """경고 로그"""
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, exc_info: bool = False, **kwargs):
        """에러 로그"""
        self._log(logging.ERROR, message, exc_info=exc_info, **kwargs)
    
    def critical(self, message: str, exc_info: bool = True, **kwargs):
        """심각한 에러 로그"""
        self._log(logging.CRITICAL, message, exc_info=exc_info, **kwargs)
    
    def _log(self, level: int, message: str, exc_info: bool = False, **kwargs):
        """로그 출력"""
        extra_info = ""
        if kwargs:
            extra_info = " | " + " | ".join(f"{k}={v}" for k, v in kwargs.items())
        self.logger.log(level, f"{message}{extra_info}", exc_info=exc_info)
    
    def scan_start(self, target: str, scan_type: str = "web"):
        """스캔 시작 로그"""
        self.info(f"🚀 스캔 시작", target=target, type=scan_type)
    
    def scan_complete(self, target: str, duration: float, results_count: int):
        """스캔 완료 로그"""
        self.info(
            f"✅ 스캔 완료",
            target=target,
            duration=f"{duration:.2f}s",
            results=results_count
        )
    
    def vulnerability_found(self, name: str, severity: str, target: str):
        """취약점 발견 로그"""
        level = logging.WARNING if severity in ('CRITICAL', 'HIGH') else logging.INFO
        self._log(level, f"🔴 취약점 발견: {name}", severity=severity, target=target)
    
    def script_executed(self, script_name: str, duration: float, status: str):
        """스크립트 실행 로그"""
        emoji = "✓" if status == "success" else "✗"
        self.debug(f"{emoji} {script_name}", duration=f"{duration:.3f}s", status=status)


def log_execution_time(func):
    """함수 실행 시간 측정 데코레이터"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger = ScannerLogger()
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            logger.debug(f"⏱ {func.__name__}", duration=f"{duration:.3f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"❌ {func.__name__} 실패",
                duration=f"{duration:.3f}s",
                error=str(e)
            )
            raise
    
    return wrapper


def log_exception(func):
    """예외 로깅 데코레이터"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger = ScannerLogger()
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(
                f"예외 발생: {func.__name__}",
                error=str(e),
                traceback=traceback.format_exc()[-500:]
            )
            raise
    
    return wrapper


# 싱글톤 인스턴스 생성
scanner_logger = ScannerLogger()
