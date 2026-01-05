"""
스캔 결과 표준화

모든 스캔 스크립트의 결과 포맷을 통일합니다.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class ScanStatus(Enum):
    """스캔 상태"""
    SAFE = "SAFE"
    VULNERABLE = "VULNERABLE"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    INFO = "INFO"


class Severity(Enum):
    """위험도"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    ERROR = "ERROR"


@dataclass
class ScanResult:
    """표준화된 스캔 결과"""
    
    name: str
    category: str
    status: ScanStatus = ScanStatus.SAFE
    severity: Severity = Severity.MEDIUM
    vulnerabilities: List[str] = field(default_factory=list)
    recommendation: str = ""
    details: str = ""
    
    # 메타데이터
    target_url: str = ""
    scan_time: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    extra: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환 (기존 스크립트와 호환)"""
        return {
            'name': self.name,
            'category': self.category,
            'status': self.status.value if isinstance(self.status, ScanStatus) else self.status,
            'severity': self.severity.value if isinstance(self.severity, Severity) else self.severity,
            'vulnerabilities': self.vulnerabilities,
            'recommendation': self.recommendation,
            'details': self.details,
            'target_url': self.target_url,
            'scan_time': self.scan_time,
            'timestamp': self.timestamp,
            **self.extra
        }
    
    def add_vulnerability(self, vuln: str):
        """취약점 추가"""
        self.vulnerabilities.append(vuln)
        if self.status == ScanStatus.SAFE:
            self.status = ScanStatus.VULNERABLE
    
    def set_error(self, error_msg: str):
        """에러 상태 설정"""
        self.status = ScanStatus.ERROR
        self.severity = Severity.ERROR
        self.details += f"\n[ERROR] {error_msg}"
    
    def is_vulnerable(self) -> bool:
        """취약점 존재 여부"""
        return self.status == ScanStatus.VULNERABLE
    
    def get_risk_score(self) -> int:
        """위험 점수 계산"""
        if self.status != ScanStatus.VULNERABLE:
            return 0
        
        severity_scores = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        
        return severity_scores.get(self.severity, 0) * len(self.vulnerabilities)


def create_result(
    name: str,
    category: str,
    severity: str = "MEDIUM",
    recommendation: str = ""
) -> Dict[str, Any]:
    """
    기존 스크립트 호환용 결과 생성
    
    Returns:
        기존 형식의 딕셔너리
    """
    return {
        'name': name,
        'category': category,
        'status': 'SAFE',
        'severity': severity,
        'vulnerabilities': [],
        'recommendation': recommendation,
        'details': ''
    }
