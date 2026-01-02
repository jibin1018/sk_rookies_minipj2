#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Claude AI 기반 취약점 분석기
Anthropic Claude API를 사용한 지능형 보안 분석
"""

import os
from anthropic import Anthropic
from dotenv import load_dotenv
import logging

load_dotenv()
logger = logging.getLogger(__name__)

class ClaudeAnalyzer:
    """Claude AI를 활용한 취약점 분석"""
    
    def __init__(self):
        self.api_key = os.getenv('ANTHROPIC_API_KEY')
        self.client = None
        
        if self.api_key:
            try:
                self.client = Anthropic(api_key=self.api_key)
                logger.info("Claude AI 분석기 초기화 완료")
            except Exception as e:
                logger.error(f"Claude 초기화 실패: {str(e)}")
        else:
            logger.warning("ANTHROPIC_API_KEY가 설정되지 않았습니다")
    
    def is_available(self):
        """Claude API 사용 가능 여부"""
        return self.client is not None
    
    def analyze_scan_results(self, target_url, results):
        """
        스캔 결과를 Claude에게 분석 요청
        
        Args:
            target_url: 대상 URL
            results: 스캔 결과 리스트
            
        Returns:
            dict: Claude의 분석 결과
        """
        if not self.is_available():
            return {
                'error': 'Claude API 키가 설정되지 않았습니다',
                'analysis': None
            }
        
        try:
            # 스캔 결과 요약
            vulnerable_results = [r for r in results if r['status'] == 'VULNERABLE']
            critical_vulns = [r for r in vulnerable_results if r.get('severity') == 'CRITICAL']
            high_vulns = [r for r in vulnerable_results if r.get('severity') == 'HIGH']
            
            # Claude에게 전달할 프롬프트 생성
            prompt = self._create_analysis_prompt(
                target_url, 
                results, 
                vulnerable_results,
                critical_vulns,
                high_vulns
            )
            
            logger.info(f"Claude 분석 요청 중... (취약점 {len(vulnerable_results)}개)")
            
            # Claude API 호출 (타임아웃: 60초)
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                temperature=0.7,
                timeout=60.0,  # 60초 타임아웃
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            analysis_text = message.content[0].text
            
            logger.info("Claude 분석 완료")
            
            return {
                'success': True,
                'analysis': analysis_text,
                'model': 'claude-sonnet-4-20250514',
                'timestamp': message.id,
                'usage': {
                    'input_tokens': message.usage.input_tokens,
                    'output_tokens': message.usage.output_tokens
                }
            }
            
        except Exception as e:
            logger.error(f"Claude 분석 오류: {str(e)}")
            return {
                'error': str(e),
                'analysis': None
            }
    
    def _create_analysis_prompt(self, target_url, results, vulnerable_results, critical_vulns, high_vulns):
        """분석 프롬프트 생성 (최적화 버전)"""
        
        # 취약점 카테고리 분류 (신규 스크립트 포함)
        vuln_categories = self._categorize_vulnerabilities(vulnerable_results)
        
        prompt = f"""당신은 OWASP TOP 10, KISA 보안 가이드 전문 보안 컨설턴트입니다.

## 스캔 결과
- **대상**: {target_url}
- **총 항목**: {len(results)}개 | **취약점**: {len(vulnerable_results)}개
- 🔴 CRITICAL: {len(critical_vulns)} | 🟠 HIGH: {len(high_vulns)} | 기타: {len(vulnerable_results) - len(critical_vulns) - len(high_vulns)}

## 발견된 취약점 (카테고리별)
"""
        # 카테고리별 취약점 요약
        for category, vulns in vuln_categories.items():
            if vulns:
                prompt += f"\n### {category}\n"
                for v in vulns[:3]:
                    severity = v.get('severity', 'MEDIUM')
                    prompt += f"- [{severity}] {v['name']}"
                    if v.get('vulnerabilities'):
                        prompt += f": {v['vulnerabilities'][0][:50]}..."
                    prompt += "\n"

        prompt += """
---

## 보고서 작성 요청

다음 구조로 **간결하고 실행 가능한** 보안 보고서를 작성하세요:

### 1. 종합 평가 (Executive Summary)
| 항목 | 내용 |
|------|------|
| 보안 등급 | 매우위험/위험/보통/양호/우수 |
| 점수 | 0-100점 |
| 핵심 위험 | 한 문장 요약 |

**TOP 3 위험**을 우선순위(P0/P1/P2)와 함께 제시

### 2. 비즈니스 영향
- 💰 금전적 손실 (구체적 금액 범위)
- ⚖️ 법적 리스크 (GDPR, 개인정보보호법 과징금)
- 📉 평판/서비스 영향

### 3. 취약점 상세 (CRITICAL/HIGH만)

각 취약점별:
```
[취약점명] - CVSS X.X (OWASP A0X)
├─ 공격 시나리오: 2-3줄
├─ 예상 피해: 구체적
└─ 조치 방안: 코드 예시 포함
```

### 4. 조치 로드맵

| 우선순위 | 기한 | 취약점 | 조치 | 담당 | 공수 |
|---------|------|--------|------|------|------|
| P0 | 24h | ... | ... | ... | ... |
| P1 | 1주 | ... | ... | ... | ... |
| P2 | 1개월 | ... | ... | ... | ... |

### 5. 예상 비용
| 구분 | 항목 | 비용(KRW) |
|------|------|-----------|
| 즉시 | 긴급 패치 | ₩X - ₩Y |
| 단기 | 코드 수정 | ₩X - ₩Y |
| 중기 | 아키텍처 개선 | ₩X - ₩Y |

### 6. 규정 준수 요약
- GDPR/개인정보보호법 위반 가능성 및 과징금
- 필요한 조치 2-3개

---
**작성 원칙**: 구체적 수치 중심, 실행 가능한 조치, 마크다운 테이블 활용
"""
        return prompt
    
    def _categorize_vulnerabilities(self, vulnerable_results):
        """취약점을 카테고리별로 분류"""
        categories = {
            '🔥 Injection': [],
            '🔐 인증/세션': [],
            '🌐 API/클라우드': [],
            '⚙️ 설정 오류': [],
            '📦 컴포넌트': [],
            '🔍 정보 노출': [],
        }
        
        # 카테고리 매핑
        category_map = {
            # Injection
            'sqli': '🔥 Injection', 'sql injection': '🔥 Injection',
            'xss': '🔥 Injection', 'command': '🔥 Injection',
            'ldap': '🔥 Injection', 'xml': '🔥 Injection',
            'xxe': '🔥 Injection', 'path traversal': '🔥 Injection',
            'log injection': '🔥 Injection',
            
            # 인증/세션
            'session': '🔐 인증/세션', 'auth': '🔐 인증/세션',
            'jwt': '🔐 인증/세션', 'cookie': '🔐 인증/세션',
            'csrf': '🔐 인증/세션', 'access control': '🔐 인증/세션',
            
            # API/클라우드
            'api': '🌐 API/클라우드', 'graphql': '🌐 API/클라우드',
            'cors': '🌐 API/클라우드', 'ssrf': '🌐 API/클라우드',
            'rate limit': '🌐 API/클라우드', 'cloud': '🌐 API/클라우드',
            'websocket': '🌐 API/클라우드', 'rest': '🌐 API/클라우드',
            
            # 설정 오류
            'header': '⚙️ 설정 오류', 'misconfig': '⚙️ 설정 오류',
            'ssl': '⚙️ 설정 오류', 'csp': '⚙️ 설정 오류',
            'cache': '⚙️ 설정 오류', 'cicd': '⚙️ 설정 오류',
            'ci/cd': '⚙️ 설정 오류', 'waf': '⚙️ 설정 오류',
            
            # 컴포넌트
            'component': '📦 컴포넌트', 'library': '📦 컴포넌트',
            'vulnerable': '📦 컴포넌트', 'deserialization': '📦 컴포넌트',
            
            # 정보 노출
            'disclosure': '🔍 정보 노출', 'backup': '🔍 정보 노출',
            'information': '🔍 정보 노출', 'enum': '🔍 정보 노출',
        }
        
        for vuln in vulnerable_results:
            name_lower = vuln.get('name', '').lower()
            category_found = False
            
            for keyword, category in category_map.items():
                if keyword in name_lower:
                    categories[category].append(vuln)
                    category_found = True
                    break
            
            if not category_found:
                categories['⚙️ 설정 오류'].append(vuln)
        
        # 빈 카테고리 제거
        return {k: v for k, v in categories.items() if v}
    
    def analyze_single_vulnerability(self, vuln_type, details):
        """
        단일 취약점 상세 분석
        
        Args:
            vuln_type: 취약점 유형 (예: 'SQL Injection')
            details: 취약점 상세 정보
            
        Returns:
            str: Claude의 분석 결과
        """
        if not self.is_available():
            return "Claude API를 사용할 수 없습니다. .env 파일에서 ANTHROPIC_API_KEY를 확인하세요."
        
        prompt = f"""웹 애플리케이션에서 **{vuln_type}** 취약점이 발견되었습니다.

## 발견된 취약점 상세 정보
{details}

다음 내용으로 상세 분석을 제공해주세요:

### 1. 취약점 설명
- 이 취약점이 무엇인지 기술적으로 설명
- OWASP TOP 10에서의 분류 및 중요도

### 2. 위험성 분석
- 공격자가 이 취약점을 악용할 경우 발생 가능한 피해
- 실제 발생했던 유사 사례 (가능한 경우)
- CVSS 점수 추정 및 근거

### 3. 실제 공격 시나리오
- 단계별 공격 흐름 (구체적 예시)
- 공격자가 얻을 수 있는 정보/권한
- 2차 공격 가능성

### 4. 구체적인 해결 방법
- 즉시 적용 가능한 임시 조치
- 근본적인 해결 방법 (코드 예제 포함)
- 프레임워크별 모범 사례

### 5. 검증 방법
- 수정 후 확인할 테스트 케이스
- 자동화된 검증 도구 추천

### 6. 재발 방지 방안
- 코드 리뷰 체크리스트
- CI/CD 파이프라인 통합 방법
- 개발자 교육 포인트

명확하고 실용적인 분석을 제공해주세요.
"""
        
        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2048,
                timeout=60.0,  # 60초 타임아웃
                messages=[{"role": "user", "content": prompt}]
            )
            
            return message.content[0].text
            
        except Exception as e:
            logger.error(f"단일 취약점 분석 오류: {str(e)}")
            return f"분석 중 오류 발생: {str(e)}"
    
    def suggest_security_improvements(self, target_url, current_vulnerabilities):
        """
        보안 개선 제안
        
        Args:
            target_url: 대상 URL
            current_vulnerabilities: 현재 취약점 목록
            
        Returns:
            dict: 보안 개선 제안
        """
        if not self.is_available():
            return {'error': 'Claude API를 사용할 수 없습니다'}
        
        vuln_summary = ', '.join(current_vulnerabilities[:10])
        if len(current_vulnerabilities) > 10:
            vuln_summary += f' 외 {len(current_vulnerabilities) - 10}개'
        
        prompt = f"""웹 애플리케이션 ({target_url})의 보안을 전반적으로 개선하기 위한 종합적인 제안을 해주세요.

## 현재 발견된 취약점
{vuln_summary}

다음 항목에 대해 구체적이고 실용적인 제안을 해주세요:

### 1. 🏗️ 아키텍처 레벨 개선
- 보안 아키텍처 설계 원칙
- Zero Trust 모델 적용 방안
- 마이크로서비스 보안 고려사항
- API Gateway 및 인증/인가 아키텍처

### 2. 💻 코드 레벨 개선
- 안전한 코딩 가이드라인 (구체적 예시)
- Input Validation 표준화
- Output Encoding 전략
- 보안 라이브러리 추천 (언어별)

### 3. 🔧 운영 레벨 개선
- 로깅 및 모니터링 체계
  * 수집해야 할 보안 이벤트
  * 실시간 알림 설정
  * SIEM 통합 방안
- 정기 보안 점검 프로세스
- 침해사고 대응 절차 (Incident Response Plan)
- 백업 및 복구 전략

### 4. 🚀 DevSecOps 통합
- CI/CD 파이프라인에 보안 점검 통합
  * SAST (Static Application Security Testing)
  * DAST (Dynamic Application Security Testing)
  * SCA (Software Composition Analysis)
  * Container Security Scanning
- Infrastructure as Code 보안
- Secret Management (API 키, 비밀번호 관리)

### 5. 📚 조직 문화 및 교육
- 개발자 보안 교육 커리큘럼
- 보안 챔피언 프로그램
- Secure Code Review 프로세스
- Bug Bounty 프로그램 도입 검토

### 6. 🛠️ 도구 및 기술 스택
- 추천 보안 도구 (오픈소스 + 상용)
- WAF 솔루션 비교
- 취약점 스캐너 선정 가이드
- 보안 테스트 자동화 도구

### 7. 📊 보안 지표 및 KPI
- 측정 가능한 보안 메트릭
- 보안 대시보드 구성
- 경영진 보고 체계

각 항목에 대해 우선순위(High/Medium/Low)와 예상 구현 기간, 예상 비용(상/중/하)을 함께 제시해주세요.
실무에서 바로 적용 가능한 구체적인 제안을 부탁드립니다.
"""
        
        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=3072,
                timeout=60.0,  # 60초 타임아웃
                messages=[{"role": "user", "content": prompt}]
            )
            
            return {
                'success': True,
                'suggestions': message.content[0].text,
                'model': 'claude-sonnet-4-20250514'
            }
            
        except Exception as e:
            logger.error(f"보안 개선 제안 오류: {str(e)}")
            return {'error': str(e)}
    
    def generate_executive_summary(self, scan_results):
        """
        경영진용 요약 보고서 생성
        
        Args:
            scan_results: 스캔 결과 데이터
            
        Returns:
            str: 경영진용 요약 보고서
        """
        if not self.is_available():
            return "Claude API를 사용할 수 없습니다"
        
        vulnerable_count = scan_results['summary']['vulnerable']
        critical_count = scan_results['summary']['critical']
        
        prompt = f"""다음 보안 진단 결과를 바탕으로 경영진용 요약 보고서를 작성해주세요.

## 진단 결과 요약
- 대상: {scan_results['target_url']}
- 총 진단 항목: {scan_results['summary']['total']}개
- 발견된 취약점: {vulnerable_count}개
- 심각한 취약점(CRITICAL): {critical_count}개

## 경영진용 요약 보고서 작성 요청

다음 내용을 포함하여 **A4 1-2페이지** 분량의 간결한 보고서를 작성해주세요:

### 1. 현황 요약 (3-4줄)
- 전체적인 보안 수준 평가
- 가장 우려되는 위험

### 2. 비즈니스 영향 (5-6줄)
- 데이터 유출 위험
- 서비스 중단 가능성
- 법적/규제 리스크
- 평판 손실 가능성

### 3. 필요한 의사결정 (불릿 포인트)
- 즉시 필요한 예산
- 리소스 할당
- 외부 전문가 투입 검토

### 4. 타임라인
- 즉시 조치: 24시간
- 단기 조치: 1주일
- 중기 조치: 1개월

**작성 스타일:**
- 전문 용어 최소화
- 숫자와 구체적 영향 중심
- 명확한 액션 아이템
- 긍정적이지만 현실적인 톤

보고서를 작성해주세요.
"""
        
        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1536,
                timeout=60.0,  # 60초 타임아웃
                messages=[{"role": "user", "content": prompt}]
            )
            
            return message.content[0].text
            
        except Exception as e:
            logger.error(f"경영진 요약 생성 오류: {str(e)}")
            return f"요약 생성 중 오류: {str(e)}"