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
        """분석 프롬프트 생성"""

        prompt = f"""당신은 OWASP TOP 10, KISA 보안 가이드, ISO 27001을 전문으로 하는 웹 애플리케이션 보안 전문가입니다.
다음 취약점 스캔 결과를 분석하고 경영진과 개발팀 모두가 이해할 수 있는 **최고 수준의 보안 진단 보고서**를 작성해주세요.

## 📊 스캔 정보
- **대상 URL**: {target_url}
- **진단 일시**: 방금 전
- **총 진단 항목**: {len(results)}개
- **발견된 취약점**: {len(vulnerable_results)}개
  - 🔴 CRITICAL: {len(critical_vulns)}개
  - 🟠 HIGH: {len(high_vulns)}개
  - 기타: {len(vulnerable_results) - len(critical_vulns) - len(high_vulns)}개

## 🔍 발견된 취약점 상세

"""

        # CRITICAL 취약점 상세
        if critical_vulns:
            prompt += "### 🚨 CRITICAL 취약점 (즉시 조치 필요)\n\n"
            for idx, result in enumerate(critical_vulns, 1):
                prompt += f"**[{idx}] {result['name']}**\n"

                if result.get('vulnerabilities'):
                    prompt += "발견된 취약점:\n"
                    for vuln in result['vulnerabilities'][:3]:  # 최대 3개
                        prompt += f"  - {vuln}\n"

                if result.get('recommendation'):
                    prompt += f"권장사항: {result['recommendation']}\n"

                prompt += "\n"

        # HIGH 취약점 요약
        if high_vulns:
            prompt += "### ⚠️ HIGH 취약점\n\n"
            for idx, result in enumerate(high_vulns, 1):
                prompt += f"**[{idx}] {result['name']}**\n"

                if result.get('vulnerabilities'):
                    count = len(result['vulnerabilities'])
                    prompt += f"발견: {count}개 취약점\n"
                    if count > 0:
                        prompt += f"  - {result['vulnerabilities'][0]}\n"

                prompt += "\n"

        # 기타 취약점
        other_vulns = [r for r in vulnerable_results
                      if r.get('severity') not in ['CRITICAL', 'HIGH']]
        if other_vulns:
            prompt += f"### ℹ️ 기타 취약점 ({len(other_vulns)}개)\n\n"
            for result in other_vulns[:5]:  # 최대 5개
                prompt += f"- {result['name']}\n"
            prompt += "\n"

        prompt += """
---

## 📋 작성할 보고서 구성

다음 구조로 **일관되고 전문적인 보안 진단 보고서**를 작성해주세요:

---

### 1. 🎯 종합 분석 (Executive Summary) - 맨 처음

#### A. 전체 보안 상태 평가
- **5단계 등급**: 매우 위험 / 위험 / 보통 / 양호 / 우수
- **종합 보안 점수**: 0-100점 (명확한 기준 제시)
- **한 줄 요약**: 경영진이 이해할 수 있는 명확한 문장

#### B. 주요 발견사항 TOP 3
- 가장 위험한 취약점 3개
- 각각의 즉각적 위험도 및 우선순위 (P0/P1/P2)

#### C. 비즈니스 영향 요약
- 💰 **금전적 손실 가능성**: 구체적 시나리오 및 예상 피해액 범위
- 📉 **평판 손상 위험**: 고객 신뢰도 하락, 브랜드 이미지 타격
- ⚖️ **법적/규제 리스크**: GDPR, 개인정보보호법 위반 가능성 및 과징금
- 🔒 **데이터 유출 가능성**: 노출될 수 있는 데이터 종류 및 규모
- 🚨 **서비스 중단 가능성**: 다운타임 발생 시나리오 및 영향

---

### 2. 📊 취약점 통계 및 현황

- **심각도별 분포 테이블**
- **위험 점수 분석**: 총 위험 점수 및 카테고리별 점수
- **OWASP TOP 10 매핑**: 발견된 취약점의 OWASP 분류

---

### 3. 🔍 취약점 상세 분석 (각 취약점별)

각 CRITICAL 및 HIGH 취약점에 대해:

#### A. 취약점 기본 정보
- 취약점 명칭
- OWASP TOP 10 분류
- **CVSS 점수 및 등급** (v3.1 기준)
- 발견 위치 (URL/엔드포인트)

#### B. 기술적 설명
- 취약점이 무엇인지 명확히 설명
- 어떻게 발견되었는지
- 기술적 근본 원인

#### C. 공격 시나리오 (구체적 예시)
- **공격자가 어떻게 악용할 수 있는지** 단계별 설명
- 실제 공격 흐름 (Request/Response 예시 포함)
- 공격 난이도 평가

#### D. 예상 피해 및 영향
- 🚨 **즉각적 피해**
  - 데이터 유출 범위 (개인정보, 결제 정보 등)
  - 시스템 장애 가능성
  - 권한 탈취 위험

- 💼 **비즈니스 영향**
  - 고객 신뢰도 하락 및 이탈률 증가
  - 매출 손실 추정치
  - 법적 책임 (GDPR 과징금 최대 €2천만 또는 전세계 매출의 4%)

- 📰 **실제 사고 사례** (유사 취약점)
  - 실제 발생한 보안 사고 예시
  - 피해 규모 및 영향

#### E. 권장 조치 방안
- 즉시 적용 가능한 임시 조치 (Workaround)
- 근본적인 해결 방법 (코드 예시 포함)
- 테스트 및 검증 방법

---

### 4. 🎯 위험도 평가 매트릭스

```
        영향도
         ↑
    HIGH │ 중위험 │ 고위험 │ 초고위험 │
  MEDIUM │ 저위험 │ 중위험 │ 고위험  │
     LOW │ 최저   │ 저위험 │ 중위험  │
         └─────────────────────────→
           LOW    MEDIUM    HIGH
              공격 가능성
```

- 각 취약점의 위치 표시
- 우선순위 결정 (P0: 긴급, P1: 높음, P2: 중간, P3: 낮음)

---

### 5. ✅ 조치 방안 (우선순위별)

#### 🔥 즉시 조치 (24시간 이내) - P0
| 취약점 | 조치 내용 | 담당자 | 예상 시간 |
|--------|----------|--------|----------|
| SQL Injection | Prepared Statement 적용 | 백엔드팀 | 4시간 |
| ... | ... | ... | ... |

**임시 완화 조치 (Workaround)**:
- WAF 긴급 룰셋 적용
- 취약한 엔드포인트 일시 비활성화

#### 📅 단기 조치 (1주일 이내) - P1
- 패치 적용 계획
- 설정 변경 사항
- 코드 수정 및 리팩토링
- 단위 테스트 및 통합 테스트

#### 📆 중기 조치 (1개월 이내) - P2
- 아키텍처 개선 (마이크로서비스, API Gateway 등)
- 보안 프로세스 수립 (코드 리뷰, SAST/DAST)
- 모니터링 시스템 구축 (SIEM, 로그 분석)

#### 📆 장기 조치 (3개월 이내) - P3
- 보안 교육 프로그램
- DevSecOps 파이프라인 구축
- 정기 진단 및 침투 테스트 프로세스

---

### 6. 💰 예상 비용 및 개발 일정

#### A. 리소스 요구사항
- **인력 투입**:
  - 백엔드 개발자: X명 × Y일
  - 프론트엔드 개발자: X명 × Y일
  - 보안 엔지니어: X명 × Y일
  - DevOps 엔지니어: X명 × Y일

#### B. 개발 공수 추정 (인일)
| 취약점 | 수정 시간 | 테스트 시간 | 총 공수 |
|--------|----------|------------|---------|
| SQL Injection | 2인일 | 1인일 | 3인일 |
| XSS | 1.5인일 | 0.5인일 | 2인일 |
| ... | ... | ... | ... |
| **총계** | | | **XX인일** |

#### C. 예산 추정
| 항목 | 내역 | 예상 비용 (KRW) |
|------|------|-----------------|
| **즉시 조치** | 긴급 패치, 임시 조치 | ₩2,000,000 - ₩5,000,000 |
| **단기 조치** | 코드 수정, 리팩토링 | ₩10,000,000 - ₩20,000,000 |
| **중기 조치** | 아키텍처 개선, 프로세스 | ₩30,000,000 - ₩50,000,000 |
| **도구/솔루션** | WAF, SIEM, 취약점 스캐너 | ₩15,000,000 - ₩30,000,000 (연간) |
| **교육/컨설팅** | 보안 교육, 침투 테스트 | ₩5,000,000 - ₩10,000,000 |
| **총계** | | **₩62,000,000 - ₩115,000,000** |

**주의**: 위 비용은 추정치이며, 실제 비용은 조직 규모, 인력 단가, 선택한 솔루션에 따라 달라질 수 있습니다.

#### D. 일정 계획
```
Week 1-2:  [████████] 즉시 조치 + 단기 조치 착수
Week 3-4:  [████████] 단기 조치 완료 + 중기 조치 시작
Month 2:   [████░░░░] 중기 조치 진행
Month 3:   [████████] 중기 조치 완료 + 장기 계획 수립
Month 4-6: [████████] 장기 조치 및 프로세스 정착
```

---

### 7. 🎓 보안 성숙도 평가

#### A. 현재 보안 수준 평가 (5단계 모델)
- **Level 1 (초기)**: 임시방편적 대응, 문서화 없음
- **Level 2 (관리)**: 기본적인 보안 정책 존재
- **Level 3 (정의)**: 표준화된 프로세스 수립
- **Level 4 (정량화)**: 측정 가능한 보안 지표
- **Level 5 (최적화)**: 지속적 개선 체계

**현재 수준**: Level X
**목표 수준**: Level Y
**격차**: Z단계 (구체적인 개선 필요 사항 설명)

#### B. 주요 영역별 성숙도
| 영역 | 현재 | 목표 | 개선 방향 |
|------|------|------|----------|
| 코드 보안 | Level X | Level Y | SAST 도입, 코드 리뷰 |
| 인프라 보안 | Level X | Level Y | 네트워크 분리, 암호화 |
| 인증/인가 | Level X | Level Y | MFA, OAuth 2.0 |
| 로깅/모니터링 | Level X | Level Y | SIEM, 실시간 알림 |
| 사고 대응 | Level X | Level Y | IR 플레이북, 훈련 |

---

### 8. ⚖️ 규정 준수 (Compliance)

#### A. GDPR (General Data Protection Regulation)
- **준수 여부**: 부분 준수 / 미준수
- **주요 위반 가능성**:
  - Art. 32 (보안 조치 미흡) → 최대 €2천만 또는 매출의 4%
  - Art. 33 (데이터 유출 시 72시간 내 신고 의무)
- **개선 필요 사항**:
  - 개인정보 암호화 강화
  - 접근 제어 및 로깅
  - 데이터 유출 대응 체계

#### B. 개인정보보호법 (한국)
- **준수 여부**: 부분 준수 / 미준수
- **주요 위반 가능성**:
  - 제24조 (안전성 확보 조치) → 과태료 최대 5천만원
  - 제29조 (안전조치 의무) → 개선 명령 가능
- **개선 필요 사항**:
  - 개인정보 처리 시스템 접근 권한 관리
  - 개인정보 암호화 (전송 및 저장)
  - 접속 기록 보관 (6개월)

#### C. PCI-DSS (결제 카드 산업 데이터 보안 표준)
**해당 사항**: 결제 정보 처리 시 필수
- **주요 요구사항**:
  - Req. 6.5: 안전한 웹 애플리케이션 개발
  - Req. 11.2: 분기별 취약점 스캔
- **준수 상태**: 미준수
- **개선 필요 사항**:
  - SQL Injection, XSS 등 OWASP TOP 10 취약점 제거
  - 정기 취약점 스캔 및 침투 테스트

#### D. ISO/IEC 27001 (정보보안 관리 시스템)
- **인증 필요성**: 권장 (고객 신뢰도 향상)
- **현재 갭 분석**:
  - A.12.6 (기술적 취약점 관리) → 정기 스캔 미흡
  - A.14.2 (시스템 개발 보안) → Secure SDLC 미적용
- **인증 로드맵**: 6-12개월 소요 예상

---

### 9. 🔄 지속적 보안 개선 계획

#### A. 정기 보안 점검 프로세스
- **취약점 스캔**: 월 1회 (자동화)
- **침투 테스트**: 분기 1회 (외부 전문가)
- **코드 리뷰**: 모든 PR에 대해 보안 검토
- **보안 감사**: 연 2회 (내부 + 외부)

#### B. DevSecOps 통합
```
[개발] → [SAST] → [빌드] → [DAST] → [배포] → [모니터링]
         ↓         ↓        ↓         ↓         ↓
      정적분석   SCA     동적테스트  런타임   위협탐지
                컨테이너           보안
                스캔
```

**도구 스택**:
- SAST: SonarQube, Checkmarx
- DAST: OWASP ZAP, Burp Suite
- SCA: Snyk, Dependabot
- Container Security: Trivy, Clair
- Runtime Security: Falco, Sysdig

#### C. 보안 메트릭 및 KPI
| 지표 | 목표 | 측정 방법 |
|------|------|----------|
| 취약점 해결 시간 (MTTR) | 24시간 (Critical) | Jira 티켓 |
| 신규 취약점 발견율 | < 5개/월 | 스캔 보고서 |
| 코드 커버리지 | > 80% | 테스트 리포트 |
| 보안 교육 이수율 | 100% | LMS 시스템 |
| 침해사고 대응 훈련 | 분기 1회 | 훈련 기록 |

#### D. 침해사고 대응 체계 (Incident Response)
**IR 플레이북**:
1. **탐지 (Detection)**: SIEM 알림, 사용자 제보
2. **분석 (Analysis)**: 로그 분석, 영향 범위 파악
3. **억제 (Containment)**: 격리, 임시 조치
4. **제거 (Eradication)**: 근본 원인 제거
5. **복구 (Recovery)**: 서비스 복원, 모니터링 강화
6. **사후 검토 (Post-Incident)**: 교훈, 프로세스 개선

**대응 팀 구성**:
- IR 리더: CTO/보안 책임자
- 기술팀: 개발자, 시스템 관리자
- 커뮤니케이션: PR, 법무팀

#### E. 보안 교육 및 인식 제고
**개발자 교육 프로그램**:
- **Secure Coding 기초**: 4시간 (신입 필수)
- **OWASP TOP 10 심화**: 8시간 (전체 개발자)
- **프레임워크별 보안**: 각 4시간 (Spring, React 등)
- **실습 워크샵**: 분기 1회 (CTF, 해킹 실습)

**보안 챔피언 프로그램**:
- 각 팀에 보안 챔피언 1명 배치
- 보안 이슈 우선 검토 및 팀 내 교육
- 월례 보안 챔피언 미팅

**보안 인식 캠페인**:
- 월별 보안 뉴스레터
- 피싱 시뮬레이션 (월 1회)
- 보안 포스터 및 슬로건

---

### 10. 📚 참고 자료 및 부록

#### A. OWASP TOP 10 참조
- [A01:2021 - Broken Access Control]
- [A02:2021 - Cryptographic Failures]
- [A03:2021 - Injection]
- (발견된 취약점과 관련된 항목 링크)

#### B. CVE/CWE 참조
- CVE-XXXX-XXXXX: 관련 공개 취약점
- CWE-89: SQL Injection
- CWE-79: Cross-site Scripting
- (해당 취약점의 CVE/CWE 매핑)

#### C. 보안 표준 및 가이드
- NIST Cybersecurity Framework
- SANS Top 25 Most Dangerous Software Errors
- CIS Controls v8
- KISA 웹 애플리케이션 보안 가이드

#### D. 용어 설명 (Glossary)
- **CVSS**: Common Vulnerability Scoring System
- **WAF**: Web Application Firewall
- **SIEM**: Security Information and Event Management
- **SAST/DAST**: Static/Dynamic Application Security Testing
- (기타 보안 용어)

---

## ✍️ 작성 가이드라인

1. **일관성**: 모든 취약점에 대해 동일한 구조와 깊이로 분석
2. **구체성**: 추상적인 설명 대신 구체적인 수치, 예시, 코드 포함
3. **실행 가능성**: 즉시 적용 가능한 조치 방안 제시
4. **균형**: 기술적 정확성 + 비기술자도 이해 가능한 설명
5. **톤**: 전문적이면서도 긍정적, 현실적인 톤 유지
6. **포맷**: 마크다운 형식으로 깔끔하게 작성 (헤더, 테이블, 리스트 활용)

**중요**: 위 구조를 **모두 포함**하여 완전하고 전문적인 보안 진단 보고서를 작성해주세요.
"""

        return prompt
    
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