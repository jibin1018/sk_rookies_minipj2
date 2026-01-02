#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
보안 취약점 자동 탐지 시스템 발표용 PPT 생성기
"""

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
import os

# 색상 정의
DARK_BG = RGBColor(30, 30, 46)      # 다크 배경
ACCENT_BLUE = RGBColor(137, 180, 250)  # 파란 강조
ACCENT_GREEN = RGBColor(166, 227, 161)  # 초록
ACCENT_RED = RGBColor(243, 139, 168)   # 빨강
ACCENT_YELLOW = RGBColor(249, 226, 175)  # 노랑
WHITE = RGBColor(205, 214, 244)     # 밝은 텍스트


def add_title_slide(prs, title, subtitle=""):
    """표지 슬라이드 추가"""
    slide_layout = prs.slide_layouts[6]  # 빈 슬라이드
    slide = prs.slides.add_slide(slide_layout)
    
    # 배경색 설정
    background = slide.background
    fill = background.fill
    fill.solid()
    fill.fore_color.rgb = DARK_BG
    
    # 제목
    left = Inches(0.5)
    top = Inches(2.5)
    width = Inches(9)
    height = Inches(1.5)
    
    title_box = slide.shapes.add_textbox(left, top, width, height)
    tf = title_box.text_frame
    tf.paragraphs[0].text = title
    tf.paragraphs[0].font.size = Pt(44)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = WHITE
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    
    # 부제목
    if subtitle:
        sub_top = Inches(4)
        sub_box = slide.shapes.add_textbox(left, sub_top, width, Inches(1))
        stf = sub_box.text_frame
        stf.paragraphs[0].text = subtitle
        stf.paragraphs[0].font.size = Pt(24)
        stf.paragraphs[0].font.color.rgb = ACCENT_BLUE
        stf.paragraphs[0].alignment = PP_ALIGN.CENTER
    
    return slide


def add_content_slide(prs, title, content_lines, highlight_indices=None):
    """내용 슬라이드 추가"""
    if highlight_indices is None:
        highlight_indices = []
    
    slide_layout = prs.slide_layouts[6]
    slide = prs.slides.add_slide(slide_layout)
    
    # 배경색
    background = slide.background
    fill = background.fill
    fill.solid()
    fill.fore_color.rgb = DARK_BG
    
    # 제목
    title_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(9), Inches(0.8))
    tf = title_box.text_frame
    tf.paragraphs[0].text = title
    tf.paragraphs[0].font.size = Pt(32)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = ACCENT_BLUE
    
    # 구분선
    line = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(0.5), Inches(1.1), Inches(9), Inches(0.02)
    )
    line.fill.solid()
    line.fill.fore_color.rgb = ACCENT_BLUE
    line.line.fill.background()
    
    # 내용
    content_box = slide.shapes.add_textbox(Inches(0.5), Inches(1.4), Inches(9), Inches(5.5))
    ctf = content_box.text_frame
    ctf.word_wrap = True
    
    for i, line_text in enumerate(content_lines):
        if i == 0:
            p = ctf.paragraphs[0]
        else:
            p = ctf.add_paragraph()
        
        p.text = line_text
        p.font.size = Pt(18)
        p.space_after = Pt(8)
        
        if i in highlight_indices:
            p.font.color.rgb = ACCENT_YELLOW
            p.font.bold = True
        else:
            p.font.color.rgb = WHITE
    
    return slide


def add_table_slide(prs, title, headers, rows):
    """테이블 슬라이드 추가"""
    slide_layout = prs.slide_layouts[6]
    slide = prs.slides.add_slide(slide_layout)
    
    # 배경색
    background = slide.background
    fill = background.fill
    fill.solid()
    fill.fore_color.rgb = DARK_BG
    
    # 제목
    title_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(9), Inches(0.8))
    tf = title_box.text_frame
    tf.paragraphs[0].text = title
    tf.paragraphs[0].font.size = Pt(32)
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].font.color.rgb = ACCENT_BLUE
    
    # 테이블
    num_rows = len(rows) + 1
    num_cols = len(headers)
    
    table_width = Inches(9)
    table_height = Inches(0.4 * num_rows)
    
    table = slide.shapes.add_table(
        num_rows, num_cols, Inches(0.5), Inches(1.3), table_width, table_height
    ).table
    
    # 헤더
    for i, header in enumerate(headers):
        cell = table.cell(0, i)
        cell.text = header
        cell.text_frame.paragraphs[0].font.size = Pt(14)
        cell.text_frame.paragraphs[0].font.bold = True
        cell.text_frame.paragraphs[0].font.color.rgb = WHITE
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(69, 71, 90)
    
    # 데이터
    for row_idx, row in enumerate(rows):
        for col_idx, value in enumerate(row):
            cell = table.cell(row_idx + 1, col_idx)
            cell.text = str(value)
            cell.text_frame.paragraphs[0].font.size = Pt(12)
            cell.text_frame.paragraphs[0].font.color.rgb = WHITE
            cell.fill.solid()
            cell.fill.fore_color.rgb = RGBColor(49, 50, 68)
    
    return slide


def create_presentation():
    """메인 PPT 생성 함수"""
    prs = Presentation()
    prs.slide_width = Inches(10)
    prs.slide_height = Inches(7.5)
    
    # 슬라이드 1: 표지
    add_title_slide(
        prs,
        "🛡️ 보안 취약점 자동 탐지 시스템",
        "50개+ 취약점 항목 | OWASP TOP 10 100% | AI 분석"
    )
    
    # 슬라이드 2: 탐지 능력 요약
    add_table_slide(
        prs,
        "🎯 스캐너 탐지 능력 요약",
        ["구분", "탐지 항목 수", "주요 대상"],
        [
            ["🌐 웹 취약점", "33개", "SQL Injection, XSS, 파일 업로드 등"],
            ["🖥️ OS 진단", "5개", "계정, 패스워드, 파일 권한, 서비스, 로그"],
            ["🔧 WAS 진단", "4개", "Tomcat, Apache, IIS, Nginx 설정"],
            ["💾 DB 진단", "6개", "MySQL, PostgreSQL, Oracle, MSSQL, MongoDB, Redis"],
            ["🌍 웹서버 진단", "2개", "Apache, Nginx 보안 설정"],
            ["📊 합계", "50개+", "-"],
        ]
    )
    
    # 슬라이드 3: OWASP TOP 10
    add_table_slide(
        prs,
        "✅ OWASP TOP 10 2025 완벽 대응",
        ["순위", "OWASP 카테고리", "탐지 모듈"],
        [
            ["A01", "Broken Access Control", "access_control.py, idor.py"],
            ["A02", "Cryptographic Failures", "crypto_failures.py, jwt_vulnerabilities.py"],
            ["A03", "Injection", "sqli.py, xss.py, command_injection.py"],
            ["A04", "Insecure Design", "insecure_design.py, business_logic.py"],
            ["A05", "Security Misconfiguration", "security_misconfig.py, security_headers.py"],
            ["A06", "Vulnerable Components", "vulnerable_components.py"],
            ["A07", "Auth Failures", "auth_failures.py, rate_limiting.py"],
            ["A08", "Integrity Failures", "integrity_failures.py, deserialization.py"],
            ["A09", "Logging Failures", "logging_failures.py"],
            ["A10", "SSRF", "ssrf.py"],
        ]
    )
    
    # 슬라이드 4: 웹 취약점 CRITICAL
    add_content_slide(
        prs,
        "🔴 웹 취약점 - CRITICAL (8개)",
        [
            "• SQL Injection - 데이터베이스 공격",
            "• Command Injection - 시스템 명령어 실행",
            "• File Upload - 악성 파일 업로드",
            "• File Upload Bypass - 확장자 우회 공격",
            "• Access Control - 권한 우회",
            "• Crypto Failures - 암호화 취약점",
            "• IDOR - 직접 객체 참조 취약점",
            "• JWT Vulnerabilities - 토큰 인증 취약점",
            "• Deserialization - 역직렬화 공격",
        ],
        [0, 1, 2, 3, 4, 5, 6, 7, 8]
    )
    
    # 슬라이드 5: 웹 취약점 HIGH/MEDIUM
    add_content_slide(
        prs,
        "🟠 웹 취약점 - HIGH / MEDIUM (25개)",
        [
            "HIGH (10개):",
            "  XSS, Path Traversal, XXE, Auth Failures, Security Misconfig,",
            "  Insecure Design, Rate Limiting, Business Logic, Mass Assignment, GraphQL",
            "",
            "MEDIUM (13개):",
            "  SSRF, CORS/CSRF, Open Redirect, HTTP Method Abuse,",
            "  Host Header Injection, HTTP Parameter Pollution,",
            "  Information Disclosure, Security Headers, Vulnerable Components,",
            "  Integrity Failures, Input Bypass 등",
            "",
            "LOW (2개):",
            "  Logging Failures",
        ],
        [0, 4, 10]
    )
    
    # 슬라이드 6: 인프라 진단
    add_content_slide(
        prs,
        "🖥️ 인프라 보안 스캐너",
        [
            "OS 진단 (5개 모듈)",
            "  • linux_account.py - 불필요한 계정, UID 0, 휴면 계정 점검",
            "  • linux_password.py - 패스워드 정책, 만료일, 복잡도 설정",
            "  • linux_file_permission.py - 중요 파일 권한, SUID/SGID 검사",
            "  • linux_service.py - 불필요한 서비스, 위험 데몬 점검",
            "  • linux_log.py - 로그 설정, 보관 기간, 로테이션",
            "",
            "미들웨어 진단 (4개 모듈)",
            "  • Tomcat, Apache, IIS, Nginx 설정 점검",
            "",
            "데이터베이스 진단 (6개 모듈)",
            "  • MySQL, PostgreSQL, Oracle, MSSQL, MongoDB, Redis",
        ],
        [0, 7, 10]
    )
    
    # 슬라이드 7: AI 분석
    add_content_slide(
        prs,
        "🤖 AI 분석 기능 (Claude AI)",
        [
            "주요 기능:",
            "  ✓ 자동 위험 분석 - 탐지된 취약점의 실제 위험도 AI 평가",
            "  ✓ 맞춤형 해결책 - 취약점별 구체적인 조치 방안 제시",
            "  ✓ 경영진 요약 보고서 - 비전문가도 이해할 수 있는 요약",
            "  ✓ 우선순위 제안 - 조치 우선순위 자동 정렬",
            "",
            "분석 결과 예시:",
            "  ┌─────────────────────────────────────────────┐",
            "  │  🔴 SQL Injection 발견                      │",
            "  │  ├ 위치: /api/login                        │",
            "  │  ├ 위험도: 10/10                           │",
            "  │  ├ 영향: 전체 데이터베이스 탈취 가능       │",
            "  │  └ 조치: PreparedStatement 사용 권고       │",
            "  └─────────────────────────────────────────────┘",
        ],
        [0, 6]
    )
    
    # 슬라이드 8: 위험 점수 시스템
    add_table_slide(
        prs,
        "📊 정량적 위험 평가 시스템",
        ["심각도", "점수", "설명"],
        [
            ["🔴 CRITICAL", "+10점", "즉시 조치 필요"],
            ["🟠 HIGH", "+5점", "빠른 조치 필요"],
            ["🟡 MEDIUM", "+2점", "계획적 조치"],
            ["🟢 LOW", "+1점", "개선 권고"],
        ]
    )
    
    # 슬라이드 9: 스캔 프로세스
    add_content_slide(
        prs,
        "🔄 자동화된 진단 프로세스",
        [
            "",
            "  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐",
            "  │   대상 입력  │ → │  스캔 실행   │ → │  결과 수집   │",
            "  │  (URL/SSH)  │    │  (33개 모듈) │    │             │",
            "  └─────────────┘    └─────────────┘    └─────────────┘",
            "                                              ↓",
            "  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐",
            "  │ 리포트 생성  │ ← │  AI 분석    │ ← │ 취약점 분류  │",
            "  │ (MD/HTML)   │    │ (Claude AI) │    │ (심각도별)  │",
            "  └─────────────┘    └─────────────┘    └─────────────┘",
            "",
            "✓ 실시간 진행률 표시",
            "✓ 각 모듈 실행 상태 업데이트",
            "✓ 현재 진행 중인 테스트 표시",
        ],
        [11, 12, 13]
    )
    
    # 슬라이드 10: 핵심 차별점
    add_content_slide(
        prs,
        "💡 우리 시스템의 강점",
        [
            "",
            "✅ 50개+ 탐지 항목",
            "    → 업계 최다 수준의 취약점 커버리지",
            "",
            "✅ OWASP TOP 10 100%",
            "    → 2025년 최신 기준 완벽 대응",
            "",
            "✅ AI 기반 분석",
            "    → 단순 탐지를 넘어 지능형 해석 제공",
            "",
            "✅ 통합 스캔",
            "    → 웹 + 인프라(OS/WAS/DB) 원스톱 진단",
            "",
            "✅ 자동 리포트",
            "    → 전문가/경영진용 보고서 자동 생성",
        ],
        [1, 4, 7, 10, 13]
    )
    
    # 슬라이드 11: 기술 스택
    add_table_slide(
        prs,
        "🛠️ 사용 기술",
        ["영역", "기술"],
        [
            ["스캐너 엔진", "Python, Flask"],
            ["AI 분석", "Anthropic Claude API"],
            ["인프라 접근", "Paramiko (SSH)"],
            ["리포트", "Markdown, HTML"],
            ["취약 웹사이트", "Spring Boot, React"],
            ["데이터베이스", "MySQL/MariaDB"],
        ]
    )
    
    # 슬라이드 12: 결론
    add_content_slide(
        prs,
        "🎯 결론 및 인사이트",
        [
            "정량적 성과:",
            "  • 50개 이상의 취약점 탐지 항목 구현",
            "  • OWASP TOP 10 2025 100% 커버리지",
            "  • 6종 DB, 4종 WAS 지원",
            "",
            "인사이트:",
            "  1. 자동화의 중요성: 수동 진단 대비 시간 90% 단축",
            "  2. AI 활용 가치: 단순 탐지 → 의미있는 분석 전환",
            "  3. 통합 접근: 웹+인프라 통합 진단의 효율성",
            "",
            "향후 발전 방향:",
            "  • 클라우드 환경 진단 확장 (AWS, Azure)",
            "  • CI/CD 파이프라인 통합",
            "  • 실시간 모니터링 대시보드",
        ],
        [0, 5, 10]
    )
    
    # 슬라이드 13: Q&A
    add_title_slide(prs, "Q & A", "감사합니다")
    
    return prs


def main():
    """메인 실행"""
    output_dir = "/Users/user/Library/CloudStorage/SynologyDrive-desktop/CODE/SK_Rookies/project/Mini_PJT2"
    output_path = os.path.join(output_dir, "보안_취약점_자동탐지_시스템_발표.pptx")
    
    print("PPT 생성 중...")
    prs = create_presentation()
    prs.save(output_path)
    print(f"✅ PPT 생성 완료: {output_path}")


if __name__ == "__main__":
    main()
