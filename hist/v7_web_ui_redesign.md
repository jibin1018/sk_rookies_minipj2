# Version 7: 웹 인터페이스 디자인 개선

## 날짜
2026-01-03

## 작업 내용

### templates/index.html 전체 교체

기존 그라데이션 테마 → **Cyber Sentinel** 엔터프라이즈 디자인

---

### 디자인 시스템

| 항목 | 값 |
|------|-----|
| **테마** | 라이트 모드 (Slate 배경 #f1f5f9) |
| **기본 폰트** | Inter |
| **코드 폰트** | JetBrains Mono |
| **Primary Color** | Blue 600 (#2563eb) |
| **Success** | Emerald 600 (#059669) |
| **Danger** | Red 600 (#dc2626) |
| **카드 스타일** | Glassmorphism + Shadow |
| **아이콘** | Font Awesome 6 |

---

### UI 구성 요소

#### Header
```
🛡️ Cyber Sentinel
Enterprise Grade Security & Infrastructure Analysis
OWASP Top 10 & KISA 가이드 기반
```

#### Tabs
- **Web App**: 웹 취약점 스캔
- **Infra**: 인프라 보안 진단
- **History**: 스캔 기록

#### Features Grid
| 아이콘 | 제목 | 설명 |
|:------:|------|------|
| 🛡️ | 54+ Scripts | Web Vulnerability |
| ✅ | OWASP Top 10 | 2025 Standard |
| 🖥️ | Infra Scan | KISA Guide |
| 🤖 | AI Analysis | Claude Sonnet 4 |

---

### 유지된 기능

| API 엔드포인트 | 용도 |
|--------------|------|
| `/api/scan/start` | 웹 스캔 시작 |
| `/api/infra/scan/start` | 인프라 스캔 (비밀번호) |
| `/api/infra/scan/start/pem` | 인프라 스캔 (PEM) |
| `/api/scans/history` | 히스토리 조회 |
| `/api/report/raw/{id}` | 보고서 내용 |
| `/download/{id}` | 보고서 다운로드 |

---

### 스크린샷

#### Web Tab
- 타겟 URL 입력
- Claude AI 분석 옵션
- "Initiate Security Scan" 버튼

#### Infra Tab
- Host IP / Domain
- SSH Port
- Username
- Password / PEM Key 선택

## 변경 파일

- `Scanner/templates/index.html` (전체 교체)
