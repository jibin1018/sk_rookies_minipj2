# 보안 취약점 자동탐지 시스템 - SK Shieldus Rookies Mini Project 2

SK Shieldus 루키즈 현장실습 미니 프로젝트 2

## 📋 프로젝트 개요

본 프로젝트는 **웹 보안 취약점을 교육하고 자동으로 탐지**하기 위한 통합 시스템입니다. 의도적으로 취약하게 구현된 웹 애플리케이션과 이를 스캔하는 자동화된 보안 진단 도구로 구성되어 있습니다.

### 시스템 구성

1. **Backend (취약한 서버)** - Spring Boot 기반 그룹웨어 백엔드
2. **Frontend (취약한 UI)** - React 기반 그룹웨어 프론트엔드
3. **Scanner (취약점 스캐너)** - Flask 기반 자동 보안 취약점 탐지 시스템

### 주요 특징

- 🎯 **실전 취약점 구현**: OWASP Top 10을 포함한 31가지 웹 취약점을 의도적으로 구현
- 🔍 **자동화된 탐지**: Scanner를 통한 자동 취약점 스캔 및 보고서 생성
- 🤖 **AI 기반 분석**: Claude AI를 활용한 심화 보안 분석 및 권장사항 제공
- 📊 **포괄적 점검**: 웹 애플리케이션뿐만 아니라 OS, 데이터베이스, WAS 설정까지 점검
- 📚 **교육 목적**: 보안 취약점의 원인, 탐지 방법, 대응 방안을 학습

---

## 🛠 기술 스택

### Backend (취약한 서버)
- **Framework**: Spring Boot 3.2.0
- **Language**: Java 17
- **Database**: MySQL 8.0
- **Security**: Spring Security, JWT (jjwt 0.12.3)
- **ORM**: Spring Data JPA (Hibernate)
- **Build**: Maven

**주요 의존성:**
- spring-boot-starter-web
- spring-boot-starter-data-jpa
- spring-boot-starter-security
- spring-boot-starter-validation
- commons-text, commons-io
- Lombok

### Frontend (취약한 UI)
- **Framework**: React 18.2.0
- **Language**: JavaScript
- **UI Library**: Material-UI (MUI) 5.14.20
- **HTTP Client**: Axios 1.6.2
- **Routing**: React Router DOM 6.20.1
- **Crypto**: CryptoJS 4.2.0
- **Date**: date-fns 2.30.0, react-datepicker 4.25.0
- **Styling**: Emotion (CSS-in-JS)

### Scanner (취약점 스캐너)
- **Framework**: Flask 3.0.0
- **Language**: Python 3.12+
- **HTTP**: requests 2.31.0
- **AI**: Anthropic Claude API (claude-sonnet-4)
- **SSH**: Paramiko 3.4.0
- **CORS**: Flask-CORS 4.0.0
- **Report**: python-pptx
- **Environment**: python-dotenv 1.0.0

---

## 📂 프로젝트 구조

```
Mini_PJT2/
├── backend/                          # 의도적 취약 백엔드 서버
│   ├── src/main/java/com/company/portal/
│   │   ├── controller/              # 13개 REST API 컨트롤러
│   │   ├── service/                 # 10개+ 비즈니스 로직 서비스
│   │   ├── entity/                  # 17개 JPA 엔티티
│   │   ├── repository/              # 16개 데이터 접근 레포지토리
│   │   ├── security/                # JWT 인증 및 보안 설정
│   │   ├── dto/                     # 요청/응답 DTO
│   │   ├── exception/               # 예외 처리
│   │   └── util/                    # 유틸리티
│   ├── src/main/resources/
│   │   ├── application.yml          # 애플리케이션 설정
│   │   └── application.properties
│   └── pom.xml                      # Maven 의존성
│
├── frontend/                         # 의도적 취약 프론트엔드
│   ├── src/
│   │   ├── components/              # React 컴포넌트
│   │   │   ├── common/             # Header, Sidebar, PrivateRoute
│   │   │   ├── board/              # 게시판 (XSS 취약)
│   │   │   ├── schedule/           # 일정 (XSS 취약)
│   │   │   ├── attendance/         # 근태 관리
│   │   │   ├── approval/           # 결재 시스템
│   │   │   ├── file/               # 파일 관리
│   │   │   ├── suggestion/         # 익명 건의함
│   │   │   ├── cafeteria/          # 구내식당
│   │   │   └── employee/           # 사원 관리
│   │   ├── services/                # 14개 API 서비스
│   │   ├── contexts/                # AuthContext (전역 인증)
│   │   ├── pages/                   # 페이지 컴포넌트
│   │   └── App.js                   # 라우팅 및 테마
│   ├── public/
│   └── package.json
│
├── Scanner/                          # 보안 취약점 스캐너
│   ├── app.py                       # Flask 메인 애플리케이션
│   ├── scanner_engine.py            # 스캔 엔진 (VulnerabilityScanner, InfraScanner)
│   ├── claude_analyzer.py           # Claude AI 분석기
│   ├── create_ppt.py                # 파워포인트 보고서 생성
│   ├── modules/                     # 스캔 모듈
│   │   ├── web/                    # 31개 웹 취약점 모듈
│   │   │   ├── sqli.py             # SQL Injection
│   │   │   ├── xss.py              # Cross-Site Scripting
│   │   │   ├── path_traversal.py   # 경로 조작
│   │   │   ├── command_injection.py
│   │   │   ├── access_control.py
│   │   │   ├── jwt_vulnerabilities.py
│   │   │   ├── idor.py
│   │   │   └── ... (25개 더)
│   │   ├── db/                     # 데이터베이스 설정 점검
│   │   │   ├── mysql_config.py
│   │   │   ├── mongodb_config.py
│   │   │   ├── postgresql_config.py
│   │   │   ├── oracle_config.py
│   │   │   ├── mssql_config.py
│   │   │   └── redis_config.py
│   │   ├── was/                    # WAS 설정 점검
│   │   │   ├── tomcat_config.py
│   │   │   ├── apache_config.py
│   │   │   ├── iis_config.py
│   │   │   └── nginx_config.py
│   │   └── os/                     # OS 레벨 점검
│   │       ├── linux_account.py
│   │       ├── linux_password.py
│   │       ├── linux_file_permission.py
│   │       ├── linux_service.py
│   │       └── linux_log.py
│   ├── templates/                   # HTML 템플릿
│   │   ├── index.html              # 메인 페이지
│   │   ├── scan.html
│   │   └── report.html             # 스캔 보고서 뷰
│   ├── static/                      # CSS, JS
│   ├── reports/                     # 스캔 결과 저장소 (JSON)
│   ├── temp/                        # 임시 파일 (PEM 키)
│   ├── requirements.txt
│   └── .env                         # ANTHROPIC_API_KEY 등
│
└── README.md                         # 본 문서
```

---

## 📦 설치 및 실행 방법

### 1. 사전 요구사항

**필수 소프트웨어:**
- Java 17 이상
- Node.js 16 이상
- Python 3.12 이상
- MySQL 8.0
- Maven 3.6 이상

**API 키:**
- Anthropic API Key (Scanner의 Claude AI 분석 기능 사용 시)

---

### 2. 데이터베이스 설정

#### MySQL 접속 및 설정

```bash
mysql -u root -p
```

#### 데이터베이스 및 사용자 생성

```sql
CREATE DATABASE company_portal CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'portal_user'@'localhost' IDENTIFIED BY 'portal_password';
GRANT ALL PRIVILEGES ON company_portal.* TO 'portal_user'@'localhost';
FLUSH PRIVILEGES;
USE company_portal;
```

#### 초기 데이터 삽입

##### 부서 생성
```sql
INSERT INTO departments (name, description, created_at, updated_at) VALUES
('개발부', 'IT 개발 및 운영', NOW(), NOW()),
('영업부', '영업 및 마케팅', NOW(), NOW()),
('인사부', '인사 및 총무', NOW(), NOW());
```

##### 팀 생성
```sql
INSERT INTO teams (name, department_id, description, created_at, updated_at) VALUES
('프론트엔드팀', 1, 'React, Vue 등 프론트엔드 개발', NOW(), NOW()),
('백엔드팀', 1, 'Spring, Node.js 등 백엔드 개발', NOW(), NOW()),
('영업1팀', 2, '국내 영업', NOW(), NOW()),
('인사팀', 3, '채용 및 인사 관리', NOW(), NOW());
```

##### 테스트 계정 생성
**비밀번호**: `admin123`을 SHA-256 해시한 값 사용
```sql
-- SHA-256(admin123) = 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9
INSERT INTO employees (employee_id, password, name, email, department_id, team_id, position, role, hire_date, is_active, created_at, updated_at) VALUES
('admin', '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', '관리자', 'admin@company.com', 3, 4, 'EXECUTIVE', 'ADMIN', '2020-01-01', 1, NOW(), NOW()),
('EMP001', '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', '박지빈', 'jibin@company.com', 1, 2, 'SENIOR', 'USER', '2023-03-01', 1, NOW(), NOW()),
('EMP002', '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', '김팀장', 'leader@company.com', 1, 2, 'MANAGER', 'TEAM_LEADER', '2021-01-01', 1, NOW(), NOW());
```

##### 샘플 식단 데이터
```sql
INSERT INTO cafeteria_menus (menu_date, meal_type, menu_items, calories, created_at) VALUES
('2026-01-02', '중식', '순두부찌개, 생선구이, 시금치나물, 김치, 밥', 750, NOW()),
('2026-01-02', '석식', '된장찌개, 불고기, 계란말이, 깍두기, 밥', 850, NOW()),
('2026-01-03', '중식', '김치찌개, 제육볶음, 잡채, 배추김치, 밥', 800, NOW()),
('2026-01-03', '석식', '미역국, 닭갈비, 시금치무침, 깍두기, 밥', 780, NOW());
```

---

### 3. Backend (취약한 서버) 실행

#### application.yml 설정 확인
`backend/src/main/resources/application.yml`:
```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/company_portal?useSSL=false&serverTimezone=Asia/Seoul&characterEncoding=UTF-8
    username: portal_user
    password: portal_password
  jpa:
    hibernate:
      ddl-auto: update
```

#### 빌드 및 실행
```bash
cd backend
./mvnw clean install -DskipTests
./mvnw spring-boot:run
```

**Windows:**
```bash
mvnw.cmd clean install -DskipTests
mvnw.cmd spring-boot:run
```

**실행 확인:**
```bash
curl http://localhost:8080/api/auth/test
```

---

### 4. Frontend (취약한 UI) 실행

#### 환경 변수 설정
`frontend/.env` 파일 생성:
```env
REACT_APP_API_URL=http://localhost:8080/api
```

#### 의존성 설치 및 실행
```bash
cd frontend
npm install
npm start
```

**실행 확인:** 브라우저에서 `http://localhost:3000` 접속

---

### 5. Scanner (취약점 스캐너) 실행

#### Python 가상 환경 생성 (권장)
```bash
cd Scanner
python -m venv venv

# macOS/Linux
source venv/bin/activate

# Windows
venv\Scripts\activate
```

#### 의존성 설치
```bash
pip install -r requirements.txt
```

#### 환경 변수 설정
`Scanner/.env` 파일 생성:
```env
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

**API 키 발급:** https://console.anthropic.com/

#### Scanner 실행
```bash
python app.py
```

**실행 확인:** 브라우저에서 `http://localhost:5000` 접속

---

## 🔐 테스트 계정

| 사번 | 비밀번호 | 이름 | 역할 | 설명 |
|------|---------|------|------|------|
| `admin` | `admin123` | 관리자 | ADMIN | 전체 관리 권한 |
| `EMP001` | `admin123` | 박지빈 | USER | 일반 사용자 |
| `EMP002` | `admin123` | 김팀장 | TEAM_LEADER | 팀 리더 권한 |

---

## ✨ Backend 주요 기능

### 1. 인증 및 권한 관리
- 사번(employeeId) 기반 로그인/회원가입
- JWT 토큰 기반 인증
- Role 기반 접근 제어 (USER, TEAM_LEADER, ADMIN)
- **취약점**: 클라이언트측 SHA-256 해싱 (salt 없음), CSRF 보호 비활성화

### 2. 게시판 시스템
- 공지사항, 일반, 경조사, 동호회, 중고거래 카테고리
- 댓글 및 대댓글 기능
- 좋아요, 조회수, 검색 기능
- **취약점**:
  - Stored XSS (`BoardService.createBoard()`, `updateBoard()`)
  - SQL Injection (`BoardService.searchBoards()`)
  - Broken Access Control (작성자 검증 우회)

### 3. 결재 시스템
- 결재 요청 생성 (휴가, 출장, 지출결의, 연장근무, 구매요청 등)
- 순차적 결재선 지정 및 처리
- 결재 상태: PENDING, APPROVED, REJECTED, CANCELLED
- 결재자별 대기/완료 문서 관리

### 4. 파일 관리
- 팀별 파일 업로드/다운로드
- 폴더 경로 기반 파일 관리
- 다운로드 횟수 추적
- **취약점**:
  - Broken Access Control (팀 권한 검증 우회)
  - Path Traversal (`FileService.downloadFile()`)
  - Dangerous File Upload (exe, jsp, php 등 위험한 확장자)

### 5. 일정 관리
- 팀 일정 생성/조회
- 날짜 범위별 일정 검색
- 주간 일정 요약

### 6. 출퇴근 관리
- 출근/퇴근 체크 기능
- 일별, 월별 근태 조회
- 관리자용 전체 근태 관리

### 7. 익명 건의함
- 익명으로 건의사항 제출
- SHA-256 기반 익명성 보장
- 상태 관리 (접수, 검토중, 완료, 반려)
- 관리자 답변 기능

### 8. 기타 기능
- 사원 관리 (ADMIN 전용)
- 부서/팀 조회
- 카페테리아 메뉴/리뷰
- 대시보드 (공지/일정/결재 요약)

---

## 🎨 Frontend 주요 기능

### 1. 사용자 인터페이스
- Material-UI 기반 현대적인 디자인
- 다크 테마 지원
- 반응형 레이아웃
- 좌측 사이드바 네비게이션

### 2. 게시판 UI
- 카테고리별 필터링
- 검색 및 페이지네이션
- 게시글 작성/수정/삭제
- 댓글 및 답글 기능
- **취약점**: `dangerouslySetInnerHTML` 사용 (BoardDetail.js:173, 230)

### 3. 일정 관리 UI
- 주간/월간 보기 전환
- 드래그 앤 드롭 일정 추가
- 일정 겹침 시각화
- **취약점**: `dangerouslySetInnerHTML` 사용 (ScheduleList.js:302)

### 4. 결재 시스템 UI
- 결재 문서 작성 폼
- 결재선 선택 및 순서 지정
- 결재 진행 상황 시각화
- 승인/반려 처리 UI

### 5. 파일 관리 UI
- 팀별 파일 목록
- 파일 업로드/다운로드
- 파일 정보 표시 (크기, 업로더, 다운로드 수)

### 6. 근태 관리 UI
- 출근/퇴근 버튼
- 월별 근태 현황 테이블
- 근무 시간 자동 계산

### 7. 기타 UI
- 대시보드 (통계 카드, 최근 공지, 주간 일정)
- 익명 건의함 (건의 작성, 상태별 조회)
- 구내식당 식단표
- 사원 관리 (ADMIN 전용)

### 8. 인증 및 상태 관리
- AuthContext를 통한 전역 인증 상태
- localStorage 기반 JWT 토큰 저장
- PrivateRoute를 통한 접근 제어
- **취약점**:
  - 클라이언트측 SHA-256 해싱 (CryptoJS)
  - localStorage에 토큰 평문 저장 (XSS로 탈취 가능)
  - 클라이언트측 권한 검증만 수행

---

## 🔍 Scanner 주요 기능

### 1. 웹 애플리케이션 스캔 (31개 취약점)

#### OWASP Top 10
- **A01:2021 - Broken Access Control**
  - Access Control 우회
  - IDOR (Insecure Direct Object Reference)
  - Mass Assignment

- **A02:2021 - Cryptographic Failures**
  - 암호화 실패
  - 취약한 암호화 알고리즘
  - 평문 데이터 전송

- **A03:2021 - Injection**
  - SQL Injection (Error-based, Union-based, Blind SQLi)
  - Command Injection
  - XXE (XML External Entity)
  - Deserialization

- **A04:2021 - Insecure Design**
  - 비즈니스 로직 취약점
  - 설계 단계 보안 결함

- **A05:2021 - Security Misconfiguration**
  - Security Headers 누락
  - 기본 설정 사용
  - 불필요한 기능 활성화

- **A06:2021 - Vulnerable and Outdated Components**
  - 취약한 라이브러리
  - 패치되지 않은 컴포넌트

- **A07:2021 - Identification and Authentication Failures**
  - 인증 실패
  - 세션 관리 취약점
  - JWT 취약점

- **A08:2021 - Software and Data Integrity Failures**
  - 무결성 검증 실패
  - 안전하지 않은 역직렬화

- **A09:2021 - Security Logging and Monitoring Failures**
  - 로깅 부족
  - 모니터링 실패

- **A10:2021 - Server-Side Request Forgery (SSRF)**
  - SSRF 공격

#### 추가 취약점
- Cross-Site Scripting (XSS)
- Path Traversal
- File Upload 검증 우회
- CORS/CSRF
- Rate Limiting 부재
- HTTP Method Abuse
- Host Header Injection
- HTTP Parameter Pollution
- GraphQL 보안
- Open Redirect
- Information Disclosure

### 2. 인프라 보안 스캔

#### OS 레벨 점검 (Linux)
- 계정 관리 설정
- 패스워드 정책
- 파일 권한 설정
- 서비스 보안
- 로그 관리

#### 웹 서버 점검
- **Apache**: 버전 정보 노출, 디렉토리 리스팅, 보안 헤더
- **Nginx**: 설정 보안, TLS/SSL, 버전 정보
- **IIS**: 설정 보안 점검

#### WAS 점검
- **Tomcat**: 설정 보안, 관리자 페이지 접근

#### 데이터베이스 점검
- **MySQL**: 사용자, 권한, 암호화 설정
- **MongoDB**: 인증, 권한, 네트워크 노출
- **PostgreSQL**: 설정 보안
- **MSSQL**: 설정 보안
- **Oracle**: 설정 보안
- **Redis**: 인증 및 설정 보안

### 3. Claude AI 분석
- 스캔 결과에 대한 AI 기반 심화 분석
- 권장사항 및 수정 방법 제시
- 위험도 평가 및 우선순위 제안

### 4. 보고서 생성
- Markdown 형식 보고서
- 파워포인트 보고서 (python-pptx)
- 심각도별 취약점 요약
- 상세한 취약점 설명 및 권장사항

### 5. API 엔드포인트

**웹 스캔:**
- `POST /api/scan/start` - 웹 스캔 시작
- `GET /api/scan/status/<scan_id>` - 스캔 진행 상태
- `GET /api/scan/results/<scan_id>` - 스캔 결과 조회
- `POST /api/test/<test_name>` - 단일 테스트 실행

**인프라 스캔:**
- `POST /api/infra/scan/start` - SSH 비밀번호로 스캔
- `POST /api/infra/scan/start/pem` - PEM 키로 스캔

**보고서:**
- `POST /api/report/generate/<scan_id>` - 보고서 생성
- `GET /api/report/raw/<scan_id>` - 보고서 원문
- `GET /download/<scan_id>` - 보고서 다운로드

**기타:**
- `GET /api/tests/list` - 테스트 목록
- `GET /api/scans/history` - 스캔 히스토리
- `POST /api/claude/analyze` - Claude AI 분석

---

## 🔒 구현된 취약점 상세

### Backend 취약점

| 취약점 | 위치 | 심각도 | 설명 |
|--------|------|--------|------|
| **SQL Injection** | `BoardService.searchBoards()` (라인 84-85) | CRITICAL | 검색 키워드를 동적 쿼리에 직접 연결 |
| **Stored XSS** | `BoardService.createBoard()`, `updateBoard()` (라인 49-56, 139-142) | HIGH | HTML/JavaScript 이스케이프 없이 저장 |
| **Reflected XSS** | `BoardService.createComment()` (라인 170-204) | HIGH | 댓글 내용을 검증 없이 반환 |
| **Broken Access Control - 파일 업로드** | `FileService.uploadFile()` (라인 56-61) | CRITICAL | 팀 소속 확인 후에도 실제 권한 체크 없음 |
| **Broken Access Control - 파일 다운로드** | `FileService.downloadFile()` (라인 132-171) | CRITICAL | 파일 소유자 확인 없음 |
| **Path Traversal** | `FileService.downloadFile()` | HIGH | `requestedPath` 파라미터 검증 없음 (`../../` 가능) |
| **Broken Access Control - 게시글** | `BoardService.updateBoard()`, `deleteBoard()` (라인 127-167) | CRITICAL | 작성자 확인 후에도 권한 체크 없음 |
| **Dangerous File Upload** | `FileService.uploadFile()` (라인 63-74) | CRITICAL | 위험한 확장자 감지만 하고 차단하지 않음 (exe, jsp, php 등) |
| **Insecure Password Storage** | `AuthService.login()`, `signup()` (라인 36-125) | HIGH | SHA-256만 사용 (salt/bcrypt 없음) |
| **No CSRF Protection** | `SecurityConfig.filterChain()` (라인 57) | MEDIUM | CSRF 보호 명시적으로 비활성화 |
| **Overly Permissive CORS** | `SecurityConfig.corsConfigurationSource()` (라인 76) | MEDIUM | 모든 헤더 허용 |

**보안 로깅 시스템:**
- 모든 취약점 시도가 `SecurityLog` 엔티티에 기록
- 공격 유형: SQL_INJECTION, XSS_STORED, PATH_TRAVERSAL, UNAUTHORIZED_FILE_UPLOAD 등

### Frontend 취약점

| 취약점 | 위치 | 심각도 | 설명 |
|--------|------|--------|------|
| **XSS (dangerouslySetInnerHTML)** | `BoardDetail.js` (라인 173, 230) | HIGH | 댓글 및 게시글 HTML 직접 렌더링 |
| **XSS (dangerouslySetInnerHTML)** | `ScheduleList.js` (라인 302) | HIGH | 일정 content HTML 렌더링 |
| **Client-side Password Hashing** | `authService.js` (라인 9, 24) | MEDIUM | SHA-256 클라이언트측 해싱 (salt 없음) |
| **Token in localStorage** | `api.js`, `AuthContext.js` | HIGH | JWT 토큰을 localStorage에 평문 저장 (XSS로 탈취 가능) |
| **Client-side Auth Check** | `PrivateRoute.js` (라인 6-44) | HIGH | 클라이언트 라우팅만으로 보호 (개발자 도구로 우회 가능) |
| **No CSRF Protection** | 모든 API 호출 | MEDIUM | CSRF 토큰 미사용 |
| **Weak Input Validation** | 폼 컴포넌트들 | MEDIUM | HTML/Script 태그 필터링 없음 |
| **Information Disclosure** | `LoginPage.js` (라인 160-190) | LOW | 테스트 계정 정보 UI에 표시, 콘솔 로깅 다수 |

---

## 🧪 보안 테스트 가이드

### Scanner를 이용한 자동 스캔

#### 1. 웹 애플리케이션 스캔

1. Backend와 Frontend 실행 확인 (`http://localhost:8080`, `http://localhost:3000`)
2. Scanner 실행 (`http://localhost:5000`)
3. Scanner 메인 페이지에서:
   - 대상 URL 입력: `http://localhost:3000`
   - 스캔 유형 선택: Web Application
   - Claude AI 분석 활성화 (선택사항)
   - "Start Scan" 버튼 클릭
4. 실시간 진행률 확인
5. 스캔 완료 후 보고서 다운로드

#### 2. 인프라 스캔

1. SSH 접속 정보 준비
2. Scanner에서 인프라 스캔 선택
3. 호스트, 포트, 사용자명, 비밀번호 (또는 PEM 키) 입력
4. 점검 대상 선택 (OS, 웹서버, WAS, DB)
5. 스캔 실행 및 결과 확인

### 수동 취약점 테스트

#### XSS 공격 시연

**Stored XSS (게시판):**
1. Frontend에서 로그인 (`admin` / `admin123`)
2. 게시판 → 글쓰기
3. 제목: `<script>alert('XSS')</script>`
4. 내용: `<img src=x onerror=alert('XSS')>`
5. 게시글 저장 후 조회 → alert 실행 확인

**Stored XSS (일정):**
1. 팀 일정 페이지 접속
2. 일정 추가 시 content에: `<svg onload=alert('XSS')>`
3. 일정 조회 시 스크립트 실행 확인

#### SQL Injection 시연

**검색창 SQL Injection:**
1. 게시판 검색창에 입력: `' OR '1'='1`
2. 모든 게시글 조회됨 확인 (인증 우회)
3. 고급 페이로드 시도:
   - `' UNION SELECT NULL--`
   - `' AND SLEEP(5)--`
   - `' UNION SELECT @@version--`

#### Path Traversal 시연

**파일 다운로드 경로 조작:**
1. 브라우저 개발자 도구에서 Network 탭 열기
2. 파일 다운로드 요청 확인
3. 요청 URL 수정: `/api/files/1?path=../../../../../../etc/passwd`
4. 요청 재전송 → 시스템 파일 접근 시도

#### Broken Access Control 시연

**다른 팀 파일 접근:**
1. 사용자 A (팀 1)로 로그인
2. 개발자 도구로 API 요청 확인
3. `/api/teams/2/files` 요청 (팀 2의 파일)
4. 다른 팀의 파일 목록 조회 가능 확인

**다른 사용자 게시글 수정:**
1. 사용자 A로 로그인하여 게시글 작성
2. 사용자 B로 로그인
3. 개발자 도구에서 게시글 ID 확인
4. `/api/boards/{id}` PUT 요청으로 수정 시도
5. 다른 사용자의 게시글 수정 가능 확인

#### Dangerous File Upload 시연

**악성 파일 업로드:**
1. 팀 자료실 페이지 접속
2. 다음 파일들 업로드 시도:
   - `test.jsp` (웹쉘)
   - `malware.exe` (실행 파일)
   - `script.php` (서버 스크립트)
3. 업로드 성공 확인 (경고만 표시되고 차단되지 않음)
4. SecurityLog 테이블에서 로그 확인

---

## 📊 Scanner 스캔 결과 예시

### 심각도 분류

- **CRITICAL**: 즉시 조치 필요 (SQL Injection, 파일 업로드, IDOR 등)
- **HIGH**: 빠른 조치 필요 (XSS, 인증 실패, 민감 정보 노출 등)
- **MEDIUM**: 조치 권장 (CORS, CSRF, Security Headers 등)
- **LOW**: 참고 사항 (정보 노출, 로깅 부족 등)

### 보고서 구조

```markdown
# 보안 스캔 보고서

## 요약
- 스캔 대상: http://localhost:3000
- 스캔 시간: 2026-01-02 15:30:00
- 총 취약점: 15개
  - CRITICAL: 5개
  - HIGH: 6개
  - MEDIUM: 3개
  - LOW: 1개

## 심각도별 취약점

### CRITICAL
1. **SQL Injection** (게시판 검색)
   - 설명: 검색 키워드가 SQL 쿼리에 직접 삽입됨
   - 영향: 데이터베이스 조작, 인증 우회, 데이터 유출
   - 권장사항: Parameterized Query 또는 ORM 사용
   - 테스트 페이로드: ' OR '1'='1

2. **Path Traversal** (파일 다운로드)
   - 설명: 파일 경로가 검증 없이 사용됨
   - 영향: 시스템 파일 접근 가능
   - 권장사항: 경로 정규화 및 화이트리스트 검증
   - 테스트 페이로드: ../../../../../../etc/passwd

...
```

---

## 🎯 학습 목표 및 활용 방법

### 교육 목표

1. **취약점 이해**: 각 취약점의 발생 원인과 메커니즘 이해
2. **공격 시나리오**: 실제 공격이 어떻게 이루어지는지 체험
3. **탐지 방법**: 자동화 도구를 통한 취약점 탐지 방법 학습
4. **대응 방안**: 안전한 코딩 패턴 및 보안 설정 학습
5. **보안 도구 활용**: 보안 스캐너의 동작 원리 이해

### 활용 시나리오

#### 시나리오 1: 보안 교육 과정
1. Backend/Frontend 실행
2. 각 기능별 취약점 수동 테스트
3. Scanner로 자동 스캔 수행
4. 스캔 결과와 수동 테스트 결과 비교
5. Claude AI 분석을 통한 심화 학습

#### 시나리오 2: 모의 해킹 실습
1. 공격자 관점: 다양한 페이로드로 취약점 공격
2. 방어자 관점: Scanner로 취약점 탐지
3. 로그 분석: SecurityLog 테이블에서 공격 기록 확인
4. 대응 방안 수립: 권장사항에 따른 보안 패치 계획

#### 시나리오 3: 보안 진단 도구 개발 학습
1. Scanner 코드 분석: 각 모듈의 탐지 로직 이해
2. 새로운 취약점 모듈 추가: 커스텀 취약점 탐지 구현
3. 보고서 생성 로직 분석: Markdown/PPT 생성 방법 학습
4. Claude AI 통합: AI를 활용한 보안 분석 방법 학습

---

## ⚠️ 주의사항 및 면책 조항

### 경고

본 시스템은 **교육 목적으로 의도적으로 보안 취약점을 포함**하고 있습니다.

**절대 금지 사항:**
- 실제 운영 환경(프로덕션)에 배포하지 마세요
- 외부 네트워크에 노출하지 마세요
- 실제 사용자 데이터를 저장하지 마세요
- 허가 없이 타인의 시스템을 스캔하지 마세요

**권장 사항:**
- 로컬 개발 환경에서만 실행하세요
- 방화벽을 활성화하여 외부 접근을 차단하세요
- 테스트 완료 후 서비스를 즉시 종료하세요
- 학습한 내용을 윤리적으로만 활용하세요

### 법적 책임

- 취약점을 악용한 불법 행위에 대한 책임은 사용자에게 있습니다
- 본 프로젝트는 교육 및 연구 목적으로만 사용되어야 합니다
- 무단으로 타인의 시스템을 공격하는 행위는 불법입니다

---

## 🔧 개발 및 확장 가이드

### Scanner에 새로운 취약점 모듈 추가

#### 1. 웹 취약점 모듈 생성

`Scanner/modules/web/my_vulnerability.py`:
```python
def scan(target_url):
    result = {
        'name': 'My Vulnerability',
        'category': 'Custom',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '권장사항을 작성하세요',
        'details': ''
    }

    try:
        # 테스트 로직 구현
        # 예: HTTP 요청, 응답 분석 등

        if vulnerability_found:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'].append({
                'payload': '사용한 페이로드',
                'response': '응답 내용'
            })
    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = str(e)

    return result
```

#### 2. scanner_engine.py에 모듈 등록

```python
WEB_TESTS = [
    # ...
    ('my_vulnerability', 'My Vulnerability Test', 'MEDIUM'),
]
```

#### 3. 테스트 실행

```bash
curl -X POST http://localhost:5000/api/test/my_vulnerability \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://localhost:3000"}'
```

### Backend에 Secure 모드 구현

#### 예: SQL Injection 수정

**Vulnerable (현재):**
```java
String sql = "SELECT b FROM CompanyBoard b WHERE b.title LIKE '%" + keyword + "%'";
```

**Secure (권장):**
```java
@Query("SELECT b FROM CompanyBoard b WHERE b.title LIKE %:keyword% OR b.content LIKE %:keyword%")
List<CompanyBoard> searchBoardsSecure(@Param("keyword") String keyword);
```

#### 예: XSS 수정

**Vulnerable (현재):**
```java
board.setContent(request.getContent());  // 검증 없음
```

**Secure (권장):**
```java
import org.apache.commons.text.StringEscapeUtils;

String sanitizedContent = StringEscapeUtils.escapeHtml4(request.getContent());
board.setContent(sanitizedContent);
```

---

## 📚 참고 자료

### OWASP 리소스
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### 보안 도구
- [Burp Suite](https://portswigger.net/burp) - 웹 애플리케이션 보안 테스트
- [OWASP ZAP](https://www.zaproxy.org/) - 무료 웹 보안 스캐너
- [SQLMap](https://sqlmap.org/) - SQL Injection 자동화 도구
- [XSStrike](https://github.com/s0md3v/XSStrike) - XSS 탐지 도구

### Spring Security
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [CSRF Protection](https://docs.spring.io/spring-security/reference/features/exploits/csrf.html)
- [JWT with Spring Boot](https://jwt.io/)

### React Security
- [React Security Best Practices](https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml)
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

## 📝 개발 이력

- **2025.12.28**: 프로젝트 초기 설정, Backend 기본 구조
- **2025.12.29**: Frontend 구현, 전체 기능 완성
- **2025.12.30**: Scanner 개발 시작, 웹 취약점 모듈 구현
- **2025.12.31**: 인프라 스캔 기능 추가, Claude AI 통합
- **2026.01.01**: 보고서 생성 기능, PPT 출력 완성
- **2026.01.02**: 프로젝트 문서화 완료

---

## 👥 개발자

**SK Shieldus 루키즈 28기**

- 박지빈 - Backend & Scanner 개발
- 김동현 - Frontend 개발
- 김한수 - Backend 개발
- 정의상 - Scanner 개발
- 정현학 - Frontend & 인프라 스캔 개발

---

## 🙏 감사의 말

본 프로젝트는 SK Shieldus 루키즈 현장실습 프로그램의 일환으로 개발되었습니다.
보안 취약점을 안전하게 학습할 수 있는 환경을 제공하기 위해 노력했습니다.

특별히 감사드립니다:
- SK Shieldus 교육팀 및 멘토님들
- Anthropic Claude AI 팀 (Claude API 제공)
- OWASP 커뮤니티 (보안 가이드라인 제공)

---

## 📧 문의

프로젝트 관련 문의사항이나 버그 제보는 개발자에게 직접 연락 주시기 바랍니다.

---

## 📄 라이선스

이 프로젝트는 **교육 목적으로만 사용**됩니다.

- 상업적 사용 금지
- 불법적 목적으로 사용 금지
- 수정 및 배포 시 출처 표기 필수

---

**마지막 업데이트:** 2026년 1월 2일
