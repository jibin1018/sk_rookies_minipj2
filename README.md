# 사내 그룹웨어 시스템 - 보안 취약점 시연 프로젝트

SK Shieldus 루키즈 현장실습 미니 프로젝트 2

## 📋 프로젝트 개요

본 프로젝트는 웹 보안 취약점을 교육 목적으로 시연하기 위한 사내 그룹웨어 시스템입니다.
**보안 모드 토글 기능**을 통해 동일한 기능에 대해 취약한 구현과 안전한 구현을 비교할 수 있습니다.

### 주요 특징
- 🔒 **이중 구현**: Secure/Vulnerable 모드 전환 가능
- 🎯 **실전 시연**: 실제 공격 시나리오 기반 취약점 구현
- 📚 **교육 목적**: 보안 취약점의 원인과 대응 방법 학습

---

## 🛠 기술 스택

### Backend
- **Framework**: Spring Boot 3.2.0
- **Language**: Java 17
- **Database**: MySQL 8.0
- **Security**: Spring Security, JWT
- **ORM**: JPA (Hibernate)

### Frontend
- **Framework**: React 18.2.0
- **UI Library**: Material-UI 5.14.20
- **HTTP Client**: Axios 1.6.2
- **Routing**: React Router 6.20.1

---

## 📦 설치 및 실행 방법

### 1. 사전 요구사항
- Java 17 이상
- Node.js 16 이상
- MySQL 8.0
- Maven 3.6 이상

#### MySQL 접속
```bashmysql -u root -p

#### 데이터베이스 및 사용자 생성
```sqlCREATE DATABASE company_portal CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;CREATE USER 'portal_user'@'localhost' IDENTIFIED BY 'portal_password';GRANT ALL PRIVILEGES ON company_portal.* TO 'portal_user'@'localhost';FLUSH PRIVILEGES;USE company_portal;

#### 초기 데이터 삽입

**부서 생성**
```sqlINSERT INTO departments (name, description, created_at, updated_at) VALUES
('개발부', 'IT 개발 및 운영', NOW(), NOW()),
('영업부', '영업 및 마케팅', NOW(), NOW()),
('인사부', '인사 및 총무', NOW(), NOW());

**팀 생성**
```sqlINSERT INTO teams (name, department_id, description, created_at, updated_at) VALUES
('프론트엔드팀', 1, 'React, Vue 등 프론트엔드 개발', NOW(), NOW()),
('백엔드팀', 1, 'Spring, Node.js 등 백엔드 개발', NOW(), NOW()),
('영업1팀', 2, '국내 영업', NOW(), NOW()),
('인사팀', 3, '채용 및 인사 관리', NOW(), NOW());

**테스트 계정 생성** (비밀번호: admin123, 평문 저장)
```sqlINSERT INTO employees (employee_id, password, name, email, department_id, team_id, position, role, hire_date, is_active, created_at, updated_at) VALUES
('admin', 'admin123', '관리자', 'admin@company.com', 3, 4, 'EXECUTIVE', 'ADMIN', '2020-01-01', 1, NOW(), NOW()),
('EMP001', 'admin123', '박지빈', 'jibin@company.com', 1, 2, 'SENIOR', 'USER', '2023-03-01', 1, NOW(), NOW()),
('EMP002', 'admin123', '김팀장', 'leader@company.com', 1, 2, 'MANAGER', 'TEAM_LEADER', '2021-01-01', 1, NOW(), NOW());

**샘플 식단 데이터** (일주일치)
```sqlINSERT INTO cafeteria_menus (menu_date, meal_type, menu_items, calories, created_at) VALUES
('2025-12-29', '중식', '순두부찌개, 생선구이, 시금치나물, 김치, 밥', 750, NOW()),
('2025-12-29', '석식', '된장찌개, 불고기, 계란말이, 깍두기, 밥', 850, NOW()),
('2025-12-30', '중식', '김치찌개, 제육볶음, 잡채, 배추김치, 밥', 800, NOW()),
('2025-12-30', '석식', '미역국, 닭갈비, 시금치무침, 깍두기, 밥', 780, NOW()),
('2025-12-31', '중식', '부대찌개, 고등어구이, 콩나물무침, 김치, 밥', 820, NOW()),
('2025-12-31', '석식', '갈비탕, 잡채, 무생채, 깍두기, 밥', 900, NOW()),
('2026-01-01', '중식', '떡국, 전, 나물, 김치, 밥', 750, NOW()),
('2026-01-01', '석식', '갈비찜, 잡채, 김치, 과일, 밥', 950, NOW());

---

### 3️⃣ 백엔드 실행

#### application.yml 설정 확인
파일 위치: `backend/src/main/resources/application.yml`
```yamlspring:
datasource:
url: jdbc:mysql://localhost:3306/company_portal?useSSL=false&serverTimezone=Asia/Seoul&characterEncoding=UTF-8
username: portal_user
password: portal_password

#### 백엔드 빌드 및 실행
```bashcd backend
mvnw.cmd clean install -DskipTests
mvnw.cmd spring-boot:run

#### 백엔드 실행 확인
브라우저에서 접속: http://localhost:8080/api/auth/test

예상 응답:
```json{
"success": true,
"message": "성공",
"data": "Hello from backend!"
}

---

### 4️⃣ 프론트엔드 실행

#### 환경 변수 설정
파일 생성: `frontend/.env`
```envREACT_APP_API_URL=http://localhost:8080/api

#### 의존성 설치 및 실행
```bashcd frontend
npm install
npm start

#### 프론트엔드 실행 확인
브라우저에서 자동으로 열림: http://localhost:3000

---

## 🔐 테스트 계정

| 사번 | 비밀번호 | 이름 | 역할 | 설명 |
|------|---------|------|------|------|
| `admin` | `admin123` | 관리자 | ADMIN | 전체 관리 권한 |
| `EMP001` | `admin123` | 박지빈 | USER | 일반 사원 |
| `EMP002` | `admin123` | 김팀장 | TEAM_LEADER | 팀장 권한 |

---

## ✨ 주요 기능

### 1. 사내 게시판
- 공지사항 및 일반 게시글 작성
- 댓글 및 대댓글 기능
- **취약점**: XSS (Stored)
  - Vulnerable 모드: HTML 태그 실행
  - Secure 모드: HTML 이스케이프 처리

### 2. 팀 일정
- 팀 단위 일정 관리
- 일정 CRUD 기능
- **취약점**: 권한 검증 우회
  - Vulnerable 모드: 다른 팀 일정 접근 가능
  - Secure 모드: 팀 권한 검증

### 3. 근태 관리
- 출근/퇴근 시간 기록
- 개인 근태 내역 조회
- **취약점**: 시간 조작
  - Vulnerable 모드: 임의 시간 입력 가능
  - Secure 모드: 서버 시간 기준 기록

### 4. 팀 자료실
- 파일 업로드/다운로드
- 팀 단위 파일 공유
- **취약점**: 파일 업로드 검증, Path Traversal
  - Vulnerable 모드: 실행 파일 업로드, 경로 조작 가능
  - Secure 모드: 화이트리스트 기반 검증, 경로 정규화

### 5. 익명 건의함
- 익명 건의사항 제출
- 관리자 답변 기능
- **취약점**: SQL Injection
  - Vulnerable 모드: 동적 쿼리 생성
  - Secure 모드: Parameterized Query

### 6. 구내식당
- 일별 식단 조회
- 주간 식단 확인

### 7. 전자결재
- 결재 문서 상신
- 결재선 지정
- 승인/반려 처리

### 8. 사원 관리
- 사원 정보 조회
- 부서/팀별 조회 (관리자)

---

## 🔒 보안 취약점 목록

| 취약점 | 위치 | Vulnerable 모드 | Secure 모드 |
|--------|------|----------------|-------------|
| **XSS (Stored)** | 게시판 | `<script>` 태그 실행 | HTML Escape |
| **SQL Injection** | 검색 기능 | `' OR '1'='1` | Parameterized Query |
| **시간 조작** | 근태 관리 | 클라이언트 시간 신뢰 | 서버 시간 기준 |
| **파일 업로드** | 자료실 | .exe, .jsp 허용 | 화이트리스트 검증 |
| **Path Traversal** | 파일 다운로드 | `../../` 경로 조작 | 경로 정규화 |
| **권한 검증 우회** | API 전반 | 권한 검증 없음 | Role 기반 검증 |
| **평문 비밀번호** | 인증 | 평문 저장 | BCrypt 해싱 |

---

## 📂 프로젝트 구조
```
sk_rookies_minipj2/
│
├── backend/
│   ├── src/main/java/com/company/portal/
│   │   ├── controller/              # REST API 컨트롤러
│   │   ├── service/
│   │   │   ├── secure/             # 안전한 구현
│   │   │   ├── vulnerable/         # 취약한 구현
│   │   │   └── common/             # 공통 서비스
│   │   ├── entity/                 # JPA 엔티티
│   │   ├── repository/             # 데이터 접근 계층
│   │   ├── security/               # 보안 설정 (JWT, Filter 등)
│   │   ├── dto/                    # 데이터 전송 객체
│   │   ├── exception/              # 예외 처리
│   │   └── util/                   # 유틸리티
│   └── src/main/resources/
│       ├── application.yml         # 설정 파일
│       └── data.sql                # 초기 데이터 (옵션)
│
├── frontend/
│   ├── src/
│   │   ├── components/             # React 컴포넌트
│   │   │   ├── common/            # 공통 컴포넌트 (Header, Sidebar)
│   │   │   ├── board/             # 게시판
│   │   │   ├── schedule/          # 일정
│   │   │   ├── attendance/        # 근태
│   │   │   ├── file/              # 자료실
│   │   │   ├── suggestion/        # 건의함
│   │   │   ├── cafeteria/         # 식당
│   │   │   └── approval/          # 전자결재
│   │   ├── services/              # API 서비스
│   │   ├── contexts/              # Context API (인증, 보안모드)
│   │   └── pages/                 # 페이지 컴포넌트
│   ├── public/
│   └── .env                        # 환경 변수
│
└── README.md                       # 프로젝트 문서
```

---
## 🧪 보안 테스트 가이드

### ⚠️ 현재 상태
**보안 테스트는 아직 진행하지 않았습니다.**

향후 다음 항목에 대한 테스트가 필요합니다:
- [ ] XSS 공격 시나리오 검증
- [ ] SQL Injection 페이로드 테스트
- [ ] 파일 업로드 우회 시도
- [ ] Path Traversal 공격 테스트
- [ ] 권한 검증 우회 테스트
- [ ] JWT 토큰 조작 테스트
- [ ] CSRF 공격 시나리오

### 테스트 시 주의사항
⚠️ **이 시스템은 교육 목적으로 의도적으로 취약점을 포함하고 있습니다.**
- 프로덕션 환경에 절대 배포하지 마세요
- 로컬 개발 환경에서만 실행하세요
- 외부 네트워크에 노출하지 마세요

---

## 🎯 사용 시나리오

### XSS 공격 시연
1. **Vulnerable 모드**에서 로그인
2. 게시판 → 글쓰기
3. 제목에 입력: `<script>alert('XSS')</script>`
4. 게시글 저장 후 조회 → alert 실행 확인
5. **Secure 모드**로 전환
6. 동일 게시글 조회 → 스크립트가 텍스트로 표시됨

### SQL Injection 시연
1. **Vulnerable 모드**에서 로그인
2. 게시판 검색창에 입력: `' OR '1'='1`
3. 모든 게시글 조회됨 확인
4. **Secure 모드**로 전환
5. 동일 검색 → 정상적인 검색 결과만 표시

---

## 📝 개발 이력

- **2025.12.28**: 프로젝트 초기 설정, 백엔드 기본 구조
- **2025.12.29**: 프론트엔드 구현, 전체 기능 완성

---

## 👥 개발자

- 박지빈 - SK Shieldus 루키즈 28기

---

## 📄 라이선스

이 프로젝트는 교육 목적으로만 사용됩니다.

---

## ⚠️ 면책 조항

본 시스템은 **교육 목적으로 의도적으로 보안 취약점을 포함**하고 있습니다.
- 실제 운영 환경에 배포하지 마세요
- 로컬 개발 환경에서만 사용하세요
- 취약점을 악용한 불법 행위에 대한 책임은 사용자에게 있습니다