# Scanner SSH 연결 예외 처리 테스트 가이드

## ✅ 완료된 작업

### 1. TDD 기반 개발
- **Red 단계**: 테스트 케이스 작성 (test_ssh_connection.py)
- **Green 단계**: ssh_utils.py 구현
- **Refactor 단계**: 34개 인프라 모듈에 자동 적용

### 2. 수정된 파일
- **ssh_utils.py**: 안전한 SSH 연결 헬퍼 함수
- **modules/os/**: 11개 파일 (Linux 보안 점검)
- **modules/web_server/**: 2개 파일 (Apache, Nginx)
- **modules/was/**: 10개 파일 (Apache 상세 점검)
- **modules/db/**: 11개 파일 (MySQL, PostgreSQL 등)

### 3. 테스트 결과
```bash
$ python -m pytest test_ssh_connection.py -v
======================== 10 passed, 2 warnings in 0.09s ========================
```

---

## 🧪 실제 테스트 방법

### 시나리오 1: 잘못된 비밀번호로 인프라 스캔

1. **Scanner 서버 실행**
   ```bash
   cd /Users/user/Documents/Mini_PJT2/Scanner
   python app.py
   ```

2. **브라우저에서 접속**
   ```
   http://localhost:5000
   ```

3. **인프라 스캔 실행**
   - "Infrastructure Scan" 탭 선택
   - SSH 정보 입력:
     - Host: `localhost` (또는 실제 서버 IP)
     - User: `testuser`
     - Password: `wrong_password` ← **의도적으로 틀린 비밀번호**
     - Port: `22`
   - "Start Scan" 버튼 클릭

4. **예상 결과**
   ```json
   {
     "status": "ERROR",
     "details": "SSH 연결 실패: SSH 인증 실패: testuser@localhost - 비밀번호 또는 키 파일을 확인하세요",
     "severity": "ERROR"
   }
   ```

5. **확인 사항**
   - ✅ 스캔이 중단되지 않고 ERROR 상태 반환
   - ✅ 명확한 에러 메시지 표시
   - ✅ 보고서 생성 (ERROR 상태로)

---

### 시나리오 2: 네트워크 연결 불가

1. **존재하지 않는 호스트로 스캔**
   - Host: `192.168.255.255` (타임아웃 발생)
   - User: `admin`
   - Password: `password`

2. **예상 결과**
   ```json
   {
     "status": "ERROR",
     "details": "SSH 연결 실패: 네트워크 오류: 192.168.255.255 - [Errno 60] Operation timed out",
     "severity": "ERROR"
   }
   ```

---

### 시나리오 3: PEM 키 파일 오류

1. **잘못된 PEM 키 파일로 스캔**
   - "Use PEM Key File" 옵션 선택
   - 잘못된 키 파일 업로드

2. **예상 결과**
   ```json
   {
     "status": "ERROR",
     "details": "SSH 연결 실패: SSH 연결 오류: ...",
     "severity": "ERROR"
   }
   ```

---

## 📊 자동화 테스트 실행

### 단위 테스트
```bash
# SSH Utils 테스트
python -m pytest test_ssh_connection.py::TestSSHUtilsHelper -v

# 단일 모듈 테스트
python -m pytest test_ssh_connection.py::TestSSHConnectionHandling::test_authentication_failure -v

# 전체 모듈 일괄 테스트
python -m pytest test_ssh_connection.py::TestMultipleModulesSSHHandling -v
```

### 통합 테스트
```bash
# 전체 테스트 실행
python -m pytest test_ssh_connection.py -v

# 커버리지 확인
python -m pytest test_ssh_connection.py --cov=modules.os --cov=ssh_utils -v
```

---

## 🔍 디버깅

### 로그 확인
```bash
# Scanner 로그 확인
tail -f Scanner/cli_debug.log

# SSH 연결 오류 로그
grep "SSH" Scanner/cli_debug.log | grep "ERROR"
```

### 개별 모듈 테스트
```python
# Python 인터프리터에서 직접 테스트
import sys
sys.path.insert(0, '/Users/user/Documents/Mini_PJT2/Scanner')

from modules.os import linux_account

# SSH 연결 실패 테스트
result = linux_account.scan(
    ssh_host="invalid.host",
    ssh_user="user",
    ssh_pass="pass"
)

print(result['status'])  # 'ERROR' 출력 예상
print(result['details'])  # 에러 메시지 출력
```

---

## ✨ 개선 사항

### 이전 (문제점)
```python
# SSH 연결 실패 시 예외 발생 → 전체 스캔 중단
ssh.connect(ssh_host, ...)
# AuthenticationException → 프로그램 종료!
```

### 현재 (해결됨)
```python
# SSH 연결 실패 시 ERROR 결과 반환
ssh, error = safe_ssh_connect(ssh_host, ssh_user, ssh_pass)

if error:
    # 명확한 에러 메시지와 함께 ERROR 상태 반환
    return create_error_result('모듈명', error, 'ERROR')

# 정상 스캔 진행...
```

---

## 📝 주요 변경 내용

### ssh_utils.py (신규 생성)
- `safe_ssh_connect()`: 안전한 SSH 연결
- `create_error_result()`: 표준 ERROR 결과 생성
- `execute_ssh_command()`: 안전한 명령 실행

### 모든 인프라 모듈 (34개)
```python
# 변경 전
try:
    ssh = paramiko.SSHClient()
    ssh.connect(...)  # 예외 발생 시 전체 중단

except paramiko.AuthenticationException:
    result['status'] = 'ERROR'
```

```python
# 변경 후
ssh, error = safe_ssh_connect(...)

if error:
    return create_error_result('모듈명', error)  # 즉시 ERROR 반환

try:
    # 정상 스캔 로직
except Exception as e:
    # 스캔 중 오류만 처리
```

---

## 🎯 결론

✅ **34개 모든 인프라 모듈이 SSH 연결 실패를 안전하게 처리합니다.**

- 인증 실패
- 네트워크 오류
- 타임아웃
- 권한 거부
- 잘못된 PEM 키

모든 경우에 대해 명확한 에러 메시지와 함께 ERROR 상태를 반환하며,
스캔이 중단되지 않고 보고서가 정상적으로 생성됩니다.
