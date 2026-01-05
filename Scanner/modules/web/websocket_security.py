"""
WebSocket 보안 점검

WebSocket 엔드포인트의 보안 설정을 확인합니다.
"""
import socket
import ssl
import base64
import hashlib
from urllib.parse import urlparse


def scan(target_url):
    result = {
        'name': 'WebSocket 보안',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'Origin 검증, 인증 토큰 사용, WSS(암호화) 사용',
        'details': ''
    }
    
    details = []
    
    # WebSocket 엔드포인트 후보
    WS_ENDPOINTS = [
        '/ws',
        '/websocket',
        '/socket.io/',
        '/sockjs/',
        '/cable',
        '/realtime',
        '/live',
    ]
    
    try:
        details.append("[WS-1] WebSocket 엔드포인트 탐지\n")
        
        parsed = urlparse(target_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        
        ws_found = []
        
        for endpoint in WS_ENDPOINTS:
            try:
                # WebSocket Handshake 시도
                ws_key = base64.b64encode(b'security-test-key1').decode()
                
                request = (
                    f"GET {endpoint} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {ws_key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n"
                    f"Origin: https://evil.com\r\n"  # 악성 Origin
                    f"\r\n"
                )
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                if use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=host)
                
                sock.connect((host, port))
                sock.send(request.encode())
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                # WebSocket 업그레이드 성공 확인
                if '101' in response and 'Switching Protocols' in response:
                    ws_found.append({
                        'endpoint': endpoint,
                        'accepts_evil_origin': True
                    })
                    details.append(f"  발견: {endpoint}")
                    details.append(f"    ✗ 악성 Origin 허용!")
                elif '101' in response:
                    ws_found.append({
                        'endpoint': endpoint,
                        'accepts_evil_origin': False
                    })
                    details.append(f"  발견: {endpoint}")
                elif '403' in response or '401' in response:
                    details.append(f"  {endpoint}: Origin 검증 활성화")
                    
            except socket.timeout:
                continue
            except Exception as e:
                continue
        
        if not ws_found:
            details.append("  WebSocket 엔드포인트 미발견")
        
        # 보안 분석
        details.append("\n[WS-2] 보안 분석")
        
        # WSS (암호화) 확인
        if use_ssl:
            details.append("  ✓ WSS 사용 (암호화됨)")
        else:
            details.append("  ⚠ WS 사용 (암호화 없음)")
            result['vulnerabilities'].append("암호화되지 않은 WebSocket (WS)")
        
        # Origin 검증
        evil_origin_accepted = any(ws.get('accepts_evil_origin') for ws in ws_found)
        
        if evil_origin_accepted:
            result['vulnerabilities'].append("Cross-Origin WebSocket 허용")
            details.append("  ✗ Cross-Origin 허용 (CSWSH 취약)")
        
        # 요약
        details.append("\n[WS-3] 보안 요약")
        
        if result['vulnerabilities']:
            result['status'] = 'VULNERABLE'
            details.append(f"\n  취약점: {len(result['vulnerabilities'])}개")
            for vuln in result['vulnerabilities']:
                details.append(f"    - {vuln}")
        else:
            if ws_found:
                details.append("\n  ✓ WebSocket 보안 양호")
            else:
                details.append("\n  WebSocket 미사용")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
