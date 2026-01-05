"""
SSL 인증서 분석

SSL/TLS 인증서의 보안 상태를 점검합니다.
"""
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime


def scan(target_url):
    result = {
        'name': 'SSL 인증서 분석',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '인증서 만료 전 갱신, 강력한 암호화 사용, HSTS 설정',
        'details': ''
    }
    
    details = []
    
    # URL 파싱
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    
    if parsed.scheme != 'https':
        # HTTP인 경우 443 포트 확인
        port = 443
    
    try:
        details.append(f"[SSL-1] 인증서 정보: {hostname}:{port}")
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                version = ssock.version()
                
                if cert:
                    # 발급자
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    details.append(f"  발급자: {issuer.get('organizationName', 'Unknown')}")
                    
                    # 주체
                    subject = dict(x[0] for x in cert.get('subject', []))
                    details.append(f"  주체: {subject.get('commonName', hostname)}")
                    
                    # 만료일
                    not_after = cert.get('notAfter')
                    if not_after:
                        expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expire_date - datetime.now()).days
                        details.append(f"  만료일: {not_after}")
                        details.append(f"  남은 일수: {days_left}일")
                        
                        if days_left < 0:
                            result['status'] = 'VULNERABLE'
                            result['severity'] = 'CRITICAL'
                            result['vulnerabilities'].append("인증서 만료됨")
                            details.append("    ✗ 인증서 만료!")
                        elif days_left < 30:
                            result['vulnerabilities'].append(f"인증서 곧 만료 ({days_left}일)")
                            details.append("    ⚠ 곧 만료 예정")
                            if result['status'] == 'SAFE':
                                result['status'] = 'VULNERABLE'
                                result['severity'] = 'LOW'
                        else:
                            details.append("    ✓ 유효")
                    
                    # SAN (Subject Alternative Names)
                    san = cert.get('subjectAltName', [])
                    if san:
                        san_domains = [x[1] for x in san if x[0] == 'DNS']
                        details.append(f"  SAN: {', '.join(san_domains[:5])}")
                        if len(san_domains) > 5:
                            details.append(f"       ... 외 {len(san_domains) - 5}개")
                
                # 프로토콜 버전
                details.append(f"\n[SSL-2] 프로토콜: {version}")
                
                if 'TLSv1.0' in version or 'TLSv1.1' in version:
                    result['vulnerabilities'].append(f"취약한 프로토콜: {version}")
                    details.append(f"  ✗ {version} 사용 (취약, TLSv1.2+ 권장)")
                    result['status'] = 'VULNERABLE'
                elif 'TLSv1.2' in version:
                    details.append("  ✓ TLSv1.2 (권장)")
                elif 'TLSv1.3' in version:
                    details.append("  ✓ TLSv1.3 (최신, 권장)")
                
                # 암호화 스위트
                if cipher:
                    details.append(f"\n[SSL-3] 암호화: {cipher[0]}")
                    details.append(f"  비트: {cipher[2]}")
                    
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
                    for weak in weak_ciphers:
                        if weak in cipher[0].upper():
                            result['vulnerabilities'].append(f"취약한 암호화: {weak}")
                            details.append(f"  ✗ 취약한 암호화 사용: {weak}")
                            result['status'] = 'VULNERABLE'
                            break
                    else:
                        details.append("  ✓ 강력한 암호화")
        
    except ssl.SSLError as e:
        details.append(f"  SSL 오류: {str(e)}")
        result['status'] = 'ERROR'
    except socket.timeout:
        details.append(f"  연결 타임아웃: {hostname}:{port}")
    except ConnectionRefusedError:
        details.append(f"  연결 거부: {hostname}:{port}")
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
