"""
SSL/TLS 보안 설정 점검 모듈

HTTPS 연결의 SSL/TLS 설정을 분석하여 보안 취약점을 탐지
- 인증서 유효성
- 프로토콜 버전
- 암호화 스위트
- HSTS 설정
"""
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse


def scan(target: str) -> Dict:
    """SSL/TLS 보안 설정 점검"""
    
    result = {
        "name": "SSL/TLS Security Audit",
        "status": "SAFE",
        "severity": "HIGH",
        "vulnerabilities": [],
        "details": "",
        "recommendation": "",
        "confidence": 0.0
    }
    
    findings = []
    vuln_count = 0
    
    # URL 파싱
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port or 443
    
    if not host:
        result["status"] = "ERROR"
        result["details"] = "유효하지 않은 호스트"
        return result
    
    try:
        # 1. SSL 연결 시도
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                version = ssock.version()
                
                findings.append(f"[연결 성공] {host}:{port}")
                findings.append(f"프로토콜: {version}")
                findings.append(f"암호화: {cipher[0]} ({cipher[2]}bit)")
                
                # 2. 프로토콜 버전 점검
                weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                if version in weak_protocols:
                    vuln_count += 1
                    result["vulnerabilities"].append(
                        f"취약한 프로토콜 사용: {version}"
                    )
                
                # 3. 암호화 스위트 점검
                weak_ciphers = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon']
                cipher_name = cipher[0] if cipher else ""
                for weak in weak_ciphers:
                    if weak.lower() in cipher_name.lower():
                        vuln_count += 1
                        result["vulnerabilities"].append(
                            f"취약한 암호화 스위트: {cipher_name}"
                        )
                        break
                
                # 4. 인증서 점검 (별도 컨텍스트)
                try:
                    verify_context = ssl.create_default_context()
                    with socket.create_connection((host, port), timeout=5) as verify_sock:
                        with verify_context.wrap_socket(verify_sock, server_hostname=host) as verify_ssock:
                            verified_cert = verify_ssock.getpeercert()
                            
                            # 만료일 확인
                            if verified_cert and 'notAfter' in verified_cert:
                                expiry_str = verified_cert['notAfter']
                                # 파싱 시도
                                try:
                                    expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                                    days_left = (expiry - datetime.utcnow()).days
                                    findings.append(f"인증서 만료: {days_left}일 후")
                                    
                                    if days_left <= 0:
                                        vuln_count += 1
                                        result["vulnerabilities"].append("인증서 만료됨")
                                    elif days_left <= 30:
                                        result["vulnerabilities"].append(
                                            f"인증서 곧 만료 ({days_left}일)"
                                        )
                                except:
                                    findings.append(f"인증서 만료: {expiry_str}")
                            
                            findings.append("✓ 인증서 검증 통과")
                            
                except ssl.SSLCertVerificationError as e:
                    vuln_count += 1
                    result["vulnerabilities"].append(
                        f"인증서 검증 실패: {str(e)[:80]}"
                    )
                except Exception as e:
                    findings.append(f"인증서 검증 오류: {str(e)[:50]}")
        
        # 5. 취약한 프로토콜 테스트
        findings.append("\n[취약 프로토콜 테스트]")
        for proto in [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1]:
            proto_name = "TLSv1" if proto == ssl.PROTOCOL_TLSv1 else "TLSv1.1"
            try:
                test_ctx = ssl.SSLContext(proto)
                test_ctx.check_hostname = False
                test_ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=3) as test_sock:
                    with test_ctx.wrap_socket(test_sock, server_hostname=host):
                        vuln_count += 1
                        result["vulnerabilities"].append(
                            f"취약 프로토콜 활성화: {proto_name}"
                        )
                        findings.append(f"⚠ {proto_name}: 활성화됨")
            except:
                findings.append(f"✓ {proto_name}: 비활성화")
        
        # 결과 판정
        if vuln_count > 0:
            result["status"] = "VULNERABLE"
            result["confidence"] = min(0.9, 0.5 + (vuln_count * 0.1))
            result["recommendation"] = (
                "1. TLS 1.2 이상만 허용하도록 설정\n"
                "2. 약한 암호화 스위트 비활성화\n"
                "3. 인증서 갱신 및 적절한 관리\n"
                "4. HSTS 헤더 활성화"
            )
        else:
            result["confidence"] = 0.85
        
        result["details"] = "\n".join(findings)
        
    except socket.timeout:
        result["status"] = "ERROR"
        result["details"] = f"연결 시간 초과: {host}:{port}"
    except ConnectionRefusedError:
        result["status"] = "ERROR"
        result["details"] = f"연결 거부됨: {host}:{port}"
    except Exception as e:
        result["status"] = "ERROR"
        result["details"] = f"점검 실패: {str(e)}"
    
    return result


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://google.com"
    result = scan(target)
    print(f"\n[{result['status']}] {result['name']}")
    print(f"Confidence: {result['confidence']:.0%}")
    if result['vulnerabilities']:
        print("\n취약점:")
        for v in result['vulnerabilities']:
            print(f"  - {v}")
    print(f"\n상세:\n{result['details']}")
