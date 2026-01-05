"""
SSH 서비스 보안 감사 (원격 - 배너 분석 기반)

SSH 포트에 연결하여 보안 설정을 점검합니다.
"""
import socket
import re


def scan(target_url):
    """SSH 서비스 보안 점검 (URL 기반)"""
    result = {
        'name': 'SSH 서비스 보안 감사',
        'category': 'Network Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'SSH 프로토콜 2 사용, 최신 버전 유지, 강력한 암호화',
        'details': ''
    }
    
    details = []
    
    # URL에서 호스트 추출
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    host = parsed.hostname or target_url.replace('http://', '').replace('https://', '').split('/')[0]
    
    try:
        details.append(f"[SSH-1] SSH 배너 분석: {host}:22")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        try:
            sock.connect((host, 22))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            details.append(f"  배너: {banner}")
            
            # SSH 프로토콜 버전 확인
            if 'SSH-1' in banner and 'SSH-2' not in banner:
                result['vulnerabilities'].append("SSH Protocol 1 사용 (취약)")
                result['status'] = 'VULNERABLE'
                result['severity'] = 'HIGH'
                details.append("  ✗ SSH Protocol 1 (취약, 반드시 2로 업그레이드)")
            elif 'SSH-2' in banner:
                details.append("  ✓ SSH Protocol 2 사용")
            
            # 버전 확인
            version_match = re.search(r'OpenSSH[_-]?(\d+\.\d+)', banner)
            if version_match:
                version = float(version_match.group(1))
                details.append(f"  OpenSSH 버전: {version}")
                
                if version < 7.0:
                    result['vulnerabilities'].append(f"오래된 OpenSSH 버전: {version}")
                    result['status'] = 'VULNERABLE'
                    details.append(f"  ⚠ 오래된 버전 (7.0 이상 권장)")
                elif version < 8.0:
                    details.append(f"  ⚠ 업데이트 권장 (8.0+)")
                else:
                    details.append(f"  ✓ 최신 버전")
            
            # Dropbear 확인
            if 'dropbear' in banner.lower():
                details.append("  서버: Dropbear SSH")
            
        except socket.timeout:
            details.append("  • SSH 포트 연결 타임아웃")
        except ConnectionRefusedError:
            details.append("  • SSH 포트(22) 닫힘")
        except Exception as e:
            details.append(f"  • 연결 오류: {str(e)}")
        
        # 대체 포트 확인
        details.append("\n[SSH-2] 대체 SSH 포트 확인")
        alt_ports = [2222, 22222, 222]
        
        for port in alt_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                sock.connect((host, port))
                alt_banner = sock.recv(256).decode('utf-8', errors='ignore')
                sock.close()
                if 'SSH' in alt_banner:
                    details.append(f"  발견: {host}:{port}")
            except:
                pass
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
