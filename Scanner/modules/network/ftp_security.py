"""
FTP 서비스 보안 점검

FTP 서버의 보안 설정을 점검합니다.
"""
import socket


def scan(target_url):
    """FTP 서비스 보안 점검"""
    result = {
        'name': 'FTP 서비스 보안 점검',
        'category': 'Network Security',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'FTP 대신 SFTP/FTPS 사용 권장, Anonymous 로그인 비활성화',
        'details': ''
    }
    
    details = []
    
    # URL에서 호스트 추출
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    host = parsed.hostname or target_url.replace('http://', '').replace('https://', '').split('/')[0]
    
    try:
        details.append(f"[FTP-1] FTP 서비스 연결: {host}:21")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        try:
            sock.connect((host, 21))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            details.append(f"  배너: {banner}")
            
            # FTP 서버 타입 확인
            if 'vsftpd' in banner.lower():
                details.append("  서버: vsftpd")
            elif 'proftpd' in banner.lower():
                details.append("  서버: ProFTPD")
            elif 'filezilla' in banner.lower():
                details.append("  서버: FileZilla Server")
            elif 'microsoft' in banner.lower():
                details.append("  서버: Microsoft FTP")
            
            # Anonymous 로그인 테스트
            details.append("\n[FTP-2] Anonymous 로그인 테스트")
            
            sock.send(b'USER anonymous\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '331' in response:  # Password required
                sock.send(b'PASS anonymous@test.com\r\n')
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '230' in response:  # Login successful
                    result['vulnerabilities'].append("Anonymous FTP 로그인 허용")
                    result['status'] = 'VULNERABLE'
                    details.append("  ✗ Anonymous 로그인 허용됨 (위험)")
                    
                    # 파일 리스팅 시도
                    sock.send(b'PASV\r\n')
                    sock.recv(1024)
                    sock.send(b'LIST\r\n')
                    details.append("  ✗ 파일 리스팅 접근 가능")
                else:
                    details.append("  ✓ Anonymous 로그인 거부됨")
            elif '530' in response:  # Login denied
                details.append("  ✓ Anonymous 로그인 비활성화")
            else:
                details.append(f"  응답: {response[:50]}")
            
            sock.close()
            
        except socket.timeout:
            details.append("  • FTP 포트 연결 타임아웃")
        except ConnectionRefusedError:
            details.append("  • FTP 포트(21) 닫힘")
            details.append("  ✓ FTP 서비스 미사용")
        except Exception as e:
            details.append(f"  • 연결 오류: {str(e)}")
        
        # FTPS 포트 확인
        details.append("\n[FTP-3] FTPS (암호화 FTP) 확인")
        
        ftps_ports = [990, 989]
        ftps_found = False
        
        for port in ftps_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                sock.connect((host, port))
                sock.close()
                ftps_found = True
                details.append(f"  ✓ FTPS 포트 {port} 열림")
            except:
                pass
        
        if not ftps_found:
            details.append("  • FTPS 포트 미발견")
            if result['status'] == 'SAFE':
                details.append("  ⚠ FTP 사용 시 FTPS 또는 SFTP 권장")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
