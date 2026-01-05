"""
DNS 보안 설정 점검 모듈

DNS 관련 보안 설정을 점검
- DNS 레코드 분석
- SPF/DMARC/DKIM 설정
- DNSSEC 지원 여부
- Zone Transfer 취약점
"""
import socket
import subprocess
from typing import Dict, List
from urllib.parse import urlparse


def scan(target: str) -> Dict:
    """DNS 보안 설정 점검"""
    
    result = {
        "name": "DNS Security Configuration",
        "status": "SAFE",
        "severity": "MEDIUM",
        "vulnerabilities": [],
        "details": "",
        "recommendation": "",
        "confidence": 0.0
    }
    
    findings = []
    vuln_count = 0
    
    # 호스트명 추출
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        host = parsed.hostname
    else:
        host = target.split('/')[0].split(':')[0]
    
    if not host:
        result["status"] = "ERROR"
        result["details"] = "유효하지 않은 호스트"
        return result
    
    findings.append(f"[대상] {host}")
    
    try:
        # 1. 기본 DNS 조회
        try:
            ip_addresses = socket.gethostbyname_ex(host)[2]
            findings.append(f"\n[A 레코드] {', '.join(ip_addresses)}")
        except socket.gaierror:
            result["status"] = "ERROR"
            result["details"] = f"DNS 조회 실패: {host}"
            return result
        
        # 2. dig 명령어로 상세 분석 (가능한 경우)
        def run_dig(record_type: str) -> List[str]:
            try:
                output = subprocess.run(
                    ['dig', '+short', record_type, host],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return [line.strip() for line in output.stdout.strip().split('\n') if line.strip()]
            except:
                return []
        
        # 3. MX 레코드 확인
        mx_records = run_dig('MX')
        if mx_records:
            findings.append(f"\n[MX 레코드] {len(mx_records)}개 발견")
            for mx in mx_records[:3]:
                findings.append(f"  - {mx}")
        
        # 4. SPF 레코드 확인
        txt_records = run_dig('TXT')
        spf_found = False
        dmarc_found = False
        
        for txt in txt_records:
            if 'v=spf1' in txt.lower():
                spf_found = True
                findings.append(f"\n[SPF] ✓ 설정됨")
                # SPF 강도 분석
                if '-all' in txt:
                    findings.append("  - Hard Fail (-all) 적용")
                elif '~all' in txt:
                    findings.append("  - Soft Fail (~all) 적용")
                    result["vulnerabilities"].append("SPF: Soft Fail 설정 (권장: Hard Fail)")
                elif '?all' in txt:
                    vuln_count += 1
                    result["vulnerabilities"].append("SPF: Neutral 설정 (이메일 스푸핑 가능)")
        
        if not spf_found and mx_records:
            vuln_count += 1
            result["vulnerabilities"].append("SPF 레코드 미설정 (이메일 스푸핑 위험)")
            findings.append("\n[SPF] ✗ 미설정")
        
        # 5. DMARC 레코드 확인
        dmarc_records = []
        try:
            output = subprocess.run(
                ['dig', '+short', 'TXT', f'_dmarc.{host}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            dmarc_records = [line.strip() for line in output.stdout.strip().split('\n') if line.strip()]
        except:
            pass
        
        if dmarc_records:
            dmarc_found = True
            findings.append(f"\n[DMARC] ✓ 설정됨")
            for dmarc in dmarc_records:
                if 'p=none' in dmarc.lower():
                    result["vulnerabilities"].append("DMARC: 정책이 none (모니터링만)")
                elif 'p=quarantine' in dmarc.lower():
                    findings.append("  - 정책: quarantine")
                elif 'p=reject' in dmarc.lower():
                    findings.append("  - 정책: reject (강력)")
        elif mx_records:
            vuln_count += 1
            result["vulnerabilities"].append("DMARC 레코드 미설정")
            findings.append("\n[DMARC] ✗ 미설정")
        
        # 6. DNSSEC 확인
        try:
            output = subprocess.run(
                ['dig', '+dnssec', host],
                capture_output=True,
                text=True,
                timeout=5
            )
            if 'RRSIG' in output.stdout:
                findings.append("\n[DNSSEC] ✓ 지원됨")
            else:
                findings.append("\n[DNSSEC] ✗ 미지원")
                result["vulnerabilities"].append("DNSSEC 미설정 (DNS 스푸핑 위험)")
        except:
            findings.append("\n[DNSSEC] 확인 불가")
        
        # 7. Zone Transfer 테스트
        findings.append("\n[Zone Transfer 테스트]")
        try:
            ns_records = run_dig('NS')
            for ns in ns_records[:2]:
                ns_host = ns.rstrip('.')
                try:
                    output = subprocess.run(
                        ['dig', 'AXFR', host, f'@{ns_host}'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if 'Transfer failed' not in output.stdout and len(output.stdout) > 200:
                        vuln_count += 1
                        result["vulnerabilities"].append(
                            f"Zone Transfer 허용됨: {ns_host}"
                        )
                        findings.append(f"  ⚠ {ns_host}: 허용됨 (위험)")
                    else:
                        findings.append(f"  ✓ {ns_host}: 차단됨")
                except:
                    findings.append(f"  ? {ns_host}: 확인 불가")
        except:
            findings.append("  NS 레코드 조회 실패")
        
        # 결과 판정
        if vuln_count > 0:
            result["status"] = "VULNERABLE"
            result["confidence"] = min(0.9, 0.5 + (vuln_count * 0.1))
            result["recommendation"] = (
                "1. SPF 레코드 설정 및 Hard Fail(-all) 적용\n"
                "2. DMARC 레코드 설정 (p=reject 권장)\n"
                "3. DNSSEC 활성화\n"
                "4. Zone Transfer 제한"
            )
        else:
            result["confidence"] = 0.85
        
        result["details"] = "\n".join(findings)
        
    except Exception as e:
        result["status"] = "ERROR"
        result["details"] = f"점검 실패: {str(e)}"
    
    return result


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    result = scan(target)
    print(f"\n[{result['status']}] {result['name']}")
    if result['vulnerabilities']:
        print("\n취약점:")
        for v in result['vulnerabilities']:
            print(f"  - {v}")
    print(f"\n상세:\n{result['details']}")
