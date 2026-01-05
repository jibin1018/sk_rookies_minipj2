"""
JavaScript 라이브러리 취약점 점검

페이지에 로드된 JS 라이브러리의 버전을 확인하고 알려진 취약점을 탐지합니다.
"""
import requests
import re


def scan(target_url):
    result = {
        'name': 'JavaScript 라이브러리 점검',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'JS 라이브러리 최신 버전 유지, SRI 해시 사용',
        'details': ''
    }
    
    details = []
    
    # 알려진 취약 버전
    VULNERABLE_VERSIONS = {
        'jquery': {
            'pattern': r'jquery[/-]?v?(\d+\.\d+\.?\d*)',
            'vulnerable': [
                ('< 1.9.0', 'XSS via $(selector)'),
                ('< 3.5.0', 'XSS in jQuery.htmlPrefilter'),
            ]
        },
        'angular': {
            'pattern': r'angular[/-]?v?(\d+\.\d+\.?\d*)',
            'vulnerable': [
                ('< 1.6.0', 'Sandbox escape'),
            ]
        },
        'bootstrap': {
            'pattern': r'bootstrap[/-]?v?(\d+\.\d+\.?\d*)',
            'vulnerable': [
                ('< 3.4.0', 'XSS vulnerability'),
                ('< 4.3.1', 'XSS in data-template'),
            ]
        },
        'lodash': {
            'pattern': r'lodash[/-]?v?(\d+\.\d+\.?\d*)',
            'vulnerable': [
                ('< 4.17.12', 'Prototype pollution'),
            ]
        },
        'moment': {
            'pattern': r'moment[/-]?v?(\d+\.\d+\.?\d*)',
            'vulnerable': [
                ('< 2.29.2', 'ReDoS vulnerability'),
            ]
        },
        'vue': {
            'pattern': r'vue[/-]?v?(\d+\.\d+\.?\d*)',
            'vulnerable': [
                ('< 2.5.17', 'XSS through SSR'),
            ]
        },
        'react': {
            'pattern': r'react[/-]?v?(\d+\.\d+\.?\d*)',
            'vulnerable': []
        },
    }
    
    try:
        details.append("[JS-1] JavaScript 라이브러리 탐지\n")
        
        response = requests.get(target_url, timeout=10, verify=False)
        html = response.text
        
        found_libs = []
        vulnerable_libs = []
        
        # HTML에서 스크립트 URL 추출
        script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        
        details.append(f"  발견된 스크립트: {len(script_urls)}개\n")
        
        # 인라인 및 외부 스크립트에서 버전 탐지
        for lib_name, lib_info in VULNERABLE_VERSIONS.items():
            pattern = lib_info['pattern']
            
            # URL에서 탐지
            for url in script_urls:
                match = re.search(pattern, url, re.I)
                if match:
                    version = match.group(1)
                    found_libs.append({
                        'name': lib_name,
                        'version': version,
                        'source': 'url'
                    })
            
            # HTML 내용에서 탐지
            match = re.search(pattern, html, re.I)
            if match:
                version = match.group(1)
                if not any(f['name'] == lib_name for f in found_libs):
                    found_libs.append({
                        'name': lib_name,
                        'version': version,
                        'source': 'inline'
                    })
        
        # 버전 검사
        details.append("[JS-2] 라이브러리 버전 분석\n")
        
        for lib in found_libs:
            lib_name = lib['name']
            version = lib['version']
            
            details.append(f"  {lib_name}: v{version}")
            
            # 취약 버전 확인
            if lib_name in VULNERABLE_VERSIONS:
                for vuln_range, vuln_desc in VULNERABLE_VERSIONS[lib_name]['vulnerable']:
                    if _is_vulnerable(version, vuln_range):
                        vulnerable_libs.append({
                            'name': lib_name,
                            'version': version,
                            'vulnerability': vuln_desc
                        })
                        details.append(f"    ✗ 취약: {vuln_desc}")
                        break
                else:
                    details.append(f"    ✓ 안전")
        
        if not found_libs:
            details.append("  • 주요 JS 라이브러리 미감지")
        
        # 요약
        details.append("\n[JS-3] 보안 요약")
        
        if vulnerable_libs:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'] = [
                f"{v['name']} v{v['version']}: {v['vulnerability']}"
                for v in vulnerable_libs
            ]
            details.append(f"\n  취약한 라이브러리: {len(vulnerable_libs)}개")
        else:
            details.append("\n  ✓ 알려진 취약 버전 미사용")
        
        # SRI 확인
        sri_count = len(re.findall(r'integrity=["\'][^"\']+["\']', html, re.I))
        if sri_count > 0:
            details.append(f"\n  ✓ SRI 사용: {sri_count}개 스크립트")
        else:
            if script_urls:
                details.append("\n  ⚠ SRI (Subresource Integrity) 미사용")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result


def _is_vulnerable(version, vuln_range):
    """버전이 취약 범위에 해당하는지 확인"""
    try:
        # "< X.Y.Z" 형식 파싱
        if vuln_range.startswith('< '):
            max_ver = vuln_range[2:]
            return _compare_versions(version, max_ver) < 0
        return False
    except:
        return False


def _compare_versions(v1, v2):
    """버전 비교: v1 < v2 면 음수, v1 > v2 면 양수"""
    def normalize(v):
        return [int(x) for x in re.sub(r'[^\d.]', '', v).split('.')]
    
    parts1 = normalize(v1)
    parts2 = normalize(v2)
    
    for i in range(max(len(parts1), len(parts2))):
        p1 = parts1[i] if i < len(parts1) else 0
        p2 = parts2[i] if i < len(parts2) else 0
        if p1 != p2:
            return p1 - p2
    return 0
