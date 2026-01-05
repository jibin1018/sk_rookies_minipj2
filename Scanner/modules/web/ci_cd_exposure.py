"""
CI/CD 파이프라인 노출 점검

Jenkins, GitLab CI 등 CI/CD 도구 노출을 탐지합니다.
"""
import requests
from urllib.parse import urljoin


def scan(target_url):
    result = {
        'name': 'CI/CD 파이프라인 노출',
        'category': 'DevOps Security',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'CI/CD 도구 외부 접근 차단, 인증 강화',
        'details': ''
    }
    
    details = []
    
    # CI/CD 도구 엔드포인트 및 시그니처
    CICD_ENDPOINTS = [
        # Jenkins
        ('/jenkins/', 'Jenkins', ['Jenkins', 'Dashboard [Jenkins]', 'Jenkins ver.']),
        ('/jenkins/login', 'Jenkins', ['jenkins', 'sign in']),
        ('/jenkins/api/json', 'Jenkins API', ['"_class":', 'nodeDescription']),
        
        # GitLab
        ('/gitlab/', 'GitLab', ['GitLab', 'gitlab-ci']),
        ('/-/health', 'GitLab Health', ['GitLab OK']),
        
        # GitHub Actions (Self-hosted)
        ('/actions/', 'GitHub Actions', ['actions', 'workflow']),
        
        # Travis CI
        ('/travis/', 'Travis CI', ['Travis CI']),
        
        # CircleCI
        ('/circleci/', 'CircleCI', ['CircleCI']),
        
        # Drone CI
        ('/drone/', 'Drone CI', ['Drone', 'drone.io']),
        
        # TeamCity
        ('/teamcity/', 'TeamCity', ['TeamCity', 'JetBrains']),
        ('/teamcity/login.html', 'TeamCity', ['Log in to TeamCity']),
        
        # Bamboo
        ('/bamboo/', 'Bamboo', ['Bamboo', 'Atlassian']),
        
        # ArgoCD
        ('/argocd/', 'ArgoCD', ['Argo CD', 'argo']),
        ('/argocd/api/v1/projects', 'ArgoCD API', ['items', 'metadata']),
        
        # 기타
        ('/.github/workflows/', 'GitHub Workflows', ['yaml', 'yml']),
        ('/.gitlab-ci.yml', 'GitLab CI Config', ['stages:', 'script:']),
        ('/Jenkinsfile', 'Jenkinsfile', ['pipeline', 'agent', 'stages']),
    ]
    
    try:
        details.append("[CICD-1] CI/CD 도구 노출 점검\n")
        
        exposed_tools = []
        
        parsed_base = urljoin(target_url, '/')
        
        for path, tool_name, signatures in CICD_ENDPOINTS:
            url = urljoin(parsed_base, path)
            
            try:
                response = requests.get(
                    url,
                    timeout=5,
                    verify=False,
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    for sig in signatures:
                        if sig.lower() in content:
                            exposed_tools.append({
                                'tool': tool_name,
                                'path': path,
                                'signature': sig
                            })
                            details.append(f"  ✗ {tool_name} 발견: {path}")
                            break
                
                elif response.status_code in [401, 403]:
                    # 인증 필요 = 존재는 함
                    details.append(f"  ⚠ {tool_name} 존재 (인증 필요): {path}")
                    
            except:
                continue
        
        # 일반적인 CI/CD 파일 노출
        details.append("\n[CICD-2] 설정 파일 노출")
        
        config_files = [
            '.travis.yml', '.circleci/config.yml', 
            'azure-pipelines.yml', 'bitbucket-pipelines.yml',
            '.drone.yml', 'Jenkinsfile',
        ]
        
        for config in config_files:
            url = urljoin(parsed_base, config)
            try:
                response = requests.get(url, timeout=3, verify=False)
                if response.status_code == 200 and len(response.text) > 10:
                    result['vulnerabilities'].append(f"CI/CD 설정 노출: {config}")
                    details.append(f"  ✗ 설정 파일 노출: {config}")
            except:
                continue
        
        # 요약
        details.append("\n[CICD-3] 보안 요약")
        
        if exposed_tools:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'].extend([
                f"{t['tool']} 노출: {t['path']}" for t in exposed_tools
            ])
            details.append(f"\n  ✗ 노출된 도구: {len(exposed_tools)}개")
        
        if result['vulnerabilities']:
            details.append(f"\n  총 취약점: {len(result['vulnerabilities'])}개")
        else:
            details.append("\n  ✓ CI/CD 도구 노출 미발견")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
