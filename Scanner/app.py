#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
통합 보안 취약점 스캐너 API 서버
웹 애플리케이션 + 인프라 보안 진단
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import os
import json
from datetime import datetime
from scanner_engine import VulnerabilityScanner, InfraScanner
from claude_analyzer import ClaudeAnalyzer
import threading
import logging

# Flask 앱 초기화
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 스캔 상태 저장소 (프로덕션에서는 Redis 등 사용 권장)
scan_status = {}

# Claude 분석기 초기화
claude_analyzer = ClaudeAnalyzer()

# ============================================================================
# 웹 UI 라우트
# ============================================================================

@app.route('/')
def index():
    """메인 페이지"""
    return render_template('index.html')

@app.route('/report/<scan_id>')
def view_report(scan_id):
    """보고서 보기 페이지"""
    if scan_id not in scan_status:
        return "스캔을 찾을 수 없습니다", 404
    
    if scan_status[scan_id]['status'] != 'completed':
        return "스캔이 완료되지 않았습니다", 400
    
    return render_template('report.html', 
                         scan_id=scan_id,
                         data=scan_status[scan_id])

@app.route('/download/<scan_id>')
def download_report(scan_id):
    """보고서 파일 다운로드"""
    if scan_id not in scan_status:
        return "스캔을 찾을 수 없습니다", 404
    
    report_path = scan_status[scan_id].get('report_path')
    if not report_path or not os.path.exists(report_path):
        return "보고서 파일을 찾을 수 없습니다", 404
    
    return send_file(report_path, as_attachment=True)

# ============================================================================
# 웹 애플리케이션 스캔 API
# ============================================================================

@app.route('/api/scan/start', methods=['POST'])
def api_start_scan():
    """
    웹 애플리케이션 스캔 시작
    
    Request Body:
    {
        "target_url": "http://localhost:3000",
        "use_claude": true,
        "scan_types": ["sqli", "xss"] 또는 ["all"]
    }
    
    Response:
    {
        "success": true,
        "scan_id": "20250101_120000",
        "message": "스캔이 시작되었습니다"
    }
    """
    try:
        data = request.json
        target_url = data.get('target_url', '').strip()
        use_claude = data.get('use_claude', False)
        scan_types = data.get('scan_types', ['all'])
        
        # 입력 검증
        if not target_url:
            return jsonify({'error': '대상 URL을 입력하세요'}), 400
        
        # URL 형식 검증
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        # 스캔 ID 생성
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 스캔 상태 초기화
        scan_status[scan_id] = {
            'scan_id': scan_id,
            'type': 'web',
            'status': 'running',
            'progress': 0,
            'current_test': '스캔 초기화 중...',
            'results': [],
            'target_url': target_url,
            'use_claude': use_claude,
            'scan_types': scan_types,
            'claude_analysis': None,
            'started_at': datetime.now().isoformat(),
            'completed_at': None
        }
        
        # 백그라운드 스레드에서 스캔 실행
        thread = threading.Thread(
            target=run_web_scan_background, 
            args=(scan_id, target_url, use_claude, scan_types)
        )
        thread.daemon = True
        thread.start()
        
        logger.info(f"웹 스캔 시작: {scan_id} - {target_url}")
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': '스캔이 시작되었습니다'
        })
        
    except Exception as e:
        logger.error(f"스캔 시작 오류: {str(e)}")
        return jsonify({'error': str(e)}), 500

def run_web_scan_background(scan_id, target_url, use_claude, scan_types):
    """백그라운드 웹 스캔 실행"""
    try:
        logger.info(f"[{scan_id}] 스캔 실행 중...")
        
        # 스캐너 실행
        scanner = VulnerabilityScanner(
            target_url, 
            scan_status, 
            scan_id,
            scan_types=scan_types
        )
        results = scanner.scan_all()
        
        # 스캔 완료
        scan_status[scan_id]['status'] = 'completed'
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['results'] = results
        scan_status[scan_id]['completed_at'] = datetime.now().isoformat()
        
        logger.info(f"[{scan_id}] 스캔 완료 - {len(results)}개 테스트")
        
        # Claude AI 분석 (옵션)
        if use_claude and claude_analyzer.is_available():
            logger.info(f"[{scan_id}] Claude AI 분석 시작...")
            scan_status[scan_id]['current_test'] = 'Claude AI 분석 중...'
            
            try:
                analysis = claude_analyzer.analyze_scan_results(target_url, results)
                scan_status[scan_id]['claude_analysis'] = analysis
                logger.info(f"[{scan_id}] Claude 분석 완료")
            except Exception as e:
                logger.error(f"[{scan_id}] Claude 분석 오류: {str(e)}")
                scan_status[scan_id]['claude_analysis'] = {
                    'error': str(e),
                    'analysis': None
                }
        
        # 보고서 생성
        scan_status[scan_id]['current_test'] = '보고서 생성 중...'
        report_path = scanner.generate_report()
        scan_status[scan_id]['report_path'] = report_path
        
        scan_status[scan_id]['current_test'] = '스캔 완료!'
        logger.info(f"[{scan_id}] 보고서 생성 완료: {report_path}")
        
    except Exception as e:
        logger.error(f"[{scan_id}] 스캔 오류: {str(e)}")
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['error'] = str(e)
        scan_status[scan_id]['completed_at'] = datetime.now().isoformat()

@app.route('/api/scan/status/<scan_id>')
def api_scan_status(scan_id):
    """
    스캔 상태 조회
    
    Response:
    {
        "scan_id": "20250101_120000",
        "status": "running" | "completed" | "error",
        "progress": 75,
        "current_test": "SQL Injection 진단 중...",
        "started_at": "2025-01-01T12:00:00",
        "completed_at": "2025-01-01T12:05:00"
    }
    """
    if scan_id not in scan_status:
        return jsonify({'error': '스캔을 찾을 수 없습니다'}), 404
    
    return jsonify(scan_status[scan_id])

@app.route('/api/scan/results/<scan_id>')
def api_scan_results(scan_id):
    """
    스캔 결과 상세 조회
    
    Response:
    {
        "scan_id": "...",
        "target_url": "...",
        "status": "completed",
        "summary": {
            "total": 18,
            "vulnerable": 5,
            "safe": 13,
            "critical": 2,
            "high": 3
        },
        "results": [...],
        "claude_analysis": {...}
    }
    """
    if scan_id not in scan_status:
        return jsonify({'error': '스캔을 찾을 수 없습니다'}), 404
    
    if scan_status[scan_id]['status'] != 'completed':
        return jsonify({'error': '스캔이 완료되지 않았습니다'}), 400
    
    data = scan_status[scan_id]
    results = data['results']
    
    # 요약 통계
    summary = {
        'total': len(results),
        'vulnerable': sum(1 for r in results if r['status'] == 'VULNERABLE'),
        'safe': sum(1 for r in results if r['status'] == 'SAFE'),
        'error': sum(1 for r in results if r['status'] == 'ERROR'),
        'critical': sum(1 for r in results if r.get('severity') == 'CRITICAL' and r['status'] == 'VULNERABLE'),
        'high': sum(1 for r in results if r.get('severity') == 'HIGH' and r['status'] == 'VULNERABLE'),
        'medium': sum(1 for r in results if r.get('severity') == 'MEDIUM' and r['status'] == 'VULNERABLE'),
        'low': sum(1 for r in results if r.get('severity') == 'LOW' and r['status'] == 'VULNERABLE'),
    }
    
    return jsonify({
        'scan_id': scan_id,
        'target_url': data['target_url'],
        'type': data['type'],
        'status': data['status'],
        'started_at': data.get('started_at'),
        'completed_at': data.get('completed_at'),
        'summary': summary,
        'results': results,
        'claude_analysis': data.get('claude_analysis')
    })

# ============================================================================
# 인프라 스캔 API
# ============================================================================

@app.route('/api/infra/scan/start', methods=['POST'])
def api_start_infra_scan():
    """
    인프라 보안 스캔 시작
    
    Request Body:
    {
        "ssh_host": "192.168.1.100",
        "ssh_user": "admin",
        "ssh_pass": "password",
        "ssh_port": 22,
        "categories": ["os", "web_server", "db"] 또는 ["all"]
    }
    """
    try:
        data = request.json
        
        ssh_host = data.get('ssh_host', '').strip()
        ssh_user = data.get('ssh_user', '').strip()
        ssh_pass = data.get('ssh_pass', '').strip()
        ssh_port = data.get('ssh_port', 22)
        categories = data.get('categories', ['all'])
        
        # 입력 검증
        if not all([ssh_host, ssh_user, ssh_pass]):
            return jsonify({'error': 'SSH 접속 정보를 모두 입력하세요'}), 400
        
        # 스캔 ID 생성
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_infra")
        
        # 스캔 상태 초기화
        scan_status[scan_id] = {
            'scan_id': scan_id,
            'type': 'infrastructure',
            'status': 'running',
            'progress': 0,
            'current_test': '인프라 스캔 초기화 중...',
            'results': [],
            'target': ssh_host,
            'categories': categories,
            'started_at': datetime.now().isoformat(),
            'completed_at': None
        }
        
        # 백그라운드 스캔
        thread = threading.Thread(
            target=run_infra_scan_background,
            args=(scan_id, ssh_host, ssh_user, ssh_pass, ssh_port, categories)
        )
        thread.daemon = True
        thread.start()
        
        logger.info(f"인프라 스캔 시작: {scan_id} - {ssh_host}")
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': '인프라 스캔이 시작되었습니다'
        })
        
    except Exception as e:
        logger.error(f"인프라 스캔 시작 오류: {str(e)}")
        return jsonify({'error': str(e)}), 500

def run_infra_scan_background(scan_id, ssh_host, ssh_user, ssh_pass, ssh_port, categories):
    """백그라운드 인프라 스캔 실행"""
    try:
        logger.info(f"[{scan_id}] 인프라 스캔 실행 중...")
        
        scanner = InfraScanner(
            ssh_host, ssh_user, ssh_pass, ssh_port,
            scan_status, scan_id
        )
        
        results = scanner.scan_infrastructure(categories)
        
        scan_status[scan_id]['status'] = 'completed'
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['results'] = results
        scan_status[scan_id]['current_test'] = '스캔 완료!'
        scan_status[scan_id]['completed_at'] = datetime.now().isoformat()
        
        # 보고서 생성
        report_path = scanner.generate_report()
        scan_status[scan_id]['report_path'] = report_path
        
        logger.info(f"[{scan_id}] 인프라 스캔 완료")
        
    except Exception as e:
        logger.error(f"[{scan_id}] 인프라 스캔 오류: {str(e)}")
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['error'] = str(e)
        scan_status[scan_id]['completed_at'] = datetime.now().isoformat()

# ============================================================================
# 단일 테스트 API
# ============================================================================

@app.route('/api/test/<test_name>', methods=['POST'])
def api_single_test(test_name):
    """
    단일 취약점 테스트 실행
    
    Request Body:
    {
        "target_url": "http://localhost:3000"
    }
    """
    try:
        data = request.json
        target_url = data.get('target_url', '').strip()
        
        if not target_url:
            return jsonify({'error': '대상 URL을 입력하세요'}), 400
        
        from importlib import import_module
        module = import_module(f'modules.web.{test_name}')
        result = module.scan(target_url)
        
        logger.info(f"단일 테스트 완료: {test_name} - {target_url}")
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except ModuleNotFoundError:
        return jsonify({'error': f'테스트 모듈을 찾을 수 없습니다: {test_name}'}), 404
    except Exception as e:
        logger.error(f"단일 테스트 오류: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# 유틸리티 API
# ============================================================================

@app.route('/api/tests/list')
def api_tests_list():
    """
    사용 가능한 테스트 목록
    
    Response:
    {
        "web_tests": [...],
        "infra_tests": {...}
    }
    """
    web_tests = []
    for module_name, test_name, severity in VulnerabilityScanner.WEB_TESTS:
        web_tests.append({
            'id': module_name,
            'name': test_name,
            'severity': severity,
            'category': 'Web Application'
        })
    
    infra_tests = {}
    for category, tests in InfraScanner.INFRA_TESTS.items():
        infra_tests[category] = [
            {
                'id': module_name,
                'name': test_name,
                'severity': severity
            }
            for module_name, test_name, severity in tests
        ]
    
    return jsonify({
        'web_tests': web_tests,
        'infra_tests': infra_tests,
        'total_web': len(web_tests),
        'total_infra': sum(len(tests) for tests in infra_tests.values())
    })

@app.route('/api/scans/history')
def api_scans_history():
    """
    스캔 히스토리 조회
    
    Response:
    {
        "scans": [
            {
                "scan_id": "...",
                "type": "web" | "infrastructure",
                "status": "completed",
                "target": "...",
                "started_at": "...",
                "summary": {...}
            }
        ]
    }
    """
    scans = []
    
    for scan_id, data in scan_status.items():
        scan_info = {
            'scan_id': scan_id,
            'type': data.get('type'),
            'status': data.get('status'),
            'target': data.get('target_url') or data.get('target'),
            'started_at': data.get('started_at'),
            'completed_at': data.get('completed_at')
        }
        
        # 요약 정보 추가 (완료된 경우)
        if data.get('status') == 'completed' and data.get('results'):
            results = data['results']
            scan_info['summary'] = {
                'total': len(results),
                'vulnerable': sum(1 for r in results if r['status'] == 'VULNERABLE')
            }
        
        scans.append(scan_info)
    
    # 최신순 정렬
    scans.sort(key=lambda x: x['started_at'], reverse=True)
    
    return jsonify({
        'scans': scans,
        'total': len(scans)
    })

@app.route('/api/claude/analyze', methods=['POST'])
def api_claude_analyze():
    """
    Claude AI 분석 요청
    
    Request Body:
    {
        "target_url": "http://localhost:3000",
        "results": [...]
    }
    """
    if not claude_analyzer.is_available():
        return jsonify({'error': 'Claude API 키가 설정되지 않았습니다'}), 400
    
    try:
        data = request.json
        target_url = data.get('target_url')
        results = data.get('results', [])
        
        if not target_url or not results:
            return jsonify({'error': '잘못된 요청입니다'}), 400
        
        analysis = claude_analyzer.analyze_scan_results(target_url, results)
        
        return jsonify({
            'success': True,
            'analysis': analysis
        })
        
    except Exception as e:
        logger.error(f"Claude 분석 오류: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# API 문서
# ============================================================================

@app.route('/api/docs')
def api_docs():
    """API 문서"""
    docs = {
        'version': '1.0.0',
        'endpoints': {
            'POST /api/scan/start': {
                'description': '웹 애플리케이션 스캔 시작',
                'body': {
                    'target_url': 'string (required)',
                    'use_claude': 'boolean (optional, default: false)',
                    'scan_types': 'array (optional, default: ["all"])'
                }
            },
            'GET /api/scan/status/<scan_id>': {
                'description': '스캔 상태 조회'
            },
            'GET /api/scan/results/<scan_id>': {
                'description': '스캔 결과 상세 조회'
            },
            'POST /api/infra/scan/start': {
                'description': '인프라 보안 스캔 시작',
                'body': {
                    'ssh_host': 'string (required)',
                    'ssh_user': 'string (required)',
                    'ssh_pass': 'string (required)',
                    'ssh_port': 'integer (optional, default: 22)',
                    'categories': 'array (optional, default: ["all"])'
                }
            },
            'POST /api/test/<test_name>': {
                'description': '단일 테스트 실행',
                'body': {
                    'target_url': 'string (required)'
                }
            },
            'GET /api/tests/list': {
                'description': '사용 가능한 테스트 목록'
            },
            'GET /api/scans/history': {
                'description': '스캔 히스토리 조회'
            },
            'POST /api/claude/analyze': {
                'description': 'Claude AI 분석',
                'body': {
                    'target_url': 'string (required)',
                    'results': 'array (required)'
                }
            }
        }
    }
    
    return jsonify(docs)

@app.route('/health')
def health_check():
    """헬스 체크"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'claude_available': claude_analyzer.is_available()
    })

# ============================================================================
# 에러 핸들러
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': '요청한 리소스를 찾을 수 없습니다'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': '서버 내부 오류가 발생했습니다'}), 500

# ============================================================================
# 메인 실행
# ============================================================================

if __name__ == '__main__':
    # 보고서 디렉토리 생성
    os.makedirs('reports', exist_ok=True)
    
    print("\n" + "="*80)
    print("통합 보안 취약점 스캐너 API 서버")
    print("="*80)
    print(f"웹 UI:       http://localhost:5000")
    print(f"API 문서:    http://localhost:5000/api/docs")
    print(f"헬스 체크:   http://localhost:5000/health")
    print(f"Claude AI:   {'사용 가능' if claude_analyzer.is_available() else '비활성화 (.env 파일 확인)'}")
    print("="*80)
    print(f"웹 취약점:   {len(VulnerabilityScanner.WEB_TESTS)}개 테스트")
    print(f"인프라 진단: OS, Web Server, Database")
    print("="*80 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)