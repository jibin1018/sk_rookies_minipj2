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
from infra_detector import InfraDetector, detect_infrastructure
from batch_scanner import BatchScanner
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

# 스캔 상태 저장소 (메모리 캐시)
scan_status = {}

# Claude 분석기 초기화
claude_analyzer = ClaudeAnalyzer()

# ============================================================================
# 유틸리티 함수
# ============================================================================

def save_scan_result(scan_id, data):
    """스캔 결과를 JSON 파일로 저장"""
    try:
        # datetime 객체 직렬화 처리
        class DateTimeEncoder(json.JSONEncoder):
            def default(self, o):
                if isinstance(o, datetime):
                    return o.isoformat()
                return super().default(o)
                
        file_path = os.path.join('reports', f'scan_result_{scan_id}.json')
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, cls=DateTimeEncoder)
        logger.info(f"스캔 결과 저장 완료: {file_path}")
    except Exception as e:
        logger.error(f"스캔 결과 저장 실패: {str(e)}")

def load_scan_result(scan_id):
    """JSON 파일에서 스캔 결과 로드"""
    try:
        file_path = os.path.join('reports', f'scan_result_{scan_id}.json')
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"스캔 결과 로드 실패: {str(e)}")
    return None

def summarize_scan(scan_id, data):
    """스캔 데이터 요약"""
    summary = {}
    if data.get('results'):
        results = data['results']
        summary = {
            'total': len(results),
            'vulnerable': sum(1 for r in results if r.get('status') == 'VULNERABLE')
        }
    
    # 보고서 파일 존재 여부 확인
    has_report = False
    report_dirs = ['reports', '../reports']  # Scanner 기준 + 루트 기준
    report_filenames = [
        f'scan_report_{scan_id}.md',
        f'scan_report_{scan_id}.txt',
        f'infra_scan_report_{scan_id}.md',
        f'infra_scan_report_{scan_id}.txt',
    ]
    
    for report_dir in report_dirs:
        if has_report:
            break
        for filename in report_filenames:
            file_path = os.path.join(report_dir, filename)
            if os.path.exists(file_path):
                has_report = True
                break
        
    return {
        'scan_id': scan_id,
        'type': data.get('type'),
        'status': data.get('status'),
        'target': data.get('target_url') or data.get('target'),
        'started_at': data.get('started_at'),
        'completed_at': data.get('completed_at'),
        'summary': summary,
        'has_report': has_report
    }

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
    # 1. 메모리 확인
    data = scan_status.get(scan_id)
    
    # 2. 파일 확인 (메모리에 없으면)
    if not data:
        data = load_scan_result(scan_id)
        if data:
            scan_status[scan_id] = data
            
    if not data:
        return "스캔을 찾을 수 없습니다", 404

    return render_template('report.html',
                         scan_id=scan_id,
                         data=data)

@app.route('/download/<scan_id>')
def download_report(scan_id):
    """보고서 파일 다운로드"""
    # 1. 스캔 정보 로드 (경로 확인용)
    scan_data = scan_status.get(scan_id) or load_scan_result(scan_id)
    
    # 2. 파일 경로 찾기 시도
    report_path = None
    if scan_data and scan_data.get('report_path'):
        report_path = scan_data.get('report_path')
        # 상대 경로일 수 있으므로 절대 경로로 변환 시도
        if report_path and not os.path.isabs(report_path):
             # 1) 현재 경로 기준
             if os.path.exists(report_path):
                 report_path = os.path.abspath(report_path)
             # 2) 상위 경로 기준 (앱이 Scanner 폴더 안에 있을 때)
             elif os.path.exists(os.path.join('..', report_path)):
                 report_path = os.path.abspath(os.path.join('..', report_path))
    
    # 3. 경로가 없거나 파일이 없으면 직접 탐색
    if not report_path or not os.path.exists(report_path):
        # 예상되는 파일명 패턴들
        possible_names = [
            f"scan_report_{scan_id}.md",
            f"scan_report_{scan_id}.txt",
            f"infra_scan_report_{scan_id}.txt"
        ]
        
        # 검색할 디렉토리 목록 (현재 디렉토리의 reports와 상위 디렉토리의 reports)
        search_dirs = ['reports', '../reports', os.path.join(os.getcwd(), 'reports')]
        
        for directory in search_dirs:
            if not os.path.exists(directory):
                continue
                
            for name in possible_names:
                path = os.path.join(directory, name)
                if os.path.exists(path):
                    report_path = os.path.abspath(path)
                    break
            if report_path:
                break
    
    if report_path and os.path.exists(report_path):
        return send_file(report_path, as_attachment=True)
        
    return "보고서 파일을 찾을 수 없습니다", 404

# ============================================================================
# 웹 애플리케이션 스캔 API
# ============================================================================

@app.route('/api/scan/start', methods=['POST'])
def api_start_scan():
    """웹 애플리케이션 스캔 시작"""
    try:
        data = request.json
        target_url = data.get('target_url', '').strip()
        use_claude = data.get('use_claude', False)
        scan_types = data.get('scan_types', ['all'])
        use_infra_detection = data.get('use_infra_detection', False)
        
        # 인증 정보 추출 (쿠키/헤더)
        auth_cookies = data.get('cookies', {})
        auth_headers = data.get('headers', {})
        
        if not target_url:
            return jsonify({'error': '대상 URL을 입력하세요'}), 400
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
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
            'use_infra_detection': use_infra_detection,
            'infra_profile': None,
            'metrics': None,
            'claude_analysis': None,
            'started_at': datetime.now().isoformat(),
            'completed_at': None
        }
        
        thread = threading.Thread(
            target=run_web_scan_background, 
            args=(scan_id, target_url, use_claude, scan_types, use_infra_detection, auth_cookies, auth_headers)
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

def run_web_scan_background(scan_id, target_url, use_claude, scan_types, use_infra_detection=False, auth_cookies=None, auth_headers=None):
    """백그라운드 웹 스캔 실행"""
    try:
        logger.info(f"[{scan_id}] 스캔 실행 중... (인프라 탐지: {use_infra_detection})")
        
        scanner = VulnerabilityScanner(
            target_url, 
            scan_status, 
            scan_id,
            scan_types=scan_types,
            use_infra_detection=use_infra_detection,
            auth_cookies=auth_cookies,
            auth_headers=auth_headers
        )
        results = scanner.scan_all()
        
        # 인프라 프로필 및 메트릭 저장
        scan_status[scan_id]['infra_profile'] = scanner.infra_profile
        scan_status[scan_id]['metrics'] = scanner.metrics
        
        scan_status[scan_id]['status'] = 'completed'
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['results'] = results
        scan_status[scan_id]['completed_at'] = datetime.now().isoformat()
        
        logger.info(f"[{scan_id}] 스캔 완료 - {len(results)}개 테스트")
        
        # Claude AI 분석
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
        report_path = scanner.generate_report(results)
        scan_status[scan_id]['report_path'] = report_path
        
        scan_status[scan_id]['current_test'] = '스캔 완료!'
        logger.info(f"[{scan_id}] 보고서 생성 완료: {report_path}")
        
        # 결과 JSON 저장 (히스토리용)
        save_scan_result(scan_id, scan_status[scan_id])
        
    except Exception as e:
        logger.error(f"[{scan_id}] 스캔 오류: {str(e)}")
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['error'] = str(e)
        scan_status[scan_id]['completed_at'] = datetime.now().isoformat()
        save_scan_result(scan_id, scan_status[scan_id])

@app.route('/api/scan/status/<scan_id>')
def api_scan_status(scan_id):
    """스캔 상태 조회"""
    if scan_id in scan_status:
        return jsonify(scan_status[scan_id])
        
    data = load_scan_result(scan_id)
    if data:
        scan_status[scan_id] = data
        return jsonify(data)
    
    return jsonify({'error': '스캔을 찾을 수 없습니다'}), 404

@app.route('/api/scan/results/<scan_id>')
def api_scan_results(scan_id):
    """스캔 결과 상세 조회"""
    data = scan_status.get(scan_id)
    if not data:
        data = load_scan_result(scan_id)
        
    if not data:
        return jsonify({'error': '스캔을 찾을 수 없습니다'}), 404
    
    if data['status'] != 'completed' and data['status'] != 'error':
        return jsonify({'error': '스캔이 완료되지 않았습니다'}), 400
    
    results = data.get('results', [])
    
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
        'target_url': data.get('target_url') or data.get('target'),
        'type': data.get('type'),
        'status': data.get('status'),
        'started_at': data.get('started_at'),
        'completed_at': data.get('completed_at'),
        'summary': summary,
        'results': results,
        'claude_analysis': data.get('claude_analysis'),
        'metrics': data.get('metrics'),
        'infra_profile': data.get('infra_profile')
    })

@app.route('/api/report/generate/<scan_id>', methods=['POST'])
def generate_report_api(scan_id):
    """보고서 생성 및 Claude 분석 요청 API"""
    scan_data = scan_status.get(scan_id)
    if not scan_data:
        scan_data = load_scan_result(scan_id)
        
    if not scan_data:
        return jsonify({'error': '스캔 정보를 찾을 수 없습니다'}), 404
        
    try:
        # Claude 분석 (없는 경우)
        if not scan_data.get('claude_analysis') or scan_data.get('claude_analysis', {}).get('error'):
            if claude_analyzer.is_available():
                logger.info(f"[{scan_id}] 보고서 요청에 의한 Claude 분석 시작")
                analysis = claude_analyzer.analyze_scan_results(
                    scan_data.get('target_url', 'unknown'), 
                    scan_data.get('results', [])
                )
                scan_data['claude_analysis'] = analysis
                
                # 업데이트된 결과 저장
                if scan_id in scan_status:
                    scan_status[scan_id] = scan_data
                save_scan_result(scan_id, scan_data)
        
        # 보고서 재생성 로직은 생략 (기존 파일 활용)
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': '보고서 생성 완료',
            'report_url': f'/download/{scan_id}'
        })
        
    except Exception as e:
        logger.error(f"보고서 생성 오류: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/raw/<scan_id>')
def get_raw_report(scan_id):
    """보고서 파일의 원문 텍스트 반환"""
    # 1. 스캔 정보 로드
    scan_data = scan_status.get(scan_id) or load_scan_result(scan_id)
    
    # 2. 파일 경로 찾기 (download_report 로직 재활용)
    report_path = None
    if scan_data and scan_data.get('report_path'):
        report_path = scan_data.get('report_path')
        if not os.path.isabs(report_path):
            if os.path.exists(report_path): report_path = os.path.abspath(report_path)
            elif os.path.exists(os.path.join('..', report_path)): report_path = os.path.abspath(os.path.join('..', report_path))

    if not report_path or not os.path.exists(report_path):
        possible_names = [
            f"scan_report_{scan_id}.md", 
            f"scan_report_{scan_id}.txt", 
            f"infra_scan_report_{scan_id}.md",
            f"infra_scan_report_{scan_id}.txt"
        ]
        search_dirs = ['reports', '../reports', os.path.join(os.getcwd(), 'reports')]
        for directory in search_dirs:
            if not os.path.exists(directory): continue
            for name in possible_names:
                path = os.path.join(directory, name)
                if os.path.exists(path):
                    report_path = os.path.abspath(path)
                    break
            if report_path: break

    if report_path and os.path.exists(report_path):
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return jsonify({'success': True, 'content': content, 'filename': os.path.basename(report_path)})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
            
    return jsonify({'error': '보고서 파일을 찾을 수 없습니다'}), 404

# ============================================================================
# 인프라 스캔 API
# ============================================================================

@app.route('/api/infra/scan/start', methods=['POST'])
def api_start_infra_scan():
    """인프라 보안 스캔 시작"""
    try:
        data = request.json
        ssh_host = data.get('ssh_host', '').strip()
        
        # URL/포트 정리
        if ssh_host.startswith('http://'): ssh_host = ssh_host[7:]
        elif ssh_host.startswith('https://'): ssh_host = ssh_host[8:]
        if ':' in ssh_host: ssh_host = ssh_host.split(':')[0]
        if '/' in ssh_host: ssh_host = ssh_host.split('/')[0]

        ssh_user = data.get('ssh_user', '').strip()
        ssh_pass = data.get('ssh_pass', '').strip()
        ssh_port = data.get('ssh_port', 22)
        categories = data.get('categories', ['all'])
        
        if not all([ssh_host, ssh_user, ssh_pass]):
            return jsonify({'error': 'SSH 접속 정보를 모두 입력하세요'}), 400
        
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_infra")
        
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

@app.route('/api/infra/scan/start/pem', methods=['POST'])
def api_start_infra_scan_pem():
    """인프라 보안 스캔 시작 (.pem 키 파일 사용)"""
    try:
        ssh_host = request.form.get('ssh_host', '').strip()
        
        if ssh_host.startswith('http://'): ssh_host = ssh_host[7:]
        elif ssh_host.startswith('https://'): ssh_host = ssh_host[8:]
        if ':' in ssh_host: ssh_host = ssh_host.split(':')[0]
        if '/' in ssh_host: ssh_host = ssh_host.split('/')[0]

        ssh_user = request.form.get('ssh_user', '').strip()
        ssh_port = int(request.form.get('ssh_port', 22))
        categories = json.loads(request.form.get('categories', '["all"]'))

        if not all([ssh_host, ssh_user]):
            return jsonify({'error': 'SSH 호스트와 사용자명을 입력하세요'}), 400

        if 'pem_file' not in request.files:
            return jsonify({'error': '.pem 키 파일을 업로드하세요'}), 400

        pem_file = request.files['pem_file']
        if pem_file.filename == '':
            return jsonify({'error': '.pem 키 파일을 선택하세요'}), 400

        os.makedirs('temp', exist_ok=True)
        temp_pem_path = os.path.join('temp', f'{datetime.now().strftime("%Y%m%d_%H%M%S")}_{pem_file.filename}')
        pem_file.save(temp_pem_path)
        os.chmod(temp_pem_path, 0o600)

        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_infra")

        scan_status[scan_id] = {
            'scan_id': scan_id,
            'type': 'infrastructure',
            'status': 'running',
            'progress': 0,
            'current_test': '인프라 스캔 초기화 중...',
            'results': [],
            'target': ssh_host,
            'categories': categories,
            'pem_file': temp_pem_path,
            'started_at': datetime.now().isoformat(),
            'completed_at': None
        }

        thread = threading.Thread(
            target=run_infra_scan_background_pem,
            args=(scan_id, ssh_host, ssh_user, ssh_port, temp_pem_path, categories)
        )
        thread.daemon = True
        thread.start()

        logger.info(f"인프라 스캔 시작 (PEM 키): {scan_id} - {ssh_host}")

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': '인프라 스캔이 시작되었습니다'
        })

    except Exception as e:
        logger.error(f"인프라 스캔 시작 오류 (PEM): {str(e)}")
        return jsonify({'error': str(e)}), 500

def run_infra_scan_background(scan_id, ssh_host, ssh_user, ssh_pass, ssh_port, categories):
    """백그라운드 인프라 스캔 실행 (비밀번호)"""
    try:
        logger.info(f"[{scan_id}] 인프라 스캔 실행 중...")

        scanner = InfraScanner(
            ssh_host, ssh_user, ssh_pass, ssh_port,
            scan_status=scan_status, scan_id=scan_id
        )

        results = scanner.scan_infrastructure(categories)

        scan_status[scan_id]['status'] = 'completed'
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['results'] = results
        scan_status[scan_id]['current_test'] = '스캔 완료!'
        scan_status[scan_id]['completed_at'] = datetime.now().isoformat()

        report_path = scanner.generate_report(results)
        scan_status[scan_id]['report_path'] = report_path
        
        save_scan_result(scan_id, scan_status[scan_id])

        logger.info(f"[{scan_id}] 인프라 스캔 완료")

    except Exception as e:
        logger.error(f"[{scan_id}] 인프라 스캔 오류: {str(e)}")
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['error'] = str(e)
        scan_status[scan_id]['completed_at'] = datetime.now().isoformat()
        save_scan_result(scan_id, scan_status[scan_id])

def run_infra_scan_background_pem(scan_id, ssh_host, ssh_user, ssh_port, pem_file_path, categories):
    """백그라운드 인프라 스캔 실행 (PEM 키)"""
    try:
        logger.info(f"[{scan_id}] 인프라 스캔 실행 중 (PEM 키)...")

        scanner = InfraScanner(
            ssh_host, ssh_user, ssh_pass=None, ssh_port=ssh_port,
            ssh_key_file=pem_file_path, scan_status=scan_status, scan_id=scan_id
        )

        results = scanner.scan_infrastructure(categories)

        scan_status[scan_id]['status'] = 'completed'
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['results'] = results
        scan_status[scan_id]['current_test'] = '스캔 완료!'
        scan_status[scan_id]['completed_at'] = datetime.now().isoformat()

        report_path = scanner.generate_report(results)
        scan_status[scan_id]['report_path'] = report_path
        
        save_scan_result(scan_id, scan_status[scan_id])

        logger.info(f"[{scan_id}] 인프라 스캔 완료 (PEM)")

    except Exception as e:
        logger.error(f"[{scan_id}] 인프라 스캔 오류 (PEM): {str(e)}")
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['error'] = str(e)
        scan_status[scan_id]['completed_at'] = datetime.now().isoformat()
        save_scan_result(scan_id, scan_status[scan_id])

    finally:
        try:
            if os.path.exists(pem_file_path):
                os.remove(pem_file_path)
                logger.info(f"[{scan_id}] .pem 파일 삭제 완료")
        except Exception as e:
            logger.error(f"[{scan_id}] .pem 파일 삭제 실패: {str(e)}")

# ============================================================================
# 인프라 탐지 및 배치 스캔 API
# ============================================================================

# 배치 스캔 상태 저장소
batch_status = {}

@app.route('/api/detect-infra', methods=['POST'])
def api_detect_infra():
    """인프라 탐지만 실행 (스캔 없이)"""
    try:
        data = request.json
        target_url = data.get('target_url', '').strip()
        
        if not target_url:
            return jsonify({'error': '대상 URL을 입력하세요'}), 400
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        logger.info(f"인프라 탐지 요청: {target_url}")
        
        detector = InfraDetector()
        profile = detector.detect(target_url)
        
        return jsonify({
            'success': True,
            'target_url': target_url,
            'infra_profile': profile
        })
        
    except Exception as e:
        logger.error(f"인프라 탐지 오류: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/batch-scan', methods=['POST'])
def api_batch_scan():
    """URL 목록 일괄 스캔 시작"""
    try:
        data = request.json
        urls = data.get('urls', [])
        use_infra_detection = data.get('use_infra_detection', True)
        scan_types = data.get('scan_types', ['all'])
        
        if not urls:
            return jsonify({'error': 'URL 목록을 입력하세요'}), 400
        
        # URL 정규화
        normalized_urls = []
        for url in urls:
            url = url.strip()
            if url and not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            if url:
                normalized_urls.append(url)
        
        if not normalized_urls:
            return jsonify({'error': '유효한 URL이 없습니다'}), 400
        
        batch_id = datetime.now().strftime("%Y%m%d_%H%M%S_batch")
        
        batch_status[batch_id] = {
            'batch_id': batch_id,
            'status': 'running',
            'total_urls': len(normalized_urls),
            'completed': 0,
            'urls': normalized_urls,
            'use_infra_detection': use_infra_detection,
            'results': {},
            'started_at': datetime.now().isoformat(),
            'completed_at': None
        }
        
        # 백그라운드 실행
        thread = threading.Thread(
            target=run_batch_scan_background,
            args=(batch_id, normalized_urls, use_infra_detection, scan_types)
        )
        thread.daemon = True
        thread.start()
        
        logger.info(f"배치 스캔 시작: {batch_id} - {len(normalized_urls)}개 URL")
        
        return jsonify({
            'success': True,
            'batch_id': batch_id,
            'total_urls': len(normalized_urls),
            'message': '배치 스캔이 시작되었습니다'
        })
        
    except Exception as e:
        logger.error(f"배치 스캔 시작 오류: {str(e)}")
        return jsonify({'error': str(e)}), 500


def run_batch_scan_background(batch_id, urls, use_infra_detection, scan_types):
    """백그라운드 배치 스캔 실행"""
    try:
        batch_scanner = BatchScanner()
        batch_scanner.add_urls(urls)
        
        # 순차 스캔 실행
        results = batch_scanner.scan_all(
            use_infra_detection=use_infra_detection,
            scan_types=scan_types
        )
        
        # 결과 저장
        batch_status[batch_id]['status'] = 'completed'
        batch_status[batch_id]['results'] = results
        batch_status[batch_id]['infra_profiles'] = batch_scanner.infra_profiles
        batch_status[batch_id]['completed'] = len(urls)
        batch_status[batch_id]['completed_at'] = datetime.now().isoformat()
        
        # 요약 보고서 생성
        report_path = batch_scanner.generate_summary_report()
        batch_status[batch_id]['report_path'] = report_path
        
        logger.info(f"[{batch_id}] 배치 스캔 완료")
        
    except Exception as e:
        logger.error(f"[{batch_id}] 배치 스캔 오류: {str(e)}")
        batch_status[batch_id]['status'] = 'error'
        batch_status[batch_id]['error'] = str(e)
        batch_status[batch_id]['completed_at'] = datetime.now().isoformat()


@app.route('/api/batch-status/<batch_id>')
def api_batch_status(batch_id):
    """배치 스캔 상태 조회"""
    if batch_id in batch_status:
        return jsonify(batch_status[batch_id])
    return jsonify({'error': '배치 스캔을 찾을 수 없습니다'}), 404


# ============================================================================
# 기타 API
# ============================================================================

@app.route('/api/test/<test_name>', methods=['POST'])
def api_single_test(test_name):
    """단일 취약점 테스트 실행"""
    try:
        data = request.json
        target_url = data.get('target_url', '').strip()
        
        if not target_url:
            return jsonify({'error': '대상 URL을 입력하세요'}), 400
        
        from importlib import import_module
        module = import_module(f'modules.web.{test_name}')
        result = module.scan(target_url)
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except ModuleNotFoundError:
        return jsonify({'error': f'테스트 모듈을 찾을 수 없습니다: {test_name}'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tests/list')
def api_tests_list():
    """사용 가능한 테스트 목록"""
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
    """스캔 히스토리 조회 (파일 시스템 기반)"""
    scans = []
    existing_ids = set()
    
    # 1. 메모리 데이터 우선
    for scan_id, data in scan_status.items():
        scans.append(summarize_scan(scan_id, data))
        existing_ids.add(scan_id)
        
    # 2. reports 폴더(Scanner/reports 및 루트 reports) 스캔
    report_dirs = ['reports', '../reports'] # Scanner 기준 reports와 루트 reports
    
    try:
        for report_dir in report_dirs:
            if not os.path.exists(report_dir):
                continue
                
            for filename in os.listdir(report_dir):
                # JSON 메타데이터 파일 우선 처리
                if filename.startswith('scan_result_') and filename.endswith('.json'):
                    scan_id = filename.replace('scan_result_', '').replace('.json', '')
                    if scan_id not in existing_ids:
                        data = load_scan_result(scan_id)
                        if data:
                            scans.append(summarize_scan(scan_id, data))
                            existing_ids.add(scan_id)
                
                # 메타데이터가 없는 순수 보고서 파일 (.md, .txt) 처리
                elif (filename.endswith('.md') or filename.endswith('.txt')) and ('scan_report_' in filename):
                    # 파일명에서 ID 추출
                    # 예: scan_report_20260102_141417.txt -> 20260102_141417
                    is_infra = 'infra_scan_report_' in filename
                    prefix = 'infra_scan_report_' if is_infra else 'scan_report_'
                    scan_id = filename.replace(prefix, '').split('.')[0]
                    
                    if scan_id not in existing_ids:
                        file_path = os.path.abspath(os.path.join(report_dir, filename))
                        # 파일 생성 시간을 시작 시간으로 활용
                        ctime = os.path.getctime(file_path)
                        dt_object = datetime.fromtimestamp(ctime)
                        
                        # 보고서 파일에서 대상 정보 추출
                        target_name = '점검 기록'
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read(500)  # 처음 500자만 읽기
                                # **대상**: `IP주소` 또는 **대상**: `URL` 패턴 찾기
                                import re
                                match = re.search(r'\*\*대상\*\*:\s*`([^`]+)`', content)
                                if match:
                                    target_name = match.group(1)
                        except:
                            pass
                        
                        scans.append({
                            'scan_id': scan_id,
                            'type': 'infrastructure' if is_infra else 'web',
                            'status': 'completed',
                            'target': target_name,
                            'started_at': dt_object.isoformat(),
                            'completed_at': dt_object.isoformat(),
                            'summary': {'total': '?', 'vulnerable': '?'},
                            'is_file_only': True,
                            'report_path': file_path,
                            'has_report': True
                        })
                        existing_ids.add(scan_id)
                        
    except Exception as e:
        logger.error(f"히스토리 조회 오류: {str(e)}")

    # 최신순 정렬
    scans.sort(key=lambda x: x.get('started_at', ''), reverse=True)
    
    return jsonify({
        'scans': scans,
        'total': len(scans)
    })

@app.route('/api/claude/analyze', methods=['POST'])
def api_claude_analyze():
    """Claude AI 분석 요청"""
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
        return jsonify({'error': str(e)}), 500

@app.route('/api/docs')
def api_docs():
    """API 문서 - 모든 엔드포인트 상세 정보"""
    docs = {
        "title": "Cyber Sentinel API Documentation",
        "version": "2.0.0",
        "description": "통합 보안 취약점 스캐너 API",
        "base_url": request.host_url.rstrip('/'),
        "endpoints": [
            {
                "path": "/api/scan/start",
                "method": "POST",
                "description": "웹 애플리케이션 보안 스캔 시작",
                "request_body": {
                    "target_url": {"type": "string", "required": True, "description": "스캔 대상 URL"},
                    "use_claude": {"type": "boolean", "default": False, "description": "Claude AI 분석 활성화"},
                    "use_infra_detection": {"type": "boolean", "default": True, "description": "인프라 자동 감지"},
                    "scan_types": {"type": "array", "default": ["all"], "description": "스캔 유형 (all, injection, xss 등)"}
                },
                "response": {"scan_id": "string", "success": "boolean", "message": "string"}
            },
            {
                "path": "/api/scan/status/<scan_id>",
                "method": "GET",
                "description": "스캔 진행 상태 조회",
                "response": {
                    "scan_id": "string",
                    "status": "running|completed|error",
                    "progress": "0-100",
                    "current_test": "string"
                }
            },
            {
                "path": "/api/scan/results/<scan_id>",
                "method": "GET",
                "description": "스캔 결과 상세 조회",
                "response": {
                    "scan_id": "string",
                    "target_url": "string",
                    "summary": {"total": "int", "vulnerable": "int", "safe": "int"},
                    "results": "array",
                    "metrics": {
                        "scan_duration": "float",
                        "scripts_executed": "int",
                        "scripts_skipped": "int",
                        "avg_response_time": "float"
                    },
                    "claude_analysis": "object|null"
                }
            },
            {
                "path": "/api/infra/scan/start",
                "method": "POST",
                "description": "인프라 보안 스캔 시작",
                "request_body": {
                    "ssh_host": {"type": "string", "required": True},
                    "ssh_port": {"type": "integer", "default": 22},
                    "ssh_username": {"type": "string", "required": True},
                    "ssh_password": {"type": "string", "required": False},
                    "ssh_key_file": {"type": "string", "required": False}
                }
            },
            {
                "path": "/api/report/generate/<scan_id>",
                "method": "POST",
                "description": "보고서 파일 생성"
            },
            {
                "path": "/api/report/raw/<scan_id>",
                "method": "GET",
                "description": "보고서 원본 텍스트 조회"
            },
            {
                "path": "/api/scans/history",
                "method": "GET",
                "description": "스캔 히스토리 목록 조회",
                "response": {"scans": "array", "total": "int"}
            },
            {
                "path": "/api/claude/analyze",
                "method": "POST",
                "description": "Claude AI 분석 요청",
                "request_body": {
                    "target_url": {"type": "string", "required": True},
                    "results": {"type": "array", "required": True}
                }
            },
            {
                "path": "/api/scripts/list",
                "method": "GET",
                "description": "사용 가능한 스크립트 목록"
            },
            {
                "path": "/health",
                "method": "GET",
                "description": "서버 상태 확인"
            }
        ],
        "error_codes": {
            "400": "잘못된 요청",
            "404": "리소스 없음",
            "500": "서버 오류"
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

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': '요청한 리소스를 찾을 수 없습니다'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': '서버 내부 오류가 발생했습니다'}), 500

if __name__ == '__main__':
    os.makedirs('reports', exist_ok=True)
    os.makedirs('temp', exist_ok=True)
    
    port = int(os.getenv('PORT', '5000'))
    
    print("\n" + "="*80)
    print(f"통합 보안 취약점 스캐너 API 서버 (Port: {port})")
    print("="*80 + "\n")

    app.run(debug=True, host='0.0.0.0', port=port, threaded=True)
