#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH Utils 적용 자동화 스크립트
모든 인프라 모듈에 안전한 SSH 연결 처리 적용
"""

import re
import os
from pathlib import Path


def apply_ssh_utils_to_file(file_path):
    """
    파일에 ssh_utils 적용

    Args:
        file_path: 수정할 파일 경로

    Returns:
        bool: 성공 여부
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 이미 ssh_utils를 사용하고 있으면 스킵
        if 'from ssh_utils import' in content:
            print(f"⏭  {file_path.name} - 이미 적용됨")
            return True

        # 1. import 구문 수정
        # paramiko만 import하는 경우
        new_content = re.sub(
            r'^import paramiko\s*$',
            '''import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result''',
            content,
            flags=re.MULTILINE
        )

        if new_content == content:
            # 다른 import와 함께 있는 경우
            new_content = re.sub(
                r'^(import .*\n)*import paramiko\s*\n',
                lambda m: m.group(0) + '''import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
''',
                content,
                flags=re.MULTILINE
            )

        # 2. SSH 연결 코드 패턴 찾기 및 교체
        # 패턴 1: try 내부의 SSH 연결
        ssh_connect_pattern = r'''    try:
        ssh = paramiko\.SSHClient\(\)
        ssh\.set_missing_host_key_policy\(paramiko\.AutoAddPolicy\(\)\)
        ssh\.connect\(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file, timeout=\d+\)'''

        replacement = '''    # SSH 연결 (안전)
    ssh, error = safe_ssh_connect(ssh_host, ssh_user, ssh_pass, ssh_port, ssh_key_file)

    if error:
        # SSH 연결 실패 시 ERROR 결과 반환
        module_name = result.get('name', 'Unknown Module')
        return create_error_result(module_name, error, 'ERROR')

    try:'''

        new_content = re.sub(ssh_connect_pattern, replacement, new_content)

        # 패턴 2: 기존 예외 처리 개선
        old_exception = (
            r"    except paramiko\.AuthenticationException:\s+"
            r"details\.append\(\"  \[ERROR\] SSH 인증 실패\"\)\s+"
            r"result\['status'\] = 'ERROR'\s+"
            r"except Exception as e:\s+"
            r"details\.append\(f\"  \[ERROR\] \{str\(e\)\}\"\)\s+"
            r"result\['status'\] = 'ERROR'"
        )

        new_exception = (
            "    except Exception as e:\n"
            "        # 스캔 중 예외 발생 (SSH 연결은 성공했지만 명령 실행 실패)\n"
            '        details.append(f"\\n[ERROR] 스캔 중 오류 발생: {str(e)}")\n'
            "        result['status'] = 'ERROR'\n"
            "        result['severity'] = 'ERROR'"
        )

        new_content = re.sub(old_exception, new_exception, new_content)

        # 3. 파일에 쓰기
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        if new_content != content:
            print(f"✅ {file_path.name} - 수정 완료")
            return True
        else:
            print(f"⚠️  {file_path.name} - 변경 없음 (패턴 불일치)")
            return False

    except Exception as e:
        print(f"❌ {file_path.name} - 오류: {str(e)}")
        return False


def main():
    """메인 함수"""
    scanner_root = Path(__file__).parent

    # 수정할 디렉토리 목록
    directories = [
        scanner_root / 'modules' / 'os',
        scanner_root / 'modules' / 'web_server',
        scanner_root / 'modules' / 'was',
        scanner_root / 'modules' / 'db',
    ]

    print("=" * 80)
    print("SSH Utils 자동 적용 스크립트")
    print("=" * 80)

    total_files = 0
    success_files = 0

    for directory in directories:
        if not directory.exists():
            print(f"\n⚠️  디렉토리 없음: {directory}")
            continue

        print(f"\n📁 {directory.name} 디렉토리:")
        print("-" * 80)

        py_files = list(directory.glob('*.py'))
        py_files = [f for f in py_files if f.name != '__init__.py']

        for py_file in py_files:
            total_files += 1
            if apply_ssh_utils_to_file(py_file):
                success_files += 1

    print("\n" + "=" * 80)
    print(f"완료: {success_files}/{total_files} 파일 수정")
    print("=" * 80)


if __name__ == '__main__':
    main()
