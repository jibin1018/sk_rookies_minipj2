#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH 연결 유틸리티
안전한 SSH 연결 및 예외 처리를 위한 헬퍼 함수
"""

import paramiko
import logging

logger = logging.getLogger(__name__)


def safe_ssh_connect(ssh_host, ssh_user, ssh_pass=None, ssh_port=22, ssh_key_file=None, timeout=10):
    """
    안전한 SSH 연결 (예외 처리 포함)

    Args:
        ssh_host (str): SSH 호스트 주소
        ssh_user (str): SSH 사용자명
        ssh_pass (str, optional): SSH 비밀번호
        ssh_port (int): SSH 포트 (기본 22)
        ssh_key_file (str, optional): PEM 키 파일 경로
        timeout (int): 연결 타임아웃 (초)

    Returns:
        tuple: (ssh_client, error_message)
            - 성공 시: (SSHClient 인스턴스, None)
            - 실패 시: (None, 에러 메시지)
    """
    ssh = None

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # SSH 연결 시도
        ssh.connect(
            ssh_host,
            port=ssh_port,
            username=ssh_user,
            password=ssh_pass,
            key_filename=ssh_key_file,
            timeout=timeout
        )

        logger.info(f"SSH 연결 성공: {ssh_user}@{ssh_host}:{ssh_port}")
        return ssh, None

    except paramiko.AuthenticationException as e:
        error_msg = f"SSH 인증 실패: {ssh_user}@{ssh_host} - 비밀번호 또는 키 파일을 확인하세요"
        logger.error(error_msg)
        if ssh:
            ssh.close()
        return None, error_msg

    except paramiko.SSHException as e:
        error_msg = f"SSH 연결 오류: {ssh_host}:{ssh_port} - {str(e)}"
        logger.error(error_msg)
        if ssh:
            ssh.close()
        return None, error_msg

    except OSError as e:
        # 네트워크 연결 불가, 호스트 없음 등
        error_msg = f"네트워크 오류: {ssh_host} - {str(e)}"
        logger.error(error_msg)
        if ssh:
            ssh.close()
        return None, error_msg

    except Exception as e:
        error_msg = f"SSH 연결 중 알 수 없는 오류: {str(e)}"
        logger.error(error_msg)
        if ssh:
            ssh.close()
        return None, error_msg


def create_error_result(module_name, error_message, severity='ERROR'):
    """
    SSH 연결 실패 시 반환할 표준 에러 결과 생성

    Args:
        module_name (str): 모듈 이름
        error_message (str): 에러 메시지
        severity (str): 심각도 (기본 'ERROR')

    Returns:
        dict: 표준 에러 결과 딕셔너리
    """
    return {
        'name': module_name,
        'category': 'SSH Connection',
        'status': 'ERROR',
        'severity': severity,
        'vulnerabilities': [],
        'recommendation': 'SSH 연결 정보를 확인하고 다시 시도하세요',
        'details': f'SSH 연결 실패: {error_message}'
    }


def execute_ssh_command(ssh_client, command):
    """
    SSH 명령어 실행 (안전)

    Args:
        ssh_client: paramiko SSHClient 인스턴스
        command (str): 실행할 명령어

    Returns:
        tuple: (stdout, stderr, exit_code)
            - 성공 시: (출력 문자열, 에러 문자열, 종료 코드)
            - 실패 시: (None, 에러 메시지, -1)
    """
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=30)

        # 출력 읽기
        stdout_data = stdout.read().decode('utf-8', errors='ignore').strip()
        stderr_data = stderr.read().decode('utf-8', errors='ignore').strip()
        exit_code = stdout.channel.recv_exit_status()

        return stdout_data, stderr_data, exit_code

    except Exception as e:
        logger.error(f"명령어 실행 실패 ({command}): {str(e)}")
        return None, str(e), -1
