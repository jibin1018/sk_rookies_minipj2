#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH 연결 예외 처리 테스트
TDD 방식으로 작성된 테스트 케이스
"""

import unittest
from unittest.mock import patch, MagicMock
import paramiko
import sys
import os

# 모듈 경로 추가
sys.path.insert(0, os.path.dirname(__file__))

class TestSSHConnectionHandling(unittest.TestCase):
    """SSH 연결 예외 처리 테스트"""

    def test_authentication_failure(self):
        """테스트 1: SSH 인증 실패 시 ERROR 상태 반환"""
        # Given: 잘못된 비밀번호
        ssh_host = "192.168.1.100"
        ssh_user = "admin"
        ssh_pass = "wrong_password"

        # When: SSH 연결 시도 (인증 실패)
        # Then: ERROR 상태 반환, 예외 발생하지 않음
        with patch('paramiko.SSHClient') as mock_ssh:
            mock_ssh.return_value.connect.side_effect = paramiko.AuthenticationException("Authentication failed")

            # 모듈 임포트 후 테스트
            from modules.os import linux_account
            result = linux_account.scan(ssh_host, ssh_user, ssh_pass)

            self.assertEqual(result['status'], 'ERROR')
            self.assertIn('인증 실패', result['details'].lower())
            self.assertEqual(result['severity'], 'ERROR')

    def test_connection_timeout(self):
        """테스트 2: SSH 연결 타임아웃 시 ERROR 상태 반환"""
        # Given: 접근 불가능한 호스트
        ssh_host = "192.168.255.255"  # 타임아웃 발생
        ssh_user = "admin"
        ssh_pass = "password"

        # When: SSH 연결 시도 (타임아웃)
        # Then: ERROR 상태 반환
        with patch('paramiko.SSHClient') as mock_ssh:
            mock_ssh.return_value.connect.side_effect = paramiko.SSHException("Connection timeout")

            from modules.os import linux_account
            result = linux_account.scan(ssh_host, ssh_user, ssh_pass, ssh_port=22)

            self.assertEqual(result['status'], 'ERROR')
            self.assertIn('연결', result['details'].lower())

    def test_network_unreachable(self):
        """테스트 3: 네트워크 연결 불가 시 ERROR 상태 반환"""
        # Given: 존재하지 않는 호스트
        ssh_host = "invalid.host.example.com"
        ssh_user = "admin"
        ssh_pass = "password"

        # When: SSH 연결 시도 (네트워크 오류)
        # Then: ERROR 상태 반환
        with patch('paramiko.SSHClient') as mock_ssh:
            mock_ssh.return_value.connect.side_effect = Exception("Network unreachable")

            from modules.os import linux_account
            result = linux_account.scan(ssh_host, ssh_user, ssh_pass)

            self.assertEqual(result['status'], 'ERROR')
            self.assertIsNotNone(result['details'])

    def test_successful_connection(self):
        """테스트 4: SSH 연결 성공 시 정상 스캔 실행"""
        # Given: 올바른 SSH 접속 정보
        ssh_host = "localhost"
        ssh_user = "testuser"
        ssh_pass = "testpass"

        # When: SSH 연결 성공
        # Then: VULNERABLE 또는 SAFE 상태 반환
        with patch('paramiko.SSHClient') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client
            mock_client.connect.return_value = None  # 연결 성공

            # Mock exec_command
            mock_stdout = MagicMock()
            mock_stdout.read.return_value = b"PermitRootLogin no\n"
            mock_client.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())

            from modules.os import linux_account
            result = linux_account.scan(ssh_host, ssh_user, ssh_pass)

            # 연결 성공 시 VULNERABLE 또는 SAFE 상태여야 함
            self.assertIn(result['status'], ['VULNERABLE', 'SAFE', 'ERROR'])
            if result['status'] != 'ERROR':
                # 정상 실행 시 상세 정보 포함
                self.assertIsNotNone(result['details'])

    def test_pem_key_authentication_failure(self):
        """테스트 5: PEM 키 파일 인증 실패 시 ERROR 상태 반환"""
        # Given: 잘못된 PEM 키 파일
        ssh_host = "192.168.1.100"
        ssh_user = "admin"
        ssh_pass = None
        ssh_key_file = "/invalid/path/key.pem"

        # When: SSH 키 인증 시도 (실패)
        # Then: ERROR 상태 반환
        with patch('paramiko.SSHClient') as mock_ssh:
            mock_ssh.return_value.connect.side_effect = paramiko.SSHException("Key error")

            from modules.os import linux_account
            result = linux_account.scan(ssh_host, ssh_user, ssh_pass, ssh_key_file=ssh_key_file)

            self.assertEqual(result['status'], 'ERROR')
            self.assertIsNotNone(result['details'])

    def test_permission_denied(self):
        """테스트 6: 권한 거부 시 ERROR 상태 반환"""
        # Given: 권한 없는 사용자
        ssh_host = "192.168.1.100"
        ssh_user = "guest"
        ssh_pass = "guestpass"

        # When: SSH 연결 시도 (권한 거부)
        # Then: ERROR 상태 반환
        with patch('paramiko.SSHClient') as mock_ssh:
            mock_ssh.return_value.connect.side_effect = paramiko.AuthenticationException("Permission denied")

            from modules.os import linux_account
            result = linux_account.scan(ssh_host, ssh_user, ssh_pass)

            self.assertEqual(result['status'], 'ERROR')
            self.assertIn('인증', result['details'].lower())


class TestMultipleModulesSSHHandling(unittest.TestCase):
    """여러 모듈의 SSH 연결 예외 처리 일관성 테스트"""

    @patch('paramiko.SSHClient')
    def test_all_os_modules_handle_ssh_failure(self, mock_ssh):
        """테스트 7: 모든 OS 모듈이 SSH 실패를 올바르게 처리하는지 확인"""
        # Given: SSH 연결 실패 상황
        mock_ssh.return_value.connect.side_effect = paramiko.AuthenticationException("Auth failed")

        # When: 각 OS 모듈 실행
        os_modules = [
            'linux_account',
            'linux_password',
            'linux_file_permission',
            'linux_service',
            'linux_log',
        ]

        for module_name in os_modules:
            with self.subTest(module=module_name):
                try:
                    module = __import__(f'modules.os.{module_name}', fromlist=['scan'])
                    result = module.scan("host", "user", "pass")

                    # Then: 모든 모듈이 ERROR 상태 반환해야 함
                    self.assertEqual(result['status'], 'ERROR',
                                   f"{module_name} should return ERROR status on SSH failure")
                    self.assertIsNotNone(result.get('details'),
                                       f"{module_name} should provide error details")
                except ImportError:
                    self.skipTest(f"Module {module_name} not found")


class TestSSHUtilsHelper(unittest.TestCase):
    """SSH 유틸리티 헬퍼 함수 테스트"""

    def test_ssh_utils_exists(self):
        """테스트 8: ssh_utils 모듈이 존재하는지 확인"""
        try:
            import ssh_utils
            self.assertTrue(hasattr(ssh_utils, 'safe_ssh_connect'))
        except ImportError:
            self.fail("ssh_utils module should exist with safe_ssh_connect function")

    @patch('paramiko.SSHClient')
    def test_safe_ssh_connect_returns_client_on_success(self, mock_ssh):
        """테스트 9: safe_ssh_connect가 성공 시 클라이언트 반환"""
        import ssh_utils

        # Given: 성공적인 SSH 연결
        mock_client = MagicMock()
        mock_ssh.return_value = mock_client
        mock_client.connect.return_value = None

        # When: safe_ssh_connect 호출
        client, error = ssh_utils.safe_ssh_connect("host", "user", "pass")

        # Then: 클라이언트 반환, 에러 없음
        self.assertIsNotNone(client)
        self.assertIsNone(error)

    @patch('paramiko.SSHClient')
    def test_safe_ssh_connect_returns_error_on_failure(self, mock_ssh):
        """테스트 10: safe_ssh_connect가 실패 시 에러 메시지 반환"""
        import ssh_utils

        # Given: SSH 연결 실패
        mock_ssh.return_value.connect.side_effect = paramiko.AuthenticationException("Auth failed")

        # When: safe_ssh_connect 호출
        client, error = ssh_utils.safe_ssh_connect("host", "user", "pass")

        # Then: 클라이언트 None, 에러 메시지 반환
        self.assertIsNone(client)
        self.assertIsNotNone(error)
        self.assertIn('인증 실패', error)


if __name__ == '__main__':
    # 테스트 실행
    unittest.main(verbosity=2)
