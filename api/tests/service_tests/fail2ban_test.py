import pytest
from unittest.mock import patch, MagicMock
import subprocess
import sys
import os
from datetime import datetime

# Agregar el directorio api al path para las importaciones
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from services.fail2ban import (
    is_valid_ip,
    jail_exists,
    is_ip_banned,
    get_currently_banned_ips,
    run_fail2ban_command,
    get_fail2ban_log_path,
    get_jail_ban_duration,
    format_duration
)

class TestFail2banService:
    """Tests para el servicio de Fail2ban"""

    def test_is_valid_ip_ipv4_valid(self):
        """Test de validación de IP IPv4 válida"""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "127.0.0.1"
        ]
        
        for ip in valid_ips:
            assert is_valid_ip(ip) is True

    def test_is_valid_ip_ipv4_invalid(self):
        """Test de validación de IP IPv4 inválida"""
        invalid_ips = [
            "256.256.256.256",
            "192.168.1",
            "192.168.1.1.1",
            "192.168.-1.1",
            "not.an.ip.address",
            "",
            "abc.def.ghi.jkl"
        ]
        
        for ip in invalid_ips:
            assert is_valid_ip(ip) is False

    def test_is_valid_ip_ipv6_valid(self):
        """Test de validación de IP IPv6 válida"""
        valid_ipv6s = [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8:85a3::8a2e:370:7334",
            "::1",
            "fe80::1"
        ]
        
        for ip in valid_ipv6s:
            assert is_valid_ip(ip) is True

    @patch('services.fail2ban.subprocess.run')
    def test_jail_exists_success(self, mock_run):
        """Test exitoso de verificación de existencia de jail"""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_run.return_value = mock_process
        
        result = jail_exists("sshd")
        
        assert result is True
        mock_run.assert_called_once_with(
            ["fail2ban-client", "status", "sshd"],
            capture_output=True,
            text=True,
            timeout=10
        )

    @patch('services.fail2ban.subprocess.run')
    def test_jail_exists_not_found(self, mock_run):
        """Test de jail que no existe"""
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_run.return_value = mock_process
        
        result = jail_exists("nonexistent")
        
        assert result is False

    @patch('services.fail2ban.subprocess.run')
    def test_jail_exists_timeout(self, mock_run):
        """Test de timeout al verificar jail"""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["fail2ban-client"], timeout=10)
        
        result = jail_exists("sshd")
        
        assert result is False

    @patch('services.fail2ban.subprocess.run')
    def test_jail_exists_file_not_found(self, mock_run):
        """Test cuando fail2ban-client no está instalado"""
        mock_run.side_effect = FileNotFoundError()
        
        result = jail_exists("sshd")
        
        assert result is False

    @patch('services.fail2ban.subprocess.run')
    def test_is_ip_banned_true(self, mock_run):
        """Test de IP que está baneada"""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "['192.168.1.100', '10.0.0.50']"
        mock_process.stderr = ""
        mock_run.return_value = mock_process
        
        result = is_ip_banned("sshd", "192.168.1.100")
        
        assert result is True

    @patch('services.fail2ban.subprocess.run')
    def test_is_ip_banned_false(self, mock_run):
        """Test de IP que no está baneada"""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "['10.0.0.50']"
        mock_process.stderr = ""
        mock_run.return_value = mock_process
        
        result = is_ip_banned("sshd", "192.168.1.100")
        
        assert result is False

    @patch('services.fail2ban.subprocess.run')
    def test_is_ip_banned_empty_list(self, mock_run):
        """Test cuando no hay IPs baneadas"""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = ""
        mock_process.stderr = ""
        mock_run.return_value = mock_process
        
        result = is_ip_banned("sshd", "192.168.1.100")
        
        assert result is False

    @patch('services.fail2ban.subprocess.run')
    def test_is_ip_banned_command_error(self, mock_run):
        """Test de error en comando de verificación"""
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stderr = "ERROR: Jail 'nonexistent' does not exist"
        mock_run.return_value = mock_process
        
        result = is_ip_banned("nonexistent", "192.168.1.100")
        
        assert result is False

    @patch('services.fail2ban.subprocess.run')
    def test_get_currently_banned_ips_success(self, mock_run):
        """Test exitoso de obtener IPs actualmente baneadas"""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "['192.168.1.100', '10.0.0.50', '172.16.0.25']"
        mock_process.stderr = ""
        mock_run.return_value = mock_process
        
        result = get_currently_banned_ips("sshd")
        
        assert result == ["192.168.1.100", "10.0.0.50", "172.16.0.25"]

    @patch('services.fail2ban.subprocess.run')
    def test_get_currently_banned_ips_empty(self, mock_run):
        """Test de obtener IPs baneadas cuando la lista está vacía"""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = ""
        mock_process.stderr = ""
        mock_run.return_value = mock_process
        
        result = get_currently_banned_ips("sshd")
        
        assert result == []

    @patch('services.fail2ban.subprocess.run')
    def test_get_currently_banned_ips_error(self, mock_run):
        """Test de error al obtener IPs baneadas"""
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stderr = "ERROR: Jail 'nonexistent' does not exist"
        mock_run.return_value = mock_process
        
        result = get_currently_banned_ips("nonexistent")
        
        assert result == []

    @patch('services.fail2ban.subprocess.run')
    def test_run_fail2ban_command_success(self, mock_run):
        """Test exitoso de ejecutar comando fail2ban"""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "Command executed successfully"
        mock_process.stderr = ""
        mock_run.return_value = mock_process
        
        result = run_fail2ban_command(["status"])
        
        assert result == "Command executed successfully"
        mock_run.assert_called_once_with(
            ["fail2ban-client", "status"],
            capture_output=True,
            text=True
        )

    @patch('services.fail2ban.subprocess.run')
    def test_run_fail2ban_command_no_output(self, mock_run):
        """Test de comando sin salida"""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = ""
        mock_process.stderr = ""
        mock_run.return_value = mock_process
        
        result = run_fail2ban_command(["status"])
        
        assert result == "Comando ejecutado sin salida."

    @patch('services.fail2ban.subprocess.run')
    def test_run_fail2ban_command_already_banned(self, mock_run):
        """Test de comando con mensaje 'already banned'"""
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stdout = "192.168.1.100 already banned"
        mock_process.stderr = ""
        mock_run.return_value = mock_process
        
        result = run_fail2ban_command(["set", "sshd", "banip", "192.168.1.100"])
        
        assert result == "192.168.1.100 already banned"

    @patch('services.fail2ban.subprocess.run')
    def test_run_fail2ban_command_not_banned(self, mock_run):
        """Test de comando con mensaje 'is not banned'"""
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stdout = "192.168.1.100 is not banned"
        mock_process.stderr = ""
        mock_run.return_value = mock_process
        
        result = run_fail2ban_command(["set", "sshd", "unbanip", "192.168.1.100"])
        
        assert result == "192.168.1.100 is not banned"

    @patch('services.fail2ban.subprocess.run')
    def test_run_fail2ban_command_error(self, mock_run):
        """Test de error en comando fail2ban"""
        from fastapi import HTTPException
        
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stdout = ""
        mock_process.stderr = "ERROR: Invalid command"
        mock_run.return_value = mock_process
        
        with pytest.raises(HTTPException) as exc_info:
            run_fail2ban_command(["invalid", "command"])
        
        assert exc_info.value.status_code == 400
        assert "ERROR: Invalid command" in exc_info.value.detail

    @patch('services.fail2ban.subprocess.run')
    def test_run_fail2ban_command_file_not_found(self, mock_run):
        """Test cuando fail2ban-client no está instalado"""
        from fastapi import HTTPException
        
        mock_run.side_effect = FileNotFoundError()
        
        with pytest.raises(HTTPException) as exc_info:
            run_fail2ban_command(["status"])
        
        assert exc_info.value.status_code == 500
        assert "fail2ban-client no encontrado" in exc_info.value.detail

    @patch('services.fail2ban.os.path.exists')
    def test_get_fail2ban_log_path_debian(self, mock_exists):
        """Test de obtener ruta de log en sistema Debian"""
        def side_effect(path):
            return path == "/var/log/fail2ban.log"
        
        mock_exists.side_effect = side_effect
        
        result = get_fail2ban_log_path()
        
        assert result == "/var/log/fail2ban.log"

    @patch('services.fail2ban.os.path.exists')
    def test_get_fail2ban_log_path_centos(self, mock_exists):
        """Test de obtener ruta de log en sistema CentOS"""
        def side_effect(path):
            return path == "/var/log/messages"
        
        mock_exists.side_effect = side_effect
        
        result = get_fail2ban_log_path()
        
        assert result == "/var/log/messages"

    @patch('services.fail2ban.os.path.exists')
    def test_get_fail2ban_log_path_not_found(self, mock_exists):
        """Test cuando no se encuentra el archivo de log"""
        mock_exists.return_value = False
        
        result = get_fail2ban_log_path()
        
        assert result is None

    @patch('services.fail2ban.subprocess.run')
    def test_get_jail_ban_duration_success(self, mock_run):
        """Test exitoso de obtener duración de ban"""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "600"  # 10 minutos
        mock_run.return_value = mock_process
        
        result = get_jail_ban_duration("sshd")
        
        assert result == 600

    @patch('services.fail2ban.subprocess.run')
    def test_get_jail_ban_duration_error(self, mock_run):
        """Test de error al obtener duración de ban"""
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stderr = "ERROR: Jail not found"
        mock_run.return_value = mock_process
        
        result = get_jail_ban_duration("nonexistent")
        
        assert result is None

    def test_format_duration_seconds(self):
        """Test de formateo de duración en segundos"""
        assert format_duration(45) == "45 segundos"
        assert format_duration(1) == "1 segundo"

    def test_format_duration_minutes(self):
        """Test de formateo de duración en minutos"""
        assert format_duration(60) == "1 minuto"
        assert format_duration(120) == "2 minutos"
        assert format_duration(90) == "1 minuto, 30 segundos"

    def test_format_duration_hours(self):
        """Test de formateo de duración en horas"""
        assert format_duration(3600) == "1 hora"
        assert format_duration(7200) == "2 horas"
        assert format_duration(3660) == "1 hora, 1 minuto"
        assert format_duration(3690) == "1 hora, 1 minuto, 30 segundos"

    def test_format_duration_days(self):
        """Test de formateo de duración en días"""
        assert format_duration(86400) == "1 día"
        assert format_duration(172800) == "2 días"
        assert format_duration(90000) == "1 día, 1 hora"

    def test_format_duration_complex(self):
        """Test de formateo de duración compleja"""
        # 1 día, 2 horas, 3 minutos, 30 segundos
        duration = 86400 + 7200 + 180 + 30
        result = format_duration(duration)
        assert "1 día" in result
        assert "2 horas" in result
        assert "3 minutos" in result
        assert "30 segundos" in result

    @patch('services.fail2ban.subprocess.run')
    def test_is_ip_banned_timeout(self, mock_run):
        """Test de timeout al verificar IP baneada"""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["fail2ban-client"], timeout=10)
        
        result = is_ip_banned("sshd", "192.168.1.100")
        
        assert result is False

    @patch('services.fail2ban.subprocess.run')
    def test_get_currently_banned_ips_malformed_output(self, mock_run):
        """Test con salida malformada del comando banned"""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "malformed output without proper format"
        mock_process.stderr = ""
        mock_run.return_value = mock_process
        
        result = get_currently_banned_ips("sshd")
        
        assert result == []
