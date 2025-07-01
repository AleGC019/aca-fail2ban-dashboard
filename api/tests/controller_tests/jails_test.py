import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from fastapi import HTTPException
import sys
import os

# Agregar el directorio api al path para las importaciones
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from controllers.jails import router
from fastapi import FastAPI

# Crear una app de prueba
app = FastAPI()
app.include_router(router)
client = TestClient(app)

class TestJailsController:
    """Tests para el controlador de jails de Fail2ban"""

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @patch('controllers.jails.require_admin')
    def test_ban_ip_success(self, mock_require_admin, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid_ip):
        """Test exitoso de banear una IP"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        
        mock_require_admin.return_value = mock_admin_user
        mock_is_valid_ip.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False
        mock_run_command.return_value = "IP banned successfully"
        
        request_data = {"ip_address": "192.168.1.100"}
        response = client.post("/jails/sshd/ban-ip", json=request_data, headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "success"
        assert "ha sido baneada" in response_data["message"]
        assert response_data["ip_address"] == "192.168.1.100"
        assert response_data["jail"] == "sshd"

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.require_admin')
    def test_ban_ip_invalid_format(self, mock_require_admin, mock_is_valid_ip):
        """Test de banear IP con formato inválido"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        
        mock_require_admin.return_value = mock_admin_user
        mock_is_valid_ip.return_value = False
        
        request_data = {"ip_address": "invalid-ip"}
        response = client.post("/jails/sshd/ban-ip", json=request_data, headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 400
        assert "Formato de dirección IP inválido" in response.json()["detail"]

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.require_admin')
    def test_ban_ip_jail_not_exists(self, mock_require_admin, mock_jail_exists, mock_is_valid_ip):
        """Test de banear IP en jail que no existe"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        
        mock_require_admin.return_value = mock_admin_user
        mock_is_valid_ip.return_value = True
        mock_jail_exists.return_value = False
        
        request_data = {"ip_address": "192.168.1.100"}
        response = client.post("/jails/nonexistent/ban-ip", json=request_data, headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 400
        assert "El jail nonexistent no existe" in response.json()["detail"]

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.require_admin')
    def test_ban_ip_already_banned(self, mock_require_admin, mock_is_banned, mock_jail_exists, mock_is_valid_ip):
        """Test de banear IP que ya está baneada"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        
        mock_require_admin.return_value = mock_admin_user
        mock_is_valid_ip.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = True
        
        request_data = {"ip_address": "192.168.1.100"}
        response = client.post("/jails/sshd/ban-ip", json=request_data, headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "info"
        assert "ya está baneada" in response_data["message"]

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @patch('controllers.jails.require_admin')
    def test_unban_ip_success(self, mock_require_admin, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid_ip):
        """Test exitoso de desbanear una IP"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        
        mock_require_admin.return_value = mock_admin_user
        mock_is_valid_ip.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = True
        mock_run_command.return_value = "IP unbanned successfully"
        
        request_data = {"ip_address": "192.168.1.100"}
        response = client.post("/jails/sshd/unban-ip", json=request_data, headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "success"
        assert "ha sido desbaneada" in response_data["message"]
        assert response_data["ip_address"] == "192.168.1.100"
        assert response_data["jail"] == "sshd"

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.require_admin')
    def test_unban_ip_not_banned(self, mock_require_admin, mock_is_banned, mock_jail_exists, mock_is_valid_ip):
        """Test de desbanear IP que no está baneada"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        
        mock_require_admin.return_value = mock_admin_user
        mock_is_valid_ip.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False
        
        request_data = {"ip_address": "192.168.1.100"}
        response = client.post("/jails/sshd/unban-ip", json=request_data, headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "info"
        assert "no está baneada" in response_data["message"]

    @patch('controllers.jails.run_fail2ban_command')
    @patch('controllers.jails.get_current_user')
    def test_get_jails_success(self, mock_get_current_user, mock_run_command):
        """Test exitoso de obtener lista de jails"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        mock_output = "Status\n|- Number of jail: 2\n`- Jail list: sshd, apache-auth"
        
        mock_get_current_user.return_value = mock_current_user
        mock_run_command.return_value = mock_output
        
        response = client.get("/jails", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert "sshd" in response_data
        assert "apache-auth" in response_data
        assert len(response_data) == 2

    @patch('controllers.jails.run_fail2ban_command')
    @patch('controllers.jails.get_current_user')
    def test_get_jails_empty(self, mock_get_current_user, mock_run_command):
        """Test de obtener lista de jails cuando no hay ninguno"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        mock_output = "Status\nno jail"
        
        mock_get_current_user.return_value = mock_current_user
        mock_run_command.return_value = mock_output
        
        response = client.get("/jails", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data == []

    @patch('controllers.jails.run_fail2ban_command')
    @patch('controllers.jails.get_current_user')
    def test_get_jails_parse_error(self, mock_get_current_user, mock_run_command):
        """Test de error al parsear la lista de jails"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        mock_output = "Error: malformed output"
        
        mock_get_current_user.return_value = mock_current_user
        mock_run_command.return_value = mock_output
        
        response = client.get("/jails", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 500
        assert "No se pudo obtener la lista de jails" in response.json()["detail"]

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @patch('controllers.jails.require_admin')
    def test_ban_ip_already_banned_output(self, mock_require_admin, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid_ip):
        """Test de banear IP que devuelve 'already banned' en la salida"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        
        mock_require_admin.return_value = mock_admin_user
        mock_is_valid_ip.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False  # No detectado inicialmente
        mock_run_command.return_value = "192.168.1.100 already banned"
        
        request_data = {"ip_address": "192.168.1.100"}
        response = client.post("/jails/sshd/ban-ip", json=request_data, headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "info"
        assert "ya estaba baneada" in response_data["message"]

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @patch('controllers.jails.require_admin')
    def test_unban_ip_not_banned_output(self, mock_require_admin, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid_ip):
        """Test de desbanear IP que devuelve 'is not banned' en la salida"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        
        mock_require_admin.return_value = mock_admin_user
        mock_is_valid_ip.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = True  # Detectado inicialmente como baneado
        mock_run_command.return_value = "192.168.1.100 is not banned"
        
        request_data = {"ip_address": "192.168.1.100"}
        response = client.post("/jails/sshd/unban-ip", json=request_data, headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "info"
        assert "no estaba baneada" in response_data["message"]
