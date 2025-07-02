import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from fastapi import FastAPI
import sys
import os

# Agregar el directorio api al path para las importaciones
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from controllers.jails import router
from services.auth import require_admin, get_current_user

class TestJailsController:
    """Tests para el controlador de jails de Fail2ban"""

    @pytest.fixture
    def admin_user(self):
        """Fixture para usuario admin"""
        return {
            "_id": "admin_id",
            "username": "admin",
            "email": "admin@test.com",
            "roles": ["ADMIN"]
        }

    @pytest.fixture
    def auth_headers(self, sync_admin_token):
        """Headers de autorización"""
        return {"Authorization": f"Bearer {sync_admin_token}"}

    @pytest.fixture
    def client(self, admin_user):
        """Fixture para cliente de test con override de autenticación"""
        # Crear una app de prueba
        app = FastAPI()
        app.include_router(router)
        
        # Mock functions para bypass de autenticación
        def mock_get_current_user():
            return admin_user
            
        def mock_require_admin():
            return admin_user
        
        # Override de dependencias
        app.dependency_overrides[get_current_user] = mock_get_current_user
        app.dependency_overrides[require_admin] = mock_require_admin
        
        return TestClient(app)

    @patch('controllers.jails.require_admin')
    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    def test_ban_ip_success(self, mock_run_command, mock_is_banned, mock_jail_exists, 
                           mock_is_valid_ip, mock_require_admin, client, admin_user, auth_headers):
        """Test exitoso de banear una IP"""
        # Configurar mocks
        mock_require_admin.return_value = admin_user
        mock_is_valid_ip.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False
        mock_run_command.return_value = "IP banned successfully"
        
        request_data = {"ip_address": "192.168.1.100"}
        response = client.post("/jails/sshd/ban-ip", json=request_data, headers=auth_headers)
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "success"
        assert "ha sido baneada" in response_data["message"]
        assert response_data["ip_address"] == "192.168.1.100"
        assert response_data["jail"] == "sshd"

    @patch('controllers.jails.require_admin')
    @patch('controllers.jails.is_valid_ip')
    def test_ban_ip_invalid_format(self, mock_is_valid_ip, mock_require_admin, 
                                  client, admin_user, auth_headers):
        """Test de banear IP con formato inválido"""
        mock_require_admin.return_value = admin_user
        mock_is_valid_ip.return_value = False
        
        request_data = {"ip_address": "invalid_ip"}
        response = client.post("/jails/sshd/ban-ip", json=request_data, headers=auth_headers)
        
        assert response.status_code == 400
        assert "Formato de dirección IP inválido" in response.json()["detail"]

    @patch('controllers.jails.require_admin')
    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    def test_ban_ip_jail_not_exists(self, mock_jail_exists, mock_is_valid_ip, 
                                   mock_require_admin, client, admin_user, auth_headers):
        """Test de banear IP en jail que no existe"""
        mock_require_admin.return_value = admin_user
        mock_is_valid_ip.return_value = True
        mock_jail_exists.return_value = False
        
        request_data = {"ip_address": "192.168.1.100"}
        response = client.post("/jails/nonexistent/ban-ip", json=request_data, headers=auth_headers)
        
        assert response.status_code == 400
        assert "no existe" in response.json()["detail"]

    @patch('controllers.jails.require_admin')
    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    def test_ban_ip_already_banned(self, mock_is_banned, mock_jail_exists, 
                                  mock_is_valid_ip, mock_require_admin, 
                                  client, admin_user, auth_headers):
        """Test de banear IP que ya está baneada"""
        mock_require_admin.return_value = admin_user
        mock_is_valid_ip.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = True
        
        request_data = {"ip_address": "192.168.1.100"}
        response = client.post("/jails/sshd/ban-ip", json=request_data, headers=auth_headers)
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "info"
        assert "ya está baneada" in response_data["message"]

    @patch('controllers.jails.require_admin')
    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    def test_unban_ip_success(self, mock_run_command, mock_is_banned, mock_jail_exists, 
                             mock_is_valid_ip, mock_require_admin, 
                             client, admin_user, auth_headers):
        """Test exitoso de desbanear una IP"""
        mock_require_admin.return_value = admin_user
        mock_is_valid_ip.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = True
        mock_run_command.return_value = "IP unbanned successfully"
        
        request_data = {"ip_address": "192.168.1.100"}
        response = client.post("/jails/sshd/unban-ip", json=request_data, headers=auth_headers)
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "success"
        assert "ha sido desbaneada" in response_data["message"]

    @patch('controllers.jails.require_admin')
    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    def test_unban_ip_not_banned(self, mock_is_banned, mock_jail_exists, 
                                mock_is_valid_ip, mock_require_admin, 
                                client, admin_user, auth_headers):
        """Test de desbanear IP que no está baneada"""
        mock_require_admin.return_value = admin_user
        mock_is_valid_ip.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False
        
        request_data = {"ip_address": "192.168.1.100"}
        response = client.post("/jails/sshd/unban-ip", json=request_data, headers=auth_headers)
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "info"
        assert "no está baneada" in response_data["message"]

    @patch('controllers.jails.get_current_user')
    @patch('controllers.jails.run_fail2ban_command')
    def test_get_jails_success(self, mock_run_command, mock_get_current_user, 
                              client, admin_user, auth_headers):
        """Test exitoso de obtener lista de jails"""
        mock_get_current_user.return_value = admin_user
        mock_run_command.return_value = "Status\n`- Jail list: sshd, apache2, nginx"
        
        response = client.get("/jails", headers=auth_headers)
        
        assert response.status_code == 200
        response_data = response.json()
        assert "sshd" in response_data
        assert "apache2" in response_data
        assert "nginx" in response_data

    @patch('controllers.jails.get_current_user')
    @patch('controllers.jails.run_fail2ban_command')
    def test_get_jails_empty(self, mock_run_command, mock_get_current_user, 
                            client, admin_user, auth_headers):
        """Test de obtener lista vacía de jails"""
        mock_get_current_user.return_value = admin_user
        mock_run_command.return_value = "Status\n`- no jail"
        
        response = client.get("/jails", headers=auth_headers)
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data == []

    @patch('controllers.jails.get_current_user')
    @patch('controllers.jails.run_fail2ban_command')
    def test_get_jails_parse_error(self, mock_run_command, mock_get_current_user, 
                                  client, admin_user, auth_headers):
        """Test de error al parsear lista de jails"""
        mock_get_current_user.return_value = admin_user
        mock_run_command.return_value = "Invalid output"
        
        response = client.get("/jails", headers=auth_headers)
        
        assert response.status_code == 500
        assert "No se pudo obtener la lista de jails" in response.json()["detail"]
