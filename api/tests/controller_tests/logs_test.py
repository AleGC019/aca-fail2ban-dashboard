
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import sys
import os

# Agregar el directorio api al path para las importaciones
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from controllers.logs import router
from fastapi import FastAPI

# Crear una app de prueba
app = FastAPI()
app.include_router(router)
client = TestClient(app)

class TestLogsController:
    """Tests para el controlador de logs de Fail2ban"""

    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    @patch('controllers.logs.get_current_user')
    def test_get_current_banned_ips_success(self, mock_get_current_user, mock_get_banned_ips, mock_jail_exists):
        """Test exitoso de obtener IPs actualmente baneadas"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        mock_jail_exists.return_value = True
        mock_get_banned_ips.return_value = ["192.168.1.100", "10.0.0.50"]
        
        mock_get_current_user.return_value = mock_current_user
        
        response = client.get("/fail2ban/current-banned-ips?jail=sshd", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert "banned_ips" in response_data
        assert "192.168.1.100" in response_data["banned_ips"]
        assert "10.0.0.50" in response_data["banned_ips"]

    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_current_user')
    def test_get_current_banned_ips_jail_not_exists(self, mock_get_current_user, mock_jail_exists):
        """Test de obtener IPs baneadas de jail que no existe"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        mock_jail_exists.return_value = False
        
        mock_get_current_user.return_value = mock_current_user
        
        response = client.get("/fail2ban/current-banned-ips?jail=nonexistent", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 400
        assert "El jail nonexistent no existe" in response.json()["detail"]

    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    @patch('controllers.logs.get_current_user')
    def test_banned_ips_simple_success(self, mock_get_current_user, mock_get_banned_ips, mock_jail_exists):
        """Test exitoso del endpoint simplificado de IPs baneadas"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        mock_jail_exists.return_value = True
        mock_get_banned_ips.return_value = ["192.168.1.100", "10.0.0.50"]
        
        mock_get_current_user.return_value = mock_current_user
        
        response = client.get("/fail2ban/banned-ips-simple?jail=sshd&page=0&size=10", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["totalCount"] == 2
        assert len(response_data["values"]) == 2
        assert response_data["values"][0]["ip"] == "192.168.1.100"
        assert response_data["values"][0]["jail"] == "sshd"

    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    @patch('controllers.logs.get_current_user')
    def test_banned_ips_simple_empty(self, mock_get_current_user, mock_get_banned_ips, mock_jail_exists):
        """Test del endpoint simplificado cuando no hay IPs baneadas"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        mock_jail_exists.return_value = True
        mock_get_banned_ips.return_value = []
        
        mock_get_current_user.return_value = mock_current_user
        
        response = client.get("/fail2ban/banned-ips-simple?jail=sshd", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["totalCount"] == 0
        assert response_data["values"] == []

    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    @patch('controllers.logs.get_jail_ban_duration')
    @patch('controllers.logs.get_current_user')
    def test_get_banned_ips_stats_success(self, mock_get_current_user, mock_get_duration, mock_get_banned_ips, mock_jail_exists):
        """Test exitoso de obtener estadísticas de IPs baneadas"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        mock_jail_exists.return_value = True
        mock_get_banned_ips.return_value = ["192.168.1.100", "10.0.0.50"]
        mock_get_duration.return_value = 600  # 10 minutos
        
        mock_get_current_user.return_value = mock_current_user
        
        response = client.get("/fail2ban/banned-ips-stats?jail=sshd", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["summary"]["jail_name"] == "sshd"
        assert response_data["summary"]["total_banned_ips"] == 2
        assert response_data["summary"]["ban_duration"] == "10 minutos"
        assert len(response_data["banned_ips_list"]) == 2
        assert response_data["jail_status"]["jail_exists"] is True
        assert response_data["jail_status"]["has_banned_ips"] is True

    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_current_user')
    def test_get_banned_ips_stats_jail_not_exists(self, mock_get_current_user, mock_jail_exists):
        """Test de estadísticas para jail que no existe"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        mock_jail_exists.return_value = False
        
        mock_get_current_user.return_value = mock_current_user
        
        response = client.get("/fail2ban/banned-ips-stats?jail=nonexistent", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 400
        assert "El jail nonexistent no existe" in response.json()["detail"]

    @patch('controllers.logs.AsyncClient')
    @patch('controllers.logs.get_current_user')
    def test_get_filtered_logs_success(self, mock_get_current_user, mock_async_client):
        """Test exitoso de obtener logs filtrados"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        
        # Mock de la respuesta de Loki
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "result": [
                    {
                        "stream": {"job": "fail2ban"},
                        "values": [
                            ["1640995200000000000", "2022-01-01 00:00:00 fail2ban.filter[1234]: INFO Found 192.168.1.100 - 2022-01-01 00:00:00"]
                        ]
                    }
                ]
            }
        }
        
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        mock_get_current_user.return_value = mock_current_user
        
        response = client.get("/fail2ban/logs?page=0&size=10", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert "totalCount" in response_data
        assert "values" in response_data

    @patch('controllers.logs.httpx.AsyncClient')
    @patch('controllers.logs.get_current_user')
    def test_get_fail2ban_stats_success(self, mock_get_current_user, mock_async_client):
        """Test exitoso de obtener estadísticas de Fail2ban"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        
        # Mock de respuestas de Loki para diferentes consultas
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "resultType": "matrix",
                "result": [
                    {
                        "values": [["1640995200", "10"]]
                    }
                ]
            }
        }
        
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        mock_get_current_user.return_value = mock_current_user
        
        response = client.get("/fail2ban/stats", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert "logs_difference" in response_data
        assert "parse_rate" in response_data
        assert "ban_events" in response_data
        assert "warn_error_logs" in response_data

    def test_health_endpoint(self):
        """Test del endpoint de salud"""
        response = client.get("/health")
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "ok"
        assert "API de Logs y Gestión de Fail2ban funcionando" in response_data["message"]

    @patch('controllers.logs.get_current_user')
    def test_protected_stats_success(self, mock_get_current_user):
        """Test exitoso del endpoint de estadísticas protegidas"""
        mock_current_user = {
            "_id": "user_id",
            "email": "test@example.com",
            "roles": ["USER"]
        }
        
        mock_get_current_user.return_value = mock_current_user
        
        response = client.get("/protected-stats", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["user_email"] == "test@example.com"
        assert "Hola test@example.com" in response_data["message"]
        assert "protected_data" in response_data

    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    @patch('controllers.logs.get_jail_ban_duration')
    @patch('controllers.logs.AsyncClient')
    @patch('controllers.logs.get_current_user')
    def test_get_banned_ips_full_success(self, mock_get_current_user, mock_async_client, mock_get_duration, mock_get_banned_ips, mock_jail_exists):
        """Test exitoso del endpoint completo de IPs baneadas"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        mock_jail_exists.return_value = True
        mock_get_banned_ips.return_value = ["192.168.1.100"]
        mock_get_duration.return_value = 600
        
        # Mock de la respuesta de Loki
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "result": [
                    {
                        "values": [
                            ["1640995200000000000", "2022-01-01 00:00:00 fail2ban.filter[1234]: Found 192.168.1.100"],
                            ["1640995260000000000", "2022-01-01 00:01:00 fail2ban.actions[1234]: Ban 192.168.1.100"]
                        ]
                    }
                ]
            }
        }
        
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        mock_get_current_user.return_value = mock_current_user
        
        response = client.get("/fail2ban/banned-ips?jail=sshd&page=0&size=10&hours=24", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["totalCount"] >= 0
        assert "values" in response_data

    @patch('controllers.logs.get_banned_ips_with_details')
    def test_get_banned_ips_testing_success(self, mock_get_banned_ips_details):
        """Test del endpoint de testing de IPs baneadas"""
        mock_banned_ips = [
            {
                "ip": "192.168.1.100",
                "jail": "sshd",
                "ban_time": "2022-01-01 00:00:00",
                "raw_log": "Ban 192.168.1.100"
            }
        ]
        
        mock_get_banned_ips_details.return_value = mock_banned_ips
        
        response = client.get("/fail2ban/banned-ips-testing?jail=sshd&page=0&size=10&hours=24")
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["totalCount"] == 1
        assert response_data["values"][0]["ip"] == "192.168.1.100"

    @patch('controllers.logs.get_current_user')
    def test_filtered_logs_with_filters(self, mock_get_current_user):
        """Test de logs filtrados con filtros específicos"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        mock_get_current_user.return_value = mock_current_user
        
        with patch('controllers.logs.AsyncClient') as mock_async_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": {"result": []}}
            
            mock_client_instance = MagicMock()
            mock_client_instance.get.return_value = mock_response
            mock_async_client.return_value.__aenter__.return_value = mock_client_instance
            
            response = client.get(
                "/fail2ban/logs?page=0&size=10&service=fail2ban&level=ERROR&filter_text=Ban",
                headers={"Authorization": "Bearer user_token"}
            )
            
            assert response.status_code == 200

    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    @patch('controllers.logs.get_current_user')
    def test_get_current_banned_ips_error(self, mock_get_current_user, mock_get_banned_ips, mock_jail_exists):
        """Test de error al obtener IPs baneadas"""
        mock_current_user = {"_id": "user_id", "roles": ["USER"]}
        mock_jail_exists.return_value = True
        mock_get_banned_ips.side_effect = Exception("Error de conexión")
        
        mock_get_current_user.return_value = mock_current_user
        
        response = client.get("/fail2ban/current-banned-ips?jail=sshd", headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 400
        assert "Error al obtener IPs baneadas" in response.json()["detail"]
