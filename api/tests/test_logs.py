"""
Tests unitarios para controllers/logs.py

Este módulo contiene tests completos para todas las funciones y endpoints
del controller de logs, excluyendo WebSocket que se testea en test_websocket.py
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch

import httpx
from fastapi import HTTPException

from controllers.logs import (
    query_loki_with_retry,
    query_loki_with_retry_banned_ips
)


class TestQueryLokiWithRetry:
    """Tests para la función query_loki_with_retry"""

    @pytest.mark.asyncio
    async def test_successful_query_first_attempt(self):
        """Test de consulta exitosa en el primer intento"""
        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"result": []}}
        mock_client.get.return_value = mock_response
        
        url = "http://loki:3100/api/v1/query_range?query=test"
        result = await query_loki_with_retry(mock_client, url)
        
        assert result == {"data": {"result": []}}
        mock_client.get.assert_called_once_with(url)

    @pytest.mark.asyncio
    async def test_retry_on_429_status(self):
        """Test de reintentos con backoff exponencial en error 429"""
        mock_client = AsyncMock()
        
        # Primer intento: 429, segundo intento: éxito
        responses = [
            Mock(status_code=429),
            Mock(status_code=200, json=lambda: {"data": {"result": []}})
        ]
        mock_client.get.side_effect = responses
        
        url = "http://loki:3100/api/v1/query_range?query=test"
        
        with patch('asyncio.sleep') as mock_sleep:
            result = await query_loki_with_retry(mock_client, url, max_retries=3, base_delay=1)
        
        assert result == {"data": {"result": []}}
        assert mock_client.get.call_count == 2
        mock_sleep.assert_called_once()

    @pytest.mark.asyncio
    async def test_max_retries_exceeded(self):
        """Test cuando se agotan todos los reintentos"""
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Connection error")
        
        url = "http://loki:3100/api/v1/query_range?query=test"
        
        with patch('asyncio.sleep'):
            with pytest.raises(Exception, match="Connection error"):
                await query_loki_with_retry(mock_client, url, max_retries=2, base_delay=1)
        
        assert mock_client.get.call_count == 2

    @pytest.mark.asyncio
    async def test_non_200_status_code(self):
        """Test para códigos de estado diferentes a 200"""
        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.status_code = 500
        mock_client.get.return_value = mock_response
        
        url = "http://loki:3100/api/v1/query_range?query=test"
        
        with pytest.raises(ValueError, match="Query failed with status 500"):
            await query_loki_with_retry(mock_client, url, max_retries=1)


class TestQueryLokiWithRetryBannedIps:
    """Tests para la función query_loki_with_retry_banned_ips"""

    @pytest.mark.asyncio
    async def test_successful_banned_ips_query(self):
        """Test de consulta exitosa para IPs baneadas"""
        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.json.return_value = {"data": {"result": []}}
        mock_client.get.return_value = mock_response
        
        url = "http://loki:3100/api/v1/query_range?query=banned"
        result = await query_loki_with_retry_banned_ips(mock_client, url)
        
        assert result == {"data": {"result": []}}

    @pytest.mark.asyncio
    async def test_http_status_error_429(self):
        """Test manejo de HTTPStatusError 429"""
        mock_client = AsyncMock()
        
        # Simular error 429 y luego éxito
        error_response = Mock()
        error_response.status_code = 429
        success_response = Mock()
        success_response.json.return_value = {"data": {"result": []}}
        
        mock_client.get.side_effect = [
            httpx.HTTPStatusError("Too Many Requests", request=Mock(), response=error_response),
            success_response
        ]
        
        url = "http://loki:3100/api/v1/query_range?query=banned"
        
        with patch('asyncio.sleep'):
            result = await query_loki_with_retry_banned_ips(mock_client, url, max_retries=2)
        
        assert result == {"data": {"result": []}}

    @pytest.mark.asyncio
    async def test_http_status_error_non_429(self):
        """Test manejo de HTTPStatusError diferente a 429"""
        mock_client = AsyncMock()
        error_response = Mock()
        error_response.status_code = 500
        
        mock_client.get.side_effect = httpx.HTTPStatusError(
            "Internal Server Error", 
            request=Mock(), 
            response=error_response
        )
        
        url = "http://loki:3100/api/v1/query_range?query=banned"
        
        with pytest.raises(HTTPException) as exc_info:
            await query_loki_with_retry_banned_ips(mock_client, url)
        
        assert exc_info.value.status_code == 503
        assert "Error en consulta a Loki (estado 500)" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_general_exception_max_retries(self):
        """Test manejo de excepción general tras máximo de reintentos"""
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Network error")
        
        url = "http://loki:3100/api/v1/query_range?query=banned"
        
        with patch('asyncio.sleep'):
            with pytest.raises(HTTPException) as exc_info:
                await query_loki_with_retry_banned_ips(mock_client, url, max_retries=2)
        
        assert exc_info.value.status_code == 503
        assert "Error al contactar Loki tras 2 intentos" in str(exc_info.value.detail)


class TestBannedIpsEndpoint:
    """Tests para el endpoint /fail2ban/banned-ips"""

    @pytest.fixture
    def mock_settings(self):
        """Mock de configuración"""
        with patch('controllers.logs.settings') as mock:
            mock.LOKI_QUERY_URL = "http://loki:3100/api/v1/query_range"
            yield mock

    @pytest.fixture
    def sample_banned_ips(self):
        """IPs baneadas de ejemplo"""
        return ["192.168.1.100", "10.0.0.50"]

    @pytest.fixture
    def sample_loki_response(self):
        """Respuesta de ejemplo de Loki con formato correcto"""
        return {
            "data": {
                "result": [{
                    "stream": {"job": "fail2ban", "jail": "sshd"},
                    "values": [
                        ["1671234567000000000", "2025-05-25 16:59:22,667 fail2ban.actions [128145]: NOTICE [sshd] Ban 192.168.1.100"]
                    ]
                }]
            }
        }

    @pytest.fixture
    def sample_loki_response_second_ip(self):
        """Respuesta de ejemplo de Loki para la segunda IP con formato correcto"""
        return {
            "data": {
                "result": [{
                    "stream": {"job": "fail2ban", "jail": "sshd"},
                    "values": [
                        ["1671234568000000000", "2025-05-25 16:59:23,667 fail2ban.actions [128146]: NOTICE [sshd] Ban 10.0.0.50"]
                    ]
                }]
            }
        }

    @pytest.mark.asyncio
    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    async def test_get_banned_ips_success(self, mock_get_banned, mock_jail_exists, mock_settings, sample_banned_ips, sample_loki_response, sample_loki_response_second_ip):
        """Test exitoso de obtención de IPs baneadas"""
        # Setup mocks
        mock_jail_exists.return_value = True
        mock_get_banned.return_value = sample_banned_ips
        
        # Mock del cliente HTTP
        with patch('controllers.logs.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            with patch('controllers.logs.query_loki_with_retry') as mock_query:
                # Función personalizada para simular múltiples respuestas
                call_responses = [sample_loki_response, sample_loki_response_second_ip]
                call_count = 0
                
                async def mock_query_func(*args, **kwargs):
                    nonlocal call_count
                    if call_count < len(call_responses):
                        result = call_responses[call_count]
                        call_count += 1
                        return result
                    else:
                        return {"data": {"result": []}}
                
                mock_query.side_effect = mock_query_func
                
                # Importar después de los patches para usar el router mockeado
                from fastapi.testclient import TestClient
                from main import app
                
                client = TestClient(app)
                response = client.get("/fail2ban/banned-ips?jail=sshd&page=0&size=10&hours=24")
        
        assert response.status_code == 200
        data = response.json()
        assert data["totalCount"] == 2
        assert data["currentPage"] == 0
        assert len(data["values"]) == 2
        assert data["values"][0]["ip"] in sample_banned_ips
        assert data["values"][1]["ip"] in sample_banned_ips

    @pytest.mark.asyncio
    @patch('controllers.logs.jail_exists')
    async def test_get_banned_ips_jail_not_exists(self, mock_jail_exists, mock_settings):
        """Test cuando el jail no existe"""
        mock_jail_exists.return_value = False
        
        from fastapi.testclient import TestClient
        from main import app
        
        client = TestClient(app)
        response = client.get("/fail2ban/banned-ips?jail=nonexistent")
        
        assert response.status_code == 400
        assert "El jail nonexistent no existe" in response.json()["detail"]

    @pytest.mark.asyncio
    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    async def test_get_banned_ips_no_banned_ips(self, mock_get_banned, mock_jail_exists, mock_settings):
        """Test cuando no hay IPs baneadas"""
        mock_jail_exists.return_value = True
        mock_get_banned.return_value = []
        
        from fastapi.testclient import TestClient
        from main import app
        
        client = TestClient(app)
        response = client.get("/fail2ban/banned-ips?jail=sshd")
        
        assert response.status_code == 200
        data = response.json()
        assert data["totalCount"] == 0
        assert data["values"] == []

    @pytest.mark.asyncio
    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    async def test_get_banned_ips_fail2ban_error(self, mock_get_banned, mock_jail_exists, mock_settings):
        """Test cuando fail2ban devuelve error"""
        mock_jail_exists.return_value = True
        mock_get_banned.side_effect = Exception("Fail2ban service error")
        
        from fastapi.testclient import TestClient
        from main import app
        
        client = TestClient(app)
        response = client.get("/fail2ban/banned-ips?jail=sshd")
        
        assert response.status_code == 400
        assert "Error al obtener IPs baneadas" in response.json()["detail"]

    @pytest.mark.asyncio
    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    async def test_get_banned_ips_pagination(self, mock_get_banned, mock_jail_exists, mock_settings):
        """Test de paginación correcta"""
        mock_jail_exists.return_value = True
        # Generar 15 IPs para testear paginación
        mock_ips = [f"192.168.1.{i}" for i in range(1, 16)]
        mock_get_banned.return_value = mock_ips
        
        # Mock respuesta vacía de Loki para simplificar
        with patch('controllers.logs.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            with patch('controllers.logs.query_loki_with_retry') as mock_query:
                mock_query.return_value = {"data": {"result": []}}
                
                from fastapi.testclient import TestClient
                from main import app
                
                client = TestClient(app)
                
                # Primera página
                response = client.get("/fail2ban/banned-ips?jail=sshd&page=0&size=10")
                assert response.status_code == 200
                data = response.json()
                assert data["totalCount"] == 15
                assert data["totalPages"] == 2
                assert data["hasNextPage"] is True
                assert data["hasPreviousPage"] is False
                assert len(data["values"]) == 10
                
                # Segunda página
                response = client.get("/fail2ban/banned-ips?jail=sshd&page=1&size=10")
                assert response.status_code == 200
                data = response.json()
                assert data["hasNextPage"] is False
                assert data["hasPreviousPage"] is True
                assert len(data["values"]) == 5

    @pytest.mark.asyncio
    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    async def test_get_banned_ips_with_fallback(self, mock_get_banned, mock_jail_exists, mock_settings, sample_banned_ips, sample_loki_response):
        """Test cuando una IP no tiene logs en Loki (fallback)"""
        mock_jail_exists.return_value = True
        mock_get_banned.return_value = sample_banned_ips
        
        # Mock del cliente HTTP
        with patch('controllers.logs.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            with patch('controllers.logs.query_loki_with_retry') as mock_query:
                # Primera IP tiene logs, segunda IP no tiene logs (respuesta vacía)
                empty_response = {"data": {"result": []}}
                call_responses = [sample_loki_response, empty_response]
                call_count = 0
                
                async def mock_query_func(*args, **kwargs):
                    nonlocal call_count
                    if call_count < len(call_responses):
                        result = call_responses[call_count]
                        call_count += 1
                        return result
                    else:
                        return {"data": {"result": []}}
                
                mock_query.side_effect = mock_query_func
                
                from fastapi.testclient import TestClient
                from main import app
                
                client = TestClient(app)
                response = client.get("/fail2ban/banned-ips?jail=sshd&page=0&size=10&hours=24")
        
        assert response.status_code == 200
        data = response.json()
        assert data["totalCount"] == 2
        assert len(data["values"]) == 2
        
        # Verificar que una entrada tiene log real y otra el fallback
        ips_found = [entry["ip"] for entry in data["values"]]
        assert "192.168.1.100" in ips_found
        assert "10.0.0.50" in ips_found
        
        # Verificar que hay un fallback para la IP sin logs
        fallback_entry = next((entry for entry in data["values"] if "No disponible" in entry["raw_log"]), None)
        assert fallback_entry is not None
        assert fallback_entry["ip"] == "10.0.0.50"

    @pytest.mark.asyncio
    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    async def test_get_banned_ips_debug(self, mock_get_banned, mock_jail_exists, mock_settings):
        """Test de depuración para entender el comportamiento"""
        mock_jail_exists.return_value = True
        mock_get_banned.return_value = ["192.168.1.100"]  # Solo una IP para simplificar
        
        # Respuesta que sabemos que debería funcionar
        debug_response = {
            "data": {
                "result": [{
                    "stream": {"job": "fail2ban", "jail": "sshd"},
                    "values": [
                        ["1671234567000000000", "2025-05-25 16:59:22,667 fail2ban.actions [128145]: NOTICE [sshd] Ban 192.168.1.100"]
                    ]
                }]
            }
        }
        
        with patch('controllers.logs.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            with patch('controllers.logs.query_loki_with_retry') as mock_query:
                mock_query.return_value = debug_response
                
                from fastapi.testclient import TestClient
                from main import app
                
                client = TestClient(app)
                response = client.get("/fail2ban/banned-ips?jail=sshd&page=0&size=10&hours=24")
                
                print(f"Response status: {response.status_code}")
                print(f"Response data: {response.json()}")
        
        assert response.status_code == 200


class TestCurrentBannedIpsEndpoint:
    """Tests para el endpoint /fail2ban/current-banned-ips"""

    @pytest.mark.asyncio
    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    async def test_get_current_banned_ips_success(self, mock_get_banned, mock_jail_exists):
        """Test exitoso de IPs actualmente baneadas"""
        mock_jail_exists.return_value = True
        mock_get_banned.return_value = ["192.168.1.100", "10.0.0.50"]
        
        from fastapi.testclient import TestClient
        from main import app
        
        client = TestClient(app)
        response = client.get("/fail2ban/current-banned-ips?jail=sshd")
        
        assert response.status_code == 200
        data = response.json()
        assert "banned_ips" in data
        assert len(data["banned_ips"]) == 2

    @pytest.mark.asyncio
    @patch('controllers.logs.jail_exists')
    async def test_get_current_banned_ips_jail_not_exists(self, mock_jail_exists):
        """Test cuando el jail no existe"""
        mock_jail_exists.return_value = False
        
        from fastapi.testclient import TestClient
        from main import app
        
        client = TestClient(app)
        response = client.get("/fail2ban/current-banned-ips?jail=nonexistent")
        
        assert response.status_code == 400
        assert "El jail nonexistent no existe" in response.json()["detail"]

    @pytest.mark.asyncio
    @patch('controllers.logs.jail_exists')
    @patch('controllers.logs.get_currently_banned_ips')
    async def test_get_current_banned_ips_service_error(self, mock_get_banned, mock_jail_exists):
        """Test cuando el servicio fail2ban falla"""
        mock_jail_exists.return_value = True
        mock_get_banned.side_effect = Exception("Service unavailable")
        
        from fastapi.testclient import TestClient
        from main import app
        
        client = TestClient(app)
        response = client.get("/fail2ban/current-banned-ips?jail=sshd")
        
        assert response.status_code == 400
        assert "Error al obtener IPs baneadas" in response.json()["detail"]


class TestFilteredLogsEndpoint:
    """Tests para el endpoint /fail2ban/logs"""

    @pytest.fixture
    def mock_settings(self):
        """Mock de configuración"""
        with patch('controllers.logs.settings') as mock:
            mock.LOKI_QUERY_URL = "http://loki:3100/api/v1/query_range"
            yield mock

    @pytest.fixture
    def sample_logs_response(self):
        """Respuesta de logs de ejemplo"""
        return {
            "data": {
                "result": [{
                    "stream": {"job": "fail2ban"},
                    "values": [
                        ["1671234567000000000", "2025-05-25 16:59:22,667 fail2ban.actions [128145]: NOTICE [sshd] Ban 192.168.1.100"],
                        ["1671234568000000000", "2025-05-25 16:59:23,667 fail2ban.actions [128145]: INFO [sshd] Found 192.168.1.101"]
                    ]
                }]
            }
        }

    @pytest.mark.asyncio
    async def test_get_filtered_logs_success(self, mock_settings, sample_logs_response):
        """Test exitoso de obtención de logs filtrados"""
        with patch('controllers.logs.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.json.return_value = sample_logs_response
            mock_client.get.return_value = mock_response
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            from fastapi.testclient import TestClient
            from main import app
            
            client = TestClient(app)
            response = client.get("/fail2ban/logs?page=0&size=10")
            
            assert response.status_code == 200
            data = response.json()
            assert "values" in data
            assert "totalCount" in data
            assert len(data["values"]) == 2

    @pytest.mark.asyncio
    async def test_get_filtered_logs_with_filters(self, mock_settings, sample_logs_response):
        """Test de logs con filtros aplicados"""
        with patch('controllers.logs.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.json.return_value = sample_logs_response
            mock_client.get.return_value = mock_response
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            from fastapi.testclient import TestClient
            from main import app
            
            client = TestClient(app)
            response = client.get("/fail2ban/logs?service=fail2ban&level=NOTICE&filter_text=Ban")
            
            assert response.status_code == 200
            # Verificar que se llamó con los filtros correctos
            mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_filtered_logs_loki_error(self, mock_settings):
        """Test cuando Loki devuelve error"""
        with patch('controllers.logs.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.RequestError("Connection failed")
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            from fastapi.testclient import TestClient
            from main import app
            
            client = TestClient(app)
            response = client.get("/fail2ban/logs")
            
            assert response.status_code == 503
            assert "Error al contactar Loki" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_get_filtered_logs_pagination(self, mock_settings):
        """Test de paginación en logs filtrados"""
        # Crear respuesta con más logs para testear paginación
        large_response = {
            "data": {
                "result": [{
                    "stream": {"job": "fail2ban"},
                    "values": [[f"167123456{i}000000000", f"Log entry {i}"] for i in range(25)]
                }]
            }
        }
        
        with patch('controllers.logs.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.json.return_value = large_response
            mock_client.get.return_value = mock_response
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            from fastapi.testclient import TestClient
            from main import app
            
            client = TestClient(app)
            response = client.get("/fail2ban/logs?page=0&size=10")
            
            assert response.status_code == 200
            data = response.json()
            assert data["totalCount"] == 25
            assert len(data["values"]) == 10
            assert data["hasNextPage"] is True


class TestStatsEndpoint:
    """Tests para el endpoint /fail2ban/stats"""

    @pytest.fixture
    def mock_settings(self):
        """Mock de configuración"""
        with patch('controllers.logs.settings') as mock:
            mock.LOKI_QUERY_URL = "http://loki:3100/api/v1/query_range"
            yield mock

    @pytest.fixture
    def sample_stats_responses(self):
        """Respuestas de ejemplo para estadísticas"""
        return [
            {"data": {"resultType": "matrix", "result": [{"values": [["1671234567", "100"]]}]}},  # logs actuales
            {"data": {"resultType": "matrix", "result": [{"values": [["1671234567", "80"]]}]}},   # logs anteriores
            {"data": {"resultType": "matrix", "result": [{"values": [["1671234567", "95"]]}]}},   # logs con match
            {"data": {"resultType": "matrix", "result": [{"values": [["1671234567", "5"]]}]}},    # eventos ban
            {"data": {"resultType": "matrix", "result": [{"values": [["1671234567", "2"]]}]}}     # warnings/errors
        ]

    @pytest.mark.asyncio
    async def test_get_stats_success(self, mock_settings, sample_stats_responses):
        """Test exitoso de obtención de estadísticas"""
        with patch('controllers.logs.query_loki_with_retry') as mock_query:
            mock_query.side_effect = sample_stats_responses
            
            from fastapi.testclient import TestClient
            from main import app
            
            client = TestClient(app)
            response = client.get("/fail2ban/stats")
            
            assert response.status_code == 200
            data = response.json()
            assert "logs_difference" in data
            assert "parse_rate" in data
            assert "ban_events" in data
            assert "warn_error_logs" in data
            
            # Verificar cálculos
            assert data["logs_difference"] == 20.0  # 100 - 80
            assert data["parse_rate"] == 95.0  # (95/100) * 100
            assert data["ban_events"] == 5.0
            assert data["warn_error_logs"] == 2.0

    @pytest.mark.asyncio
    async def test_get_stats_empty_results(self, mock_settings):
        """Test cuando no hay resultados en las consultas"""
        empty_responses = [{"data": {"resultType": "matrix", "result": []}}] * 5
        
        with patch('controllers.logs.query_loki_with_retry') as mock_query:
            mock_query.side_effect = empty_responses
            
            from fastapi.testclient import TestClient
            from main import app
            
            client = TestClient(app)
            response = client.get("/fail2ban/stats")
            
            assert response.status_code == 200
            data = response.json()
            assert data["logs_difference"] == 0.0
            assert data["parse_rate"] == 0.0

    @pytest.mark.asyncio
    async def test_get_stats_query_error(self, mock_settings):
        """Test cuando hay error en las consultas"""
        with patch('controllers.logs.query_loki_with_retry') as mock_query:
            mock_query.side_effect = Exception("Loki connection failed")
            
            from fastapi.testclient import TestClient
            from main import app
            
            client = TestClient(app)
            response = client.get("/fail2ban/stats")
            
            assert response.status_code == 200
            data = response.json()
            assert "error" in data
            assert "Loki connection failed" in data["error"]


class TestHealthEndpoint:
    """Tests para el endpoint /health"""

    def test_health_endpoint(self):
        """Test del endpoint de salud"""
        from fastapi.testclient import TestClient
        from main import app
        
        client = TestClient(app)
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "funcionando" in data["message"]


class TestParameterValidation:
    """Tests para validación de parámetros en endpoints"""

    def test_banned_ips_invalid_parameters(self):
        """Test de parámetros inválidos en banned-ips"""
        from fastapi.testclient import TestClient
        from main import app
        
        client = TestClient(app)
        
        # Página negativa
        response = client.get("/fail2ban/banned-ips?page=-1")
        assert response.status_code == 422
        
        # Size fuera de rango
        response = client.get("/fail2ban/banned-ips?size=200")
        assert response.status_code == 422
        
        # Hours fuera de rango
        response = client.get("/fail2ban/banned-ips?hours=200")
        assert response.status_code == 422

    def test_logs_invalid_parameters(self):
        """Test de parámetros inválidos en logs"""
        from fastapi.testclient import TestClient
        from main import app
        
        client = TestClient(app)
        
        # Página negativa
        response = client.get("/fail2ban/logs?page=-1")
        assert response.status_code == 422
        
        # Size fuera de rango
        response = client.get("/fail2ban/logs?size=0")
        assert response.status_code == 422


@pytest.mark.parametrize("page,size,expected_start,expected_end", [
    (0, 10, 0, 10),
    (1, 10, 10, 20),
    (2, 5, 10, 15),
])
class TestPaginationLogic:
    """Tests parametrizados para lógica de paginación"""
    
    def test_pagination_calculation(self, page, size, expected_start, expected_end):
        """Test de cálculos de paginación"""
        start_idx = page * size
        end_idx = start_idx + size
        
        assert start_idx == expected_start
        assert end_idx == expected_end


class TestLogProcessing:
    """Tests para procesamiento de logs"""
    
    @pytest.mark.parametrize("log_line,expected_ip,expected_event", [
        ("2025-05-25 16:59:22,667 fail2ban.actions [128145]: NOTICE [sshd] Ban 192.168.1.100", "192.168.1.100", "Ban"),
        ("2025-05-25 16:59:22,667 fail2ban.actions [128145]: INFO [sshd] Found 10.0.0.50", "10.0.0.50", "Found"),
        ("2025-05-25 16:59:22,667 fail2ban.actions [128145]: NOTICE [sshd] Unban 172.16.0.1", "172.16.0.1", "Unban"),
    ])
    def test_log_pattern_extraction(self, log_line, expected_ip, expected_event):
        """Test de extracción de patrones de logs"""
        import re
        
        # Test de IP
        ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", log_line)
        assert ip_match is not None
        assert ip_match.group(0) == expected_ip
        
        # Test de evento
        event_match = re.search(r"\] (Found|Processing|Total|Ban|Unban|Started|Stopped|Banned|Unbanned)", log_line)
        assert event_match is not None
        assert event_match.group(1) == expected_event