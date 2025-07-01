import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
import httpx
import sys
import os

# Agregar el directorio api al path para las importaciones
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from services.loki import query_loki

class TestLokiService:
    """Tests para el servicio de Loki"""

    @patch('services.loki.httpx.AsyncClient')
    async def test_query_loki_success(self, mock_async_client):
        """Test exitoso de consulta a Loki"""
        # Mock de la respuesta de Loki
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "result": [
                    {
                        "stream": {"job": "fail2ban", "instance": "localhost"},
                        "values": [
                            ["1640995200000000000", "2022-01-01 00:00:00 fail2ban.filter[1234]: INFO Found 192.168.1.100"],
                            ["1640995260000000000", "2022-01-01 00:01:00 fail2ban.actions[1234]: NOTICE Ban 192.168.1.100"]
                        ]
                    }
                ]
            }
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        # Ejecutar la consulta
        result = await query_loki(
            start="1640995200000000000",
            end="1640995260000000000",
            limit=100
        )
        
        # Verificaciones
        assert len(result) == 2
        assert result[0].timestamp == "1640995200000000000"
        assert "Found 192.168.1.100" in result[0].line
        assert result[0].labels["job"] == "fail2ban"
        assert result[1].timestamp == "1640995260000000000"
        assert "Ban 192.168.1.100" in result[1].line

    @patch('services.loki.httpx.AsyncClient')
    async def test_query_loki_empty_response(self, mock_async_client):
        """Test de consulta a Loki con respuesta vacía"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "result": []
            }
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        result = await query_loki(
            start="1640995200000000000",
            end="1640995260000000000",
            limit=100
        )
        
        assert result == []

    @patch('services.loki.httpx.AsyncClient')
    async def test_query_loki_request_error(self, mock_async_client):
        """Test de error de solicitud a Loki"""
        mock_client_instance = MagicMock()
        mock_client_instance.get.side_effect = httpx.RequestError("Connection failed")
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        with pytest.raises(HTTPException) as exc_info:
            await query_loki(
                start="1640995200000000000",
                end="1640995260000000000",
                limit=100
            )
        
        assert exc_info.value.status_code == 503
        assert "Error al contactar Loki" in exc_info.value.detail

    @patch('services.loki.httpx.AsyncClient')
    async def test_query_loki_http_status_error(self, mock_async_client):
        """Test de error de estado HTTP de Loki"""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        
        mock_client_instance = MagicMock()
        mock_client_instance.get.side_effect = httpx.HTTPStatusError(
            "Internal Server Error",
            request=MagicMock(),
            response=mock_response
        )
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        with pytest.raises(HTTPException) as exc_info:
            await query_loki(
                start="1640995200000000000",
                end="1640995260000000000",
                limit=100
            )
        
        assert exc_info.value.status_code == 500

    @patch('services.loki.httpx.AsyncClient')
    async def test_query_loki_with_optional_params(self, mock_async_client):
        """Test de consulta a Loki con parámetros opcionales"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "result": [
                    {
                        "stream": {"job": "fail2ban"},
                        "values": [
                            ["1640995200000000000", "Test log entry"]
                        ]
                    }
                ]
            }
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        # Test con start=None, end=None
        result = await query_loki(start=None, end=None, limit=50)
        
        assert len(result) == 1
        
        # Verificar que se llamó con los parámetros correctos
        expected_params = {"query": '{job="fail2ban"}', "limit": 50}
        mock_client_instance.get.assert_called_with(
            pytest.approx(expected_params, abs=1e-6),  # Usar approx para manejo de parámetros
            params=expected_params,
            timeout=10.0
        )

    @patch('services.loki.httpx.AsyncClient')
    async def test_query_loki_malformed_response(self, mock_async_client):
        """Test de consulta a Loki con respuesta malformada"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {}  # Falta 'result'
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        result = await query_loki(
            start="1640995200000000000",
            end="1640995260000000000",
            limit=100
        )
        
        assert result == []

    @patch('services.loki.httpx.AsyncClient')
    async def test_query_loki_multiple_streams(self, mock_async_client):
        """Test de consulta a Loki con múltiples streams"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "result": [
                    {
                        "stream": {"job": "fail2ban", "instance": "server1"},
                        "values": [
                            ["1640995200000000000", "Server1 log entry"]
                        ]
                    },
                    {
                        "stream": {"job": "fail2ban", "instance": "server2"},
                        "values": [
                            ["1640995201000000000", "Server2 log entry"]
                        ]
                    }
                ]
            }
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        result = await query_loki(
            start="1640995200000000000",
            end="1640995260000000000",
            limit=100
        )
        
        assert len(result) == 2
        assert result[0].labels["instance"] == "server1"
        assert result[1].labels["instance"] == "server2"
        assert "Server1 log entry" in result[0].line
        assert "Server2 log entry" in result[1].line

    @patch('services.loki.httpx.AsyncClient')
    async def test_query_loki_stream_without_values(self, mock_async_client):
        """Test de consulta a Loki con stream sin valores"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "result": [
                    {
                        "stream": {"job": "fail2ban"},
                        "values": []  # Sin valores
                    }
                ]
            }
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        result = await query_loki(
            start="1640995200000000000",
            end="1640995260000000000",
            limit=100
        )
        
        assert result == []

    @patch('services.loki.httpx.AsyncClient')
    async def test_query_loki_timeout_error(self, mock_async_client):
        """Test de timeout en consulta a Loki"""
        mock_client_instance = MagicMock()
        mock_client_instance.get.side_effect = httpx.TimeoutException("Request timeout")
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        with pytest.raises(HTTPException) as exc_info:
            await query_loki(
                start="1640995200000000000",
                end="1640995260000000000",
                limit=100
            )
        
        assert exc_info.value.status_code == 503
        assert "Error al contactar Loki" in exc_info.value.detail

    @patch('services.loki.httpx.AsyncClient')
    async def test_query_loki_with_all_params(self, mock_async_client):
        """Test de consulta a Loki con todos los parámetros"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "result": [
                    {
                        "stream": {"job": "fail2ban", "level": "INFO"},
                        "values": [
                            ["1640995200000000000", "Complete log entry with all params"]
                        ]
                    }
                ]
            }
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        result = await query_loki(
            start="1640995200000000000",
            end="1640995260000000000",
            limit=1000
        )
        
        assert len(result) == 1
        assert result[0].timestamp == "1640995200000000000"
        assert result[0].labels["job"] == "fail2ban"
        assert result[0].labels["level"] == "INFO"
        assert "Complete log entry" in result[0].line

    @patch('services.loki.settings')
    @patch('services.loki.httpx.AsyncClient')
    async def test_query_loki_uses_settings_url(self, mock_async_client, mock_settings):
        """Test que verifica que se usa la URL de configuración"""
        mock_settings.LOKI_QUERY_URL = "http://test-loki:3100/api/v1/query_range"
        
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {"result": []}}
        mock_response.raise_for_status.return_value = None
        
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        await query_loki(start=None, end=None, limit=100)
        
        # Verificar que se llamó con la URL correcta
        mock_client_instance.get.assert_called_once()
        call_args = mock_client_instance.get.call_args
        assert call_args[0][0] == "http://test-loki:3100/api/v1/query_range"
