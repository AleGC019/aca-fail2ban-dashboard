import pytest
import os
from unittest.mock import patch, MagicMock

@pytest.fixture(autouse=True)
def setup_test_environment():
    """Setup environment variables for all tests"""
    with patch.dict(os.environ, {
        'LOKI_QUERY_URL': 'http://test-loki:3100/api/v1/query_range',
        'LOKI_WS_URL': 'ws://test-loki:3100/loki/api/v1/tail',
        'LOKI_PUSH_URL': 'http://test-loki:3100/loki/api/v1/push',
        'SECRET_KEY': 'test_secret_key_for_jwt_testing',
        'ALGORITHM': 'HS256',
        'MONGODB_URI': 'mongodb://test:test@localhost:27017/test_db'
    }):
        yield

@pytest.fixture
def mock_user():
    """Fixture para usuario de prueba"""
    return {
        "_id": "test_user_id",
        "username": "testuser",
        "email": "test@example.com",
        "roles": ["USER"],
        "hashed_password": "$2b$12$test_hashed_password"
    }

@pytest.fixture
def mock_admin_user():
    """Fixture para usuario administrador de prueba"""
    return {
        "_id": "test_admin_id", 
        "username": "admin",
        "email": "admin@example.com",
        "roles": ["ADMIN"],
        "hashed_password": "$2b$12$test_admin_hashed_password"
    }

@pytest.fixture
def mock_jwt_token():
    """Fixture para token JWT de prueba"""
    return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test_payload.test_signature"

@pytest.fixture
def mock_banned_ips():
    """Fixture para lista de IPs baneadas de prueba"""
    return ["192.168.1.100", "10.0.0.50", "172.16.0.25"]

@pytest.fixture
def mock_loki_response():
    """Fixture para respuesta de Loki de prueba"""
    return {
        "data": {
            "result": [
                {
                    "stream": {"job": "fail2ban", "instance": "localhost"},
                    "values": [
                        ["1640995200000000000", "2022-01-01 00:00:00 fail2ban.filter[1234]: Found 192.168.1.100"],
                        ["1640995260000000000", "2022-01-01 00:01:00 fail2ban.actions[1234]: Ban 192.168.1.100"]
                    ]
                }
            ]
        }
    }

@pytest.fixture
def mock_fail2ban_client():
    """Fixture para mock del cliente fail2ban"""
    mock = MagicMock()
    mock.returncode = 0
    mock.stdout = "Command executed successfully"
    mock.stderr = ""
    return mock

@pytest.fixture
def test_app():
    """Fixture para aplicación de prueba (mock)"""
    # Mock simple para evitar problemas de compatibilidad
    return MagicMock()

@pytest.fixture
def settings():
    """Fixture de configuración para tests"""
    class MockSettings:
        SECRET_KEY = "test_secret_key"
        ALGORITHM = "HS256"
        ACCESS_TOKEN_EXPIRE_MINUTES = 30
    
    return MockSettings()