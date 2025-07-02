import pytest
import os
from unittest.mock import patch, MagicMock
import httpx
import asyncio

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

@pytest.fixture
async def admin_token():
    """Fixture que obtiene un token de admin real para los tests"""
    # Credenciales del admin
    admin_credentials = {
        "username": "admin",
        "password": "password"
    }
    
    try:
        # Intentar obtener token real de la API
        async with httpx.AsyncClient() as client:
            # Asumiendo que tu API corre en localhost:8000
            response = await client.post(
                "http://localhost:8000/auth/login",
                json=admin_credentials,
                timeout=5.0
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("access_token")
    except Exception as e:
        print(f"Error obteniendo token real: {e}")
        # Si falla, usar un token mock
        pass
    
    # Fallback: crear un token mock que funcione con tus tests
    # Asegúrate de que tenga la estructura correcta para tu aplicación
    import jwt
    payload = {
        "sub": "admin",
        "exp": 9999999999,  # Token que no expire
        "roles": ["ADMIN"]
    }
    try:
        # Intentar usar la misma clave secreta que tu aplicación
        secret_key = os.getenv('SECRET_KEY', 'test_secret_key_for_jwt_testing')
        token = jwt.encode(payload, secret_key, algorithm="HS256")
        return token
    except:
        # Fallback final
        return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OSwicm9sZXMiOlsiQURNSU4iXX0.mock_signature"

@pytest.fixture
async def auth_headers(admin_token):
    """Headers de autorización con token de admin"""
    token = await admin_token
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def mock_authenticated_user():
    """Mock de usuario autenticado para bypass de autenticación en tests"""
    return {
        "_id": "admin_test_id",
        "username": "admin",
        "email": "admin@example.com",
        "roles": ["ADMIN"],
        "hashed_password": "$2b$12$mock_admin_hash"
    }

@pytest.fixture
def bypass_auth():
    """Fixture para hacer bypass de autenticación en tests"""
    def _bypass_auth():
        return {
            "_id": "admin_test_id",
            "username": "admin",
            "roles": ["ADMIN"]
        }
    return _bypass_auth

@pytest.fixture
async def ensure_admin_user():
    """Fixture que asegura que existe un usuario admin para los tests"""
    admin_data = {
        "username": "admin",
        "email": "admin@test.com", 
        "password": "password"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            # Intentar registrar el usuario admin
            response = await client.post(
                "http://localhost:8000/auth/register",
                json=admin_data,
                timeout=5.0
            )
            
            if response.status_code in [200, 201, 409]:  # 409 si ya existe
                print("✅ Usuario admin disponible para tests")
                return True
            else:
                print(f"⚠️ No se pudo crear usuario admin: {response.status_code}")
                return False
                
    except Exception as e:
        print(f"⚠️ Error configurando usuario admin: {e}")
        return False

@pytest.fixture
def sync_admin_token():
    """Version síncrona del token de admin para tests que no son async"""
    import jwt
    payload = {
        "sub": "admin",
        "exp": 9999999999,  # Token que no expire
        "roles": ["ADMIN"]
    }
    try:
        secret_key = os.getenv('SECRET_KEY', 'test_secret_key_for_jwt_testing')
        token = jwt.encode(payload, secret_key, algorithm="HS256")
        return token
    except:
        return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OSwicm9sZXMiOlsiQURNSU4iXX0.mock_signature"

@pytest.fixture
def sync_auth_headers(sync_admin_token):
    """Headers de autorización síncronos para tests regulares"""
    return {"Authorization": f"Bearer {sync_admin_token}"}