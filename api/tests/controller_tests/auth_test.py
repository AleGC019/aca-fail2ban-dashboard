"""
Tests unitarios para controllers/auth.py

Este módulo contiene tests completos para todas las funciones y endpoints
del controller de autenticación.
"""

import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from fastapi import FastAPI
import sys
import os

# Agregar el directorio api al path para las importaciones
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from controllers.auth import router
from services.auth import get_current_user


class TestAuthController:
    """Tests para el controlador de autenticación"""

    @pytest.fixture
    def client(self):
        """Fixture para cliente de test"""
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)
    
    @pytest.fixture
    def authenticated_client(self):
        """Fixture para cliente autenticado"""
        app = FastAPI()
        app.include_router(router)
        
        # Usuario mock para autenticación
        mock_user = {
            "_id": "user123",
            "username": "testuser",
            "email": "test@example.com",
            "roles": ["USER"]
        }
        
        # Override de dependencias
        app.dependency_overrides[get_current_user] = lambda: mock_user
        
        return TestClient(app)

    @pytest.fixture
    def user_data(self):
        """Fixture para datos de usuario"""
        return {
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpassword123"
        }

    @patch('controllers.auth.register_user')
    def test_register_user_success(self, mock_register_user, client, user_data):
        """Test exitoso de registro de usuario"""
        mock_register_user.return_value = AsyncMock()
        
        response = client.post("/register", json=user_data)
        
        assert response.status_code == 201
        data = response.json()
        assert "mensaje" in data or "message" in data

    @patch('controllers.auth.register_user')
    def test_register_user_duplicate(self, mock_register_user, client, user_data):
        """Test de registro con usuario duplicado"""
        mock_register_user.side_effect = Exception("Usuario ya existe")
        
        response = client.post("/register", json=user_data)
        
        assert response.status_code == 400

    @patch('controllers.auth.authenticate_user')
    @patch('controllers.auth.create_access_token')
    def test_login_success(self, mock_create_token, mock_authenticate, client):
        """Test exitoso de login"""
        # Mock del usuario autenticado con valores simples
        mock_user = {
            "_id": "user123",
            "username": "testuser",
            "email": "test@example.com",
            "roles": ["USER"]
        }
        # Cambiar AsyncMock a return_value directo
        mock_authenticate.return_value = mock_user
        mock_create_token.return_value = "mock_token_123"
        
        login_data = {
            "username_or_email": "test@example.com",
            "password": "testpassword123"
        }
        
        response = client.post("/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["access_token"] == "mock_token_123"

    @patch('controllers.auth.authenticate_user')
    def test_login_invalid_credentials(self, mock_authenticate, client):
        """Test de login con credenciales inválidas"""
        mock_authenticate.return_value = None
        
        login_data = {
            "username_or_email": "wrong@example.com",
            "password": "wrongpassword"
        }
        
        response = client.post("/login", json=login_data)
        
        assert response.status_code == 401
        assert "credenciales" in response.json()["detail"].lower()

    def test_whoami_success(self, authenticated_client):
        """Test exitoso de endpoint whoami"""
        
        response = authenticated_client.get("/whoami")
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"

    def test_whoami_unauthorized(self, client):
        """Test de whoami sin autenticación"""
        
        response = client.get("/whoami")
        
        assert response.status_code == 403  # FastAPI devuelve 403 por defecto, no 401

    @patch('controllers.auth.users_exist')
    def test_users_exist_true(self, mock_users_exist, client):
        """Test cuando existen usuarios"""
        mock_users_exist.return_value = True
        
        response = client.get("/users-exist")
        
        assert response.status_code == 200
        data = response.json()
        assert data["users_exist"] is True

    @patch('controllers.auth.users_exist')
    def test_users_exist_false(self, mock_users_exist, client):
        """Test cuando no existen usuarios"""
        mock_users_exist.return_value = False
        
        response = client.get("/users-exist")
        
        assert response.status_code == 200
        data = response.json()
        assert data["users_exist"] is False

    def test_import_auth_controller(self):
        """Test básico de importación del controlador"""
        try:
            from controllers.auth import router
            assert router is not None
        except ImportError as e:
            pytest.fail(f"No se pudo importar el controlador auth: {e}")
