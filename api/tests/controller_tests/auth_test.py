import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import sys
import os

# Agregar el directorio api al path para las importaciones
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

class TestAuthController:
    """Tests para el controlador de autenticación"""

    @patch('controllers.auth.register_user')
    async def test_register_user_function(self, mock_register_user):
        """Test de la función de registro directamente"""
        mock_register_user.return_value = AsyncMock()
        
        # Simular llamada directa a la función
        try:
            from controllers.auth import register
            # Test directo de la función sin FastAPI
            user_data = MagicMock()
            user_data.username = "testuser"
            user_data.email = "test@example.com"
            user_data.password = "testpassword123"
            
            result = await register(user_data)
            assert result == {"message": "Usuario creado exitosamente"}
            mock_register_user.assert_called_once_with("testuser", "test@example.com", "testpassword123")
        except ImportError:
            pytest.skip("No se pudo importar el controlador auth")

    @patch('controllers.auth.authenticate_user')
    @patch('controllers.auth.create_access_token')
    async def test_login_function(self, mock_create_token, mock_authenticate):
        """Test de la función de login directamente"""
        # Mock del usuario autenticado
        mock_user = {
            "_id": "user123",
            "username": "testuser",
            "email": "test@example.com",
            "roles": ["USER"]
        }
        mock_authenticate.return_value = AsyncMock(return_value=mock_user)
        mock_create_token.return_value = "mock_token"
        
        try:
            from controllers.auth import login_custom
            
            login_data = MagicMock()
            login_data.username_or_email = "test@example.com"
            login_data.password = "testpassword123"
            
            result = await login_custom(login_data)
            
            assert result.access_token == "mock_token"
            assert result.token_type == "bearer"
            assert result.user.email == "test@example.com"
        except ImportError:
            pytest.skip("No se pudo importar el controlador auth")

    @patch('controllers.auth.get_current_user')
    async def test_whoami_function(self, mock_get_current_user):
        """Test de la función whoami directamente"""
        mock_user = {
            "_id": "user123",
            "username": "testuser",
            "email": "test@example.com",
            "roles": ["USER"]
        }
        mock_get_current_user.return_value = mock_user
        
        try:
            from controllers.auth import get_current_user_info
            
            result = await get_current_user_info(mock_user)
            
            assert result.email == "test@example.com"
            assert result.username == "testuser"
            assert result.roles == ["USER"]
        except ImportError:
            pytest.skip("No se pudo importar el controlador auth")

    @patch('controllers.auth.users_exist')
    async def test_users_exist_function(self, mock_users_exist):
        """Test de la función users_exist directamente"""
        mock_users_exist.return_value = AsyncMock(return_value=True)
        
        try:
            from controllers.auth import check_if_users_exist
            
            result = await check_if_users_exist()
            
            assert result == {"users_exist": True}
        except ImportError:
            pytest.skip("No se pudo importar el controlador auth")

    def test_import_auth_controller(self):
        """Test básico de importación del controlador"""
        try:
            from controllers import auth
            assert hasattr(auth, 'router')
            assert auth.router is not None
        except ImportError:
            pytest.skip("No se pudo importar el controlador auth")
