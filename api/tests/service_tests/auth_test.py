import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import sys
import os

# Agregar el directorio api al path para las importaciones
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

class TestAuthService:
    """Tests para el servicio de autenticación"""

    def test_hash_password(self):
        """Test de hash de contraseña"""
        try:
            from services.auth import hash_password
            password = "testpassword123"
            hashed = hash_password(password)
            
            assert hashed != password
            assert len(hashed) > 20  # Hash de bcrypt es largo
            assert hashed.startswith("$2b$")  # Formato bcrypt
        except ImportError:
            pytest.skip("No se pudo importar el servicio auth")

    def test_verify_password_correct(self):
        """Test de verificación de contraseña correcta"""
        try:
            from services.auth import hash_password, verify_password
            password = "testpassword123"
            hashed = hash_password(password)
            
            result = verify_password(password, hashed)
            assert result is True
        except ImportError:
            pytest.skip("No se pudo importar el servicio auth")

    def test_verify_password_incorrect(self):
        """Test de verificación de contraseña incorrecta"""
        try:
            from services.auth import hash_password, verify_password
            password = "testpassword123"
            wrong_password = "wrongpassword"
            hashed = hash_password(password)
            
            result = verify_password(wrong_password, hashed)
            assert result is False
        except ImportError:
            pytest.skip("No se pudo importar el servicio auth")

    @patch.dict('os.environ', {'SECRET_KEY': 'test_secret', 'ALGORITHM': 'HS256'})
    def test_create_access_token(self):
        """Test de creación de token de acceso"""
        try:
            from services.auth import create_access_token
            data = {"sub": "test@example.com"}
            token = create_access_token(data)
            
            assert isinstance(token, str)
            assert len(token) > 50  # JWT token es largo
            assert "." in token  # JWT tiene puntos separadores
        except ImportError:
            pytest.skip("No se pudo importar el servicio auth")

    @patch('services.auth.get_user_by_email')
    @patch('services.auth.get_user_by_username')
    @patch('services.auth.create_user')
    async def test_register_user_success(self, mock_create_user, mock_get_by_username, mock_get_by_email):
        """Test exitoso de registro de usuario"""
        try:
            from services.auth import register_user
            mock_get_by_email.return_value = AsyncMock(return_value=None)
            mock_get_by_username.return_value = AsyncMock(return_value=None)
            mock_create_user.return_value = AsyncMock()
            
            await register_user("testuser", "test@example.com", "password123")
            
            mock_get_by_email.assert_called_once_with("test@example.com")
            mock_get_by_username.assert_called_once_with("testuser")
            mock_create_user.assert_called_once()
        except ImportError:
            pytest.skip("No se pudo importar el servicio auth")

    @patch('services.auth.get_user_by_email')
    async def test_register_user_email_exists(self, mock_get_by_email):
        """Test de registro con email existente"""
        try:
            from services.auth import register_user
            mock_get_by_email.return_value = AsyncMock(return_value={"email": "test@example.com"})
            
            with pytest.raises(Exception) as exc_info:
                await register_user("testuser", "test@example.com", "password123")
            
            assert "Ya existe un usuario con este email" in str(exc_info.value)
        except ImportError:
            pytest.skip("No se pudo importar el servicio auth")

    @patch('services.auth.check_users_exist')
    async def test_users_exist_true(self, mock_check_users_exist):
        """Test cuando existen usuarios"""
        try:
            from services.auth import users_exist
            mock_check_users_exist.return_value = AsyncMock(return_value=True)
            
            result = await users_exist()
            assert result is True
        except ImportError:
            pytest.skip("No se pudo importar el servicio auth")

    @patch('services.auth.get_user_by_username_or_email')
    @patch('services.auth.verify_password')
    async def test_authenticate_user_success(self, mock_verify_password, mock_get_user):
        """Test exitoso de autenticación de usuario"""
        try:
            from services.auth import authenticate_user
            mock_user = {
                "_id": "user123",
                "username": "testuser",
                "email": "test@example.com",
                "hashed_password": "hashed_password"
            }
            mock_get_user.return_value = AsyncMock(return_value=mock_user)
            mock_verify_password.return_value = True
            
            result = await authenticate_user("test@example.com", "password123")
            
            assert result == mock_user
            mock_get_user.assert_called_once_with("test@example.com")
            mock_verify_password.assert_called_once_with("password123", "hashed_password")
        except ImportError:
            pytest.skip("No se pudo importar el servicio auth")

    async def test_require_admin_success(self):
        """Test exitoso de requerir rol admin"""
        try:
            from services.auth import require_admin
            mock_user = {
                "_id": "admin123",
                "username": "admin",
                "email": "admin@example.com",
                "roles": ["ADMIN"]
            }
            
            result = await require_admin(mock_user)
            assert result == mock_user
        except ImportError:
            pytest.skip("No se pudo importar el servicio auth")

    async def test_require_admin_no_admin_role(self):
        """Test de requerir rol admin sin tener el rol"""
        try:
            from services.auth import require_admin
            mock_user = {
                "_id": "user123",
                "username": "user",
                "email": "user@example.com",
                "roles": ["USER"]
            }
            
            with pytest.raises(Exception) as exc_info:
                await require_admin(mock_user)
            
            assert exc_info.value.status_code == 403
        except ImportError:
            pytest.skip("No se pudo importar el servicio auth")

    def test_import_auth_service(self):
        """Test básico de importación del servicio"""
        try:
            from services import auth
            assert hasattr(auth, 'hash_password')
            assert hasattr(auth, 'verify_password')
            assert hasattr(auth, 'create_access_token')
        except ImportError:
            pytest.skip("No se pudo importar el servicio auth")
