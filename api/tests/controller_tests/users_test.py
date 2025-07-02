import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from fastapi import FastAPI
import sys
import os

# Agregar el directorio api al path para las importaciones
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from controllers.users import router
from services.auth import require_admin, get_current_user

class TestUsersController:
    """Tests para el controlador de usuarios"""

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
    def regular_user(self):
        """Fixture para usuario regular"""
        return {
            "_id": "user123",
            "username": "testuser",
            "email": "test@example.com",
            "roles": ["USER"]
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

    @pytest.fixture
    def user_data(self):
        """Fixture para datos de usuario"""
        return {
            "_id": "user123",
            "username": "testuser",
            "email": "test@example.com",
            "roles": ["USER"]
        }

    @patch('controllers.users.get_user_by_id')
    def test_get_user_by_id_success(self, mock_get_user_by_id, client, user_data, auth_headers):
        """Test exitoso de obtener usuario por ID"""
        mock_get_user_by_id.return_value = user_data
        
        response = client.get("/user123", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "user123"
        assert data["username"] == "testuser"

    @patch('controllers.users.get_user_by_id')
    def test_get_user_by_id_not_found(self, mock_get_user_by_id, client, auth_headers):
        """Test de usuario no encontrado"""
        mock_get_user_by_id.return_value = None
        
        response = client.get("/nonexistent", headers=auth_headers)
        
        assert response.status_code == 404
        assert "usuario no encontrado" in response.json()["detail"].lower()

    @patch('controllers.users.get_users_paginated')
    def test_get_users_paginated_success(self, mock_get_users_paginated, client, user_data, auth_headers):
        """Test exitoso de obtener usuarios paginados"""
        mock_get_users_paginated.return_value = {
            "users": [user_data],
            "totalCount": 1,
            "currentPage": 1,
            "pageSize": 10,
            "totalPages": 1,
            "hasNextPage": False,
            "hasPreviousPage": False
        }
        
        response = client.get("/?page=1&page_size=10", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "users" in data
        assert len(data["users"]) == 1

    @patch('controllers.users.get_user_by_id')
    @patch('controllers.users.delete_user')
    def test_delete_user_success(self, mock_delete_user, mock_get_user_by_id, client, user_data, auth_headers):
        """Test exitoso de eliminar usuario"""
        mock_get_user_by_id.return_value = user_data
        mock_delete_user.return_value = True
        
        response = client.delete("/user123", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "eliminado" in data["message"].lower()

    @patch('controllers.users.get_user_by_id')
    def test_delete_user_not_found(self, mock_get_user_by_id, client, auth_headers):
        """Test de eliminar usuario no encontrado"""
        mock_get_user_by_id.return_value = None
        
        response = client.delete("/nonexistent", headers=auth_headers)
        
        assert response.status_code == 404
        assert "usuario no encontrado" in response.json()["detail"].lower()

    @patch('controllers.users.get_user_by_id')
    def test_delete_self_forbidden(self, mock_get_user_by_id, client, auth_headers):
        """Test de intentar eliminar a sí mismo"""
        # Mock para devolver el usuario admin cuando se busque por admin_id
        admin_user = {
            "_id": "admin_id", 
            "username": "admin",
            "email": "admin@test.com",
            "roles": ["ADMIN"]
        }
        mock_get_user_by_id.return_value = admin_user
        
        # El usuario admin intenta eliminarse a sí mismo
        response = client.delete("/admin_id", headers=auth_headers)
        
        assert response.status_code == 400
        assert "tu propia cuenta" in response.json()["detail"].lower()

    @patch('controllers.users.get_user_by_id')
    @patch('controllers.users.add_role_to_user')
    def test_assign_admin_role_success(self, mock_add_role, mock_get_user_by_id, client, user_data, auth_headers):
        """Test exitoso de asignar rol admin"""
        mock_get_user_by_id.return_value = user_data
        mock_add_role.return_value = True
        
        response = client.post("/user123/assign-admin", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "asignado exitosamente" in data["message"].lower()

    @patch('controllers.users.get_user_by_id')
    def test_assign_admin_role_already_admin(self, mock_get_user_by_id, client, auth_headers):
        """Test de asignar rol admin a usuario que ya es admin"""
        admin_user = {
            "_id": "user123",
            "username": "testuser",
            "email": "test@example.com",
            "roles": ["ADMIN"]  # Ya tiene rol admin
        }
        mock_get_user_by_id.return_value = admin_user
        
        response = client.post("/user123/assign-admin", headers=auth_headers)
        
        assert response.status_code == 400
        assert "ya tiene el rol" in response.json()["detail"].lower()

    @patch('controllers.users.get_user_by_id')
    @patch('controllers.users.update_user')
    def test_update_user_self_success(self, mock_update_user, mock_get_user_by_id, client, auth_headers):
        """Test exitoso de actualizar propio perfil"""
        admin_user = {
            "_id": "admin_id",
            "username": "admin",
            "email": "admin@test.com",
            "roles": ["ADMIN"]
        }
        
        # Mock tanto para la verificación inicial como para obtener el usuario actualizado
        mock_get_user_by_id.side_effect = [admin_user, admin_user]
        mock_update_user.return_value = True
        update_data = {"username": "newadmin"}
        
        # Admin actualiza su propio perfil
        response = client.put("/admin_id", json=update_data, headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "admin"

    @patch('controllers.users.get_user_by_id')
    def test_update_user_forbidden(self, mock_get_user_by_id, auth_headers):
        """Test de intentar actualizar otro usuario sin permisos"""
        # Crear un cliente con usuario regular (sin permisos admin)
        app = FastAPI()
        app.include_router(router)
        
        regular_user = {
            "_id": "user123",
            "username": "testuser",
            "email": "test@example.com",
            "roles": ["USER"]
        }
        
        other_user = {
            "_id": "other_user",
            "username": "otheruser",
            "email": "other@test.com",
            "roles": ["USER"]
        }
        
        def mock_get_current_user():
            return regular_user
        
        app.dependency_overrides[get_current_user] = mock_get_current_user
        mock_get_user_by_id.return_value = other_user
        
        client = TestClient(app)
        update_data = {"username": "hacker"}
        
        response = client.put("/other_user", json=update_data, headers=auth_headers)
        
        assert response.status_code == 403
        assert "no tienes permisos" in response.json()["detail"].lower()

    @patch('controllers.users.get_users_paginated')
    def test_get_user_stats_success(self, mock_get_users_paginated, client, auth_headers):
        """Test exitoso de obtener estadísticas de usuarios"""
        # Mock para simular respuesta de get_users_paginated
        mock_get_users_paginated.return_value = {
            "users": [
                {"_id": "1", "username": "admin", "roles": ["ADMIN"]},
                {"_id": "2", "username": "user1", "roles": ["USER"]},
                {"_id": "3", "username": "user2", "roles": ["USER"]},
            ],
            "totalCount": 3,
            "currentPage": 1,
            "pageSize": 1000,
            "totalPages": 1,
            "hasNextPage": False,
            "hasPreviousPage": False
        }
        
        response = client.get("/admin/stats", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "totalUsers" in data
        assert data["totalUsers"] == 3
        assert data["adminUsers"] == 1
        assert data["regularUsers"] == 2
