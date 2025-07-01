import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from fastapi import HTTPException
import sys
import os

# Agregar el directorio api al path para las importaciones
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from controllers.users import router
from fastapi import FastAPI

# Crear una app de prueba
app = FastAPI()
app.include_router(router)
client = TestClient(app)

class TestUsersController:
    """Tests para el controlador de usuarios"""

    @patch('controllers.users.get_user_by_id')
    @patch('controllers.users.get_current_user')
    def test_get_user_by_id_success(self, mock_get_current_user, mock_get_user_by_id):
        """Test exitoso de obtener usuario por ID"""
        mock_current_user = {"_id": "current_user_id", "roles": ["USER"]}
        mock_user = {
            "_id": "user123",
            "username": "testuser",
            "email": "test@example.com",
            "roles": ["USER"]
        }
        
        mock_get_current_user.return_value = mock_current_user
        mock_get_user_by_id.return_value = AsyncMock(return_value=mock_user)
        
        response = client.get("/user123", headers={"Authorization": "Bearer mock_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["id"] == "user123"
        assert response_data["username"] == "testuser"
        assert response_data["email"] == "test@example.com"

    @patch('controllers.users.get_user_by_id')
    @patch('controllers.users.get_current_user')
    def test_get_user_by_id_not_found(self, mock_get_current_user, mock_get_user_by_id):
        """Test de obtener usuario que no existe"""
        mock_current_user = {"_id": "current_user_id", "roles": ["USER"]}
        
        mock_get_current_user.return_value = mock_current_user
        mock_get_user_by_id.return_value = AsyncMock(return_value=None)
        
        response = client.get("/nonexistent", headers={"Authorization": "Bearer mock_token"})
        
        assert response.status_code == 404
        assert "Usuario no encontrado" in response.json()["detail"]

    @patch('controllers.users.get_users_paginated')
    @patch('controllers.users.get_current_user')
    def test_get_users_paginated_success(self, mock_get_current_user, mock_get_users_paginated):
        """Test exitoso de obtener usuarios paginados"""
        mock_current_user = {"_id": "current_user_id", "roles": ["USER"]}
        mock_paginated_result = {
            "users": [
                {"_id": "user1", "username": "user1", "email": "user1@example.com", "roles": ["USER"]},
                {"_id": "user2", "username": "user2", "email": "user2@example.com", "roles": ["ADMIN"]}
            ],
            "totalCount": 2,
            "totalPages": 1,
            "currentPage": 1,
            "pageSize": 10,
            "hasNextPage": False,
            "hasPreviousPage": False
        }
        
        mock_get_current_user.return_value = mock_current_user
        mock_get_users_paginated.return_value = AsyncMock(return_value=mock_paginated_result)
        
        response = client.get("/?page=1&page_size=10", headers={"Authorization": "Bearer mock_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["totalCount"] == 2
        assert len(response_data["users"]) == 2
        assert response_data["users"][0]["username"] == "user1"

    @patch('controllers.users.get_user_by_id')
    @patch('controllers.users.delete_user')
    @patch('controllers.users.require_admin')
    def test_delete_user_success(self, mock_require_admin, mock_delete_user, mock_get_user_by_id):
        """Test exitoso de eliminar usuario (admin)"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        mock_user_to_delete = {"_id": "user_to_delete", "username": "userdelete", "email": "delete@example.com"}
        
        mock_require_admin.return_value = mock_admin_user
        mock_get_user_by_id.return_value = AsyncMock(return_value=mock_user_to_delete)
        mock_delete_user.return_value = AsyncMock(return_value=True)
        
        response = client.delete("/user_to_delete", headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 200
        assert "Usuario eliminado exitosamente" in response.json()["message"]

    @patch('controllers.users.get_user_by_id')
    @patch('controllers.users.require_admin')
    def test_delete_user_not_found(self, mock_require_admin, mock_get_user_by_id):
        """Test de eliminar usuario que no existe"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        
        mock_require_admin.return_value = mock_admin_user
        mock_get_user_by_id.return_value = AsyncMock(return_value=None)
        
        response = client.delete("/nonexistent", headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 404
        assert "Usuario no encontrado" in response.json()["detail"]

    @patch('controllers.users.get_user_by_id')
    @patch('controllers.users.require_admin')
    def test_delete_self_forbidden(self, mock_require_admin, mock_get_user_by_id):
        """Test de admin intentando eliminarse a sí mismo"""
        admin_id = "admin_id"
        mock_admin_user = {"_id": admin_id, "roles": ["ADMIN"]}
        mock_user_to_delete = {"_id": admin_id, "username": "admin", "email": "admin@example.com"}
        
        mock_require_admin.return_value = mock_admin_user
        mock_get_user_by_id.return_value = AsyncMock(return_value=mock_user_to_delete)
        
        response = client.delete(f"/{admin_id}", headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 400
        assert "No puedes eliminar tu propia cuenta" in response.json()["detail"]

    @patch('controllers.users.get_user_by_id')
    @patch('controllers.users.add_role_to_user')
    @patch('controllers.users.require_admin')
    def test_assign_admin_role_success(self, mock_require_admin, mock_add_role, mock_get_user_by_id):
        """Test exitoso de asignar rol admin"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        mock_user = {"_id": "user123", "username": "testuser", "roles": ["USER"]}
        
        mock_require_admin.return_value = mock_admin_user
        mock_get_user_by_id.return_value = AsyncMock(return_value=mock_user)
        mock_add_role.return_value = AsyncMock(return_value=True)
        
        response = client.post("/user123/assign-admin", headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 200
        assert "Rol de ADMIN asignado exitosamente" in response.json()["message"]

    @patch('controllers.users.get_user_by_id')
    @patch('controllers.users.require_admin')
    def test_assign_admin_role_already_admin(self, mock_require_admin, mock_get_user_by_id):
        """Test de asignar rol admin a usuario que ya es admin"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        mock_user = {"_id": "user123", "username": "testuser", "roles": ["ADMIN"]}
        
        mock_require_admin.return_value = mock_admin_user
        mock_get_user_by_id.return_value = AsyncMock(return_value=mock_user)
        
        response = client.post("/user123/assign-admin", headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 400
        assert "El usuario ya tiene el rol de ADMIN" in response.json()["detail"]

    @patch('controllers.users.get_user_by_id')
    @patch('controllers.users.update_user')
    @patch('controllers.users.get_current_user')
    def test_update_user_self_success(self, mock_get_current_user, mock_update_user, mock_get_user_by_id):
        """Test exitoso de actualizar propio usuario"""
        user_id = "user123"
        mock_current_user = {"_id": user_id, "roles": ["USER"]}
        mock_user = {"_id": user_id, "username": "oldname", "email": "old@example.com", "roles": ["USER"]}
        mock_updated_user = {"_id": user_id, "username": "newname", "email": "new@example.com", "roles": ["USER"]}
        
        mock_get_current_user.return_value = mock_current_user
        mock_get_user_by_id.side_effect = [
            AsyncMock(return_value=mock_user),  # Primera llamada para verificar existencia
            AsyncMock(return_value=mock_updated_user)  # Segunda llamada para obtener usuario actualizado
        ]
        mock_update_user.return_value = AsyncMock(return_value=True)
        
        update_data = {"username": "newname", "email": "new@example.com"}
        response = client.put(f"/{user_id}", json=update_data, headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 200
        assert response.json()["username"] == "newname"
        assert response.json()["email"] == "new@example.com"

    @patch('controllers.users.get_user_by_id')
    @patch('controllers.users.get_current_user')
    def test_update_user_forbidden(self, mock_get_current_user, mock_get_user_by_id):
        """Test de actualizar usuario sin permisos"""
        user_id = "user123"
        other_user_id = "other_user"
        mock_current_user = {"_id": other_user_id, "roles": ["USER"]}
        mock_user = {"_id": user_id, "username": "testuser", "email": "test@example.com", "roles": ["USER"]}
        
        mock_get_current_user.return_value = mock_current_user
        mock_get_user_by_id.return_value = AsyncMock(return_value=mock_user)
        
        update_data = {"username": "newname"}
        response = client.put(f"/{user_id}", json=update_data, headers={"Authorization": "Bearer user_token"})
        
        assert response.status_code == 403
        assert "No tienes permisos para actualizar este usuario" in response.json()["detail"]

    @patch('controllers.users.get_users_paginated')
    @patch('controllers.users.require_admin')
    def test_get_user_stats_success(self, mock_require_admin, mock_get_users_paginated):
        """Test exitoso de obtener estadísticas de usuarios (admin)"""
        mock_admin_user = {"_id": "admin_id", "roles": ["ADMIN"]}
        mock_paginated_result = {
            "users": [
                {"_id": "user1", "roles": ["USER"]},
                {"_id": "user2", "roles": ["ADMIN"]},
                {"_id": "user3", "roles": ["USER"]}
            ],
            "totalCount": 3
        }
        
        mock_require_admin.return_value = mock_admin_user
        mock_get_users_paginated.return_value = AsyncMock(return_value=mock_paginated_result)
        
        response = client.get("/admin/stats", headers={"Authorization": "Bearer admin_token"})
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["totalUsers"] == 3
        assert response_data["adminUsers"] == 1
        assert response_data["regularUsers"] == 2
