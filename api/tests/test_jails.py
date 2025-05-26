import pytest
from fastapi import HTTPException
from unittest.mock import patch

from controllers.jails import execute_ip_action, ban_ip_in_jail, unban_ip_in_jail, get_jails
from data.models import IPActionRequest, ActionResponse


class TestJailsController:
    """Test suite para el controller de jails."""

    def test_jails_controller_import(self):
        """Test que el controller de jails se puede importar sin errores."""
        from controllers import jails
        assert jails.router is not None

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_execute_ip_action_ban_success(self, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test de ejecución exitosa de baneo de IP."""
        # Setup mocks
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False
        mock_run_command.return_value = "IP banned successfully"

        # Execute
        result = await execute_ip_action("sshd", "ban", "192.168.1.100")

        # Assertions
        assert result.status == "success"
        assert result.message == "La IP 192.168.1.100 ha sido baneada en el jail sshd."
        assert result.ip_address == "192.168.1.100"
        assert result.jail == "sshd"
        assert result.command_output == "IP banned successfully"
        mock_run_command.assert_called_once_with(["set", "sshd", "banip", "192.168.1.100"])

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_execute_ip_action_unban_success(self, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test de ejecución exitosa de desbaneo de IP."""
        # Setup mocks
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = True
        mock_run_command.return_value = "IP unbanned successfully"

        # Execute
        result = await execute_ip_action("sshd", "unban", "192.168.1.100")

        # Assertions
        assert result.status == "success"
        assert result.message == "La IP 192.168.1.100 ha sido desbaneada en el jail sshd."
        assert result.ip_address == "192.168.1.100"
        assert result.jail == "sshd"
        assert result.command_output == "IP unbanned successfully"
        mock_run_command.assert_called_once_with(["set", "sshd", "unbanip", "192.168.1.100"])

    @patch('controllers.jails.is_valid_ip')
    @pytest.mark.asyncio
    async def test_execute_ip_action_invalid_ip(self, mock_is_valid):
        """Test con IP inválida debe lanzar HTTPException 400."""
        mock_is_valid.return_value = False

        with pytest.raises(HTTPException) as exc_info:
            await execute_ip_action("sshd", "ban", "invalid_ip")

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "Formato de dirección IP inválido."

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @pytest.mark.asyncio
    async def test_execute_ip_action_jail_not_exists(self, mock_jail_exists, mock_is_valid):
        """Test con jail inexistente debe lanzar HTTPException 400."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = False

        with pytest.raises(HTTPException) as exc_info:
            await execute_ip_action("nonexistent", "ban", "192.168.1.100")

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "El jail nonexistent no existe."

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @pytest.mark.asyncio
    async def test_execute_ip_action_already_banned(self, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test cuando IP ya está baneada y se intenta banear."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = True

        result = await execute_ip_action("sshd", "ban", "192.168.1.100")

        assert result.status == "info"
        assert result.message == "La IP 192.168.1.100 ya está baneada en el jail sshd."
        assert result.ip_address == "192.168.1.100"
        assert result.jail == "sshd"
        assert result.command_output is None

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @pytest.mark.asyncio
    async def test_execute_ip_action_not_banned_unban_attempt(self, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test cuando IP no está baneada y se intenta desbanear."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False

        result = await execute_ip_action("sshd", "unban", "192.168.1.100")

        assert result.status == "info"
        assert result.message == "La IP 192.168.1.100 no está baneada en el jail sshd."
        assert result.ip_address == "192.168.1.100"
        assert result.jail == "sshd"
        assert result.command_output is None

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_execute_ip_action_already_banned_output(self, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test cuando fail2ban retorna 'already banned' en la salida."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False
        mock_run_command.return_value = "IP already banned"

        result = await execute_ip_action("sshd", "ban", "192.168.1.100")

        assert result.status == "info"
        assert result.message == "La IP 192.168.1.100 ya estaba baneada en el jail sshd."

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_execute_ip_action_not_banned_output(self, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test cuando fail2ban retorna 'is not banned' en la salida."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = True
        mock_run_command.return_value = "IP is not banned"

        result = await execute_ip_action("sshd", "unban", "192.168.1.100")

        assert result.status == "info"
        assert result.message == "La IP 192.168.1.100 no estaba baneada en el jail sshd."


class TestBanIPEndpoint:
    """Test suite para el endpoint ban_ip_in_jail."""

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_ban_ip_success(self, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test de baneo exitoso con IP válida."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False
        mock_run_command.return_value = "IP banned successfully"

        request = IPActionRequest(ip_address="192.168.1.100")
        result = await ban_ip_in_jail("sshd", request)

        assert isinstance(result, ActionResponse)
        assert result.status == "success"
        assert result.message == "La IP 192.168.1.100 ha sido baneada en el jail sshd."
        assert result.ip_address == "192.168.1.100"
        assert result.jail == "sshd"

    @patch('controllers.jails.is_valid_ip')
    @pytest.mark.asyncio
    async def test_ban_ip_invalid_ip(self, mock_is_valid):
        """Test con IP inválida debe lanzar HTTPException 400."""
        mock_is_valid.return_value = False

        request = IPActionRequest(ip_address="invalid_ip")
        with pytest.raises(HTTPException) as exc_info:
            await ban_ip_in_jail("sshd", request)

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "Formato de dirección IP inválido."

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @pytest.mark.asyncio
    async def test_ban_ip_jail_not_exists(self, mock_jail_exists, mock_is_valid):
        """Test con jail inexistente debe lanzar HTTPException 400."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = False

        request = IPActionRequest(ip_address="192.168.1.100")
        with pytest.raises(HTTPException) as exc_info:
            await ban_ip_in_jail("nonexistent", request)

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "El jail nonexistent no existe."

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @pytest.mark.asyncio
    async def test_ban_ip_already_banned(self, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test cuando IP ya está baneada."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = True

        request = IPActionRequest(ip_address="192.168.1.100")
        result = await ban_ip_in_jail("sshd", request)

        assert result.status == "info"
        assert result.message == "La IP 192.168.1.100 ya está baneada en el jail sshd."
        assert result.command_output is None

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_ban_ip_already_banned_from_fail2ban_output(self, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test del comportamiento cuando fail2ban retorna 'already banned'."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False
        mock_run_command.return_value = "IP already banned"

        request = IPActionRequest(ip_address="192.168.1.100")
        result = await ban_ip_in_jail("sshd", request)

        assert result.status == "info"
        assert result.message == "La IP 192.168.1.100 ya estaba baneada en el jail sshd."


class TestUnbanIPEndpoint:
    """Test suite para el endpoint unban_ip_in_jail."""

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_unban_ip_success(self, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test de desbaneo exitoso con IP válida."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = True
        mock_run_command.return_value = "IP unbanned successfully"

        request = IPActionRequest(ip_address="192.168.1.100")
        result = await unban_ip_in_jail("sshd", request)

        assert isinstance(result, ActionResponse)
        assert result.status == "success"
        assert result.message == "La IP 192.168.1.100 ha sido desbaneada en el jail sshd."
        assert result.ip_address == "192.168.1.100"
        assert result.jail == "sshd"

    @patch('controllers.jails.is_valid_ip')
    @pytest.mark.asyncio
    async def test_unban_ip_invalid_ip(self, mock_is_valid):
        """Test con IP inválida debe lanzar HTTPException 400."""
        mock_is_valid.return_value = False

        request = IPActionRequest(ip_address="invalid_ip")
        with pytest.raises(HTTPException) as exc_info:
            await unban_ip_in_jail("sshd", request)

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "Formato de dirección IP inválido."

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @pytest.mark.asyncio
    async def test_unban_ip_jail_not_exists(self, mock_jail_exists, mock_is_valid):
        """Test con jail inexistente debe lanzar HTTPException 400."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = False

        request = IPActionRequest(ip_address="192.168.1.100")
        with pytest.raises(HTTPException) as exc_info:
            await unban_ip_in_jail("nonexistent", request)

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "El jail nonexistent no existe."

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @pytest.mark.asyncio
    async def test_unban_ip_not_banned(self, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test cuando IP no está baneada."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False

        request = IPActionRequest(ip_address="192.168.1.100")
        result = await unban_ip_in_jail("sshd", request)

        assert result.status == "info"
        assert result.message == "La IP 192.168.1.100 no está baneada en el jail sshd."
        assert result.command_output is None

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_unban_ip_not_banned_from_fail2ban_output(self, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test del comportamiento cuando fail2ban retorna 'is not banned'."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = True
        mock_run_command.return_value = "IP is not banned"

        request = IPActionRequest(ip_address="192.168.1.100")
        result = await unban_ip_in_jail("sshd", request)

        assert result.status == "info"
        assert result.message == "La IP 192.168.1.100 no estaba baneada en el jail sshd."


class TestGetJailsEndpoint:
    """Test suite para el endpoint get_jails."""

    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_get_jails_success(self, mock_run_command):
        """Test obtención exitosa de lista de jails."""
        mock_run_command.return_value = """Status
|- Number of jail:      3
`- Jail list:   sshd, apache-auth, apache-badbots"""

        result = await get_jails()

        assert isinstance(result, list)
        assert len(result) == 3
        assert "sshd" in result
        assert "apache-auth" in result
        assert "apache-badbots" in result

    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_get_jails_single_jail(self, mock_run_command):
        """Test con un solo jail configurado."""
        mock_run_command.return_value = """Status
|- Number of jail:      1
`- Jail list:   sshd"""

        result = await get_jails()

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0] == "sshd"

    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_get_jails_no_jails_configured(self, mock_run_command):
        """Test cuando no hay jails configurados."""
        mock_run_command.return_value = """Status
|- Number of jail:      0
`- Currently no jail are active"""

        result = await get_jails()

        assert isinstance(result, list)
        assert len(result) == 0

    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_get_jails_no_jail_keyword_found(self, mock_run_command):
        """Test cuando fail2ban retorna 'no jail'."""
        mock_run_command.return_value = "No jail available"

        result = await get_jails()

        assert isinstance(result, list)
        assert len(result) == 0

    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_get_jails_cannot_parse_output(self, mock_run_command):
        """Test manejo de errores cuando no se puede parsear la salida."""
        mock_run_command.return_value = "Unexpected output format"

        with pytest.raises(HTTPException) as exc_info:
            await get_jails()

        assert exc_info.value.status_code == 500
        assert exc_info.value.detail == "No se pudo obtener la lista de jails"

    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_get_jails_with_whitespace(self, mock_run_command):
        """Test parseo correcto con espacios en blanco."""
        mock_run_command.return_value = """Status
|- Number of jail:      2
`- Jail list:   sshd,  apache-auth  """

        result = await get_jails()

        assert isinstance(result, list)
        assert len(result) == 2
        assert "sshd" in result
        assert "apache-auth" in result


class TestIntegration:
    """Tests de integración para el controller jails."""

    def test_router_endpoints_registration(self):
        """Test que los endpoints están correctamente registrados en el router."""
        from controllers.jails import router
        
        # Verificar que el router tiene rutas registradas
        assert len(router.routes) > 0
        
        # Verificar que tenemos al menos 3 endpoints registrados
        assert len(router.routes) >= 3  # ban-ip, unban-ip, get jails

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_full_ban_unban_cycle(self, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test de ciclo completo: banear y luego desbanear una IP."""
        # Setup mocks
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_run_command.return_value = "Command executed successfully"
        
        # First ban (IP not banned initially)
        mock_is_banned.return_value = False
        request = IPActionRequest(ip_address="192.168.1.100")
        ban_result = await ban_ip_in_jail("sshd", request)
        
        assert ban_result.status == "success"
        assert "baneada" in ban_result.message
        
        # Then unban (IP is now banned)
        mock_is_banned.return_value = True
        unban_result = await unban_ip_in_jail("sshd", request)
        
        assert unban_result.status == "success"
        assert "desbaneada" in unban_result.message

    def test_action_response_model_validation(self):
        """Test validación del modelo ActionResponse."""
        # Test con todos los campos
        response = ActionResponse(
            status="success",
            message="Test message",
            ip_address="192.168.1.100",
            jail="sshd",
            command_output="Output"
        )
        
        assert response.status == "success"
        assert response.message == "Test message"
        assert response.ip_address == "192.168.1.100"
        assert response.jail == "sshd"
        assert response.command_output == "Output"
        
        # Test con campos opcionales None
        response_minimal = ActionResponse(
            status="info",
            message="Info message"
        )
        
        assert response_minimal.status == "info"
        assert response_minimal.message == "Info message"
        assert response_minimal.ip_address is None
        assert response_minimal.jail is None
        assert response_minimal.command_output is None


class TestEdgeCases:
    """Tests para casos edge y escenarios especiales."""

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_ipv6_address_handling(self, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test manejo de direcciones IPv6."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False
        mock_run_command.return_value = "IPv6 banned successfully"

        request = IPActionRequest(ip_address="2001:db8::1")
        result = await ban_ip_in_jail("sshd", request)

        assert result.status == "success"
        assert "2001:db8::1" in result.message

    @patch('controllers.jails.is_valid_ip')
    @patch('controllers.jails.jail_exists')
    @patch('controllers.jails.is_ip_banned')
    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_special_characters_in_jail_name(self, mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid):
        """Test manejo de nombres de jail con caracteres especiales."""
        mock_is_valid.return_value = True
        mock_jail_exists.return_value = True
        mock_is_banned.return_value = False
        mock_run_command.return_value = "Command executed"

        request = IPActionRequest(ip_address="192.168.1.100")
        result = await ban_ip_in_jail("apache-custom-auth-2024", request)

        assert result.status == "success"
        assert "apache-custom-auth-2024" in result.message

    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_get_jails_empty_jail_list_line(self, mock_run_command):
        """Test cuando la línea de jail list está vacía."""
        mock_run_command.return_value = """Status
|- Number of jail:      0
`- Jail list:   """

        result = await get_jails()

        assert isinstance(result, list)
        assert len(result) == 0

    @patch('controllers.jails.run_fail2ban_command')
    @pytest.mark.asyncio
    async def test_get_jails_malformed_response(self, mock_run_command):
        """Test con respuesta malformada de fail2ban."""
        mock_run_command.return_value = "Malformed response without jail list"

        with pytest.raises(HTTPException) as exc_info:
            await get_jails()

        assert exc_info.value.status_code == 500