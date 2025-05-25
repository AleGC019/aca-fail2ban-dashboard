from fastapi.testclient import TestClient
from unittest.mock import patch

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
def test_jails_controller_import():
    """Test that jails controller can be imported without errors"""
    from controllers.jails import router
    assert router is not None

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
@patch('services.fail2ban.is_valid_ip')
@patch('services.fail2ban.jail_exists')
@patch('services.fail2ban.is_ip_banned')
@patch('services.fail2ban.run_fail2ban_command')
def test_ban_ip_success(mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid_ip):
    """Test successful IP ban"""
    mock_is_valid_ip.return_value = True
    mock_jail_exists.return_value = True
    mock_is_banned.return_value = False
    mock_run_command.return_value = "SUCCESS: IP banned"
    
    from main import app
    client = TestClient(app)
    
    request_data = {
        "ip_address": "192.168.1.100"
    }
    
    response = client.post("/jails/sshd/ban-ip", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "baneada" in data["message"]

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
@patch('services.fail2ban.is_valid_ip')
@patch('services.fail2ban.jail_exists')
@patch('services.fail2ban.is_ip_banned')
@patch('services.fail2ban.run_fail2ban_command')
def test_unban_ip_success(mock_run_command, mock_is_banned, mock_jail_exists, mock_is_valid_ip):
    """Test successful IP unban"""
    mock_is_valid_ip.return_value = True
    mock_jail_exists.return_value = True
    mock_is_banned.return_value = True
    mock_run_command.return_value = "SUCCESS: IP unbanned"
    
    from main import app
    client = TestClient(app)
    
    request_data = {
        "ip_address": "192.168.1.100"
    }
    
    response = client.post("/jails/sshd/unban-ip", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "desbaneada" in data["message"]

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
@patch('services.fail2ban.is_valid_ip')
def test_ban_ip_invalid_ip(mock_is_valid_ip):
    """Test ban IP with invalid IP address"""
    mock_is_valid_ip.return_value = False
    
    from main import app
    client = TestClient(app)
    
    request_data = {
        "ip_address": "invalid_ip"
    }
    
    response = client.post("/jails/sshd/ban-ip", json=request_data)
    assert response.status_code == 400
    data = response.json()
    assert "inválido" in data["detail"]

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
@patch('services.fail2ban.is_valid_ip')
@patch('services.fail2ban.jail_exists')
def test_ban_ip_invalid_jail(mock_jail_exists, mock_is_valid_ip):
    """Test ban IP with invalid jail"""
    mock_is_valid_ip.return_value = True
    mock_jail_exists.return_value = False
    
    from main import app
    client = TestClient(app)
    
    request_data = {
        "ip_address": "192.168.1.100"
    }
    
    response = client.post("/jails/nonexistent_jail/ban-ip", json=request_data)
    assert response.status_code == 400
    data = response.json()
    assert "no existe" in data["detail"]

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
@patch('services.fail2ban.is_valid_ip')
@patch('services.fail2ban.jail_exists')
@patch('services.fail2ban.is_ip_banned')
def test_ban_ip_already_banned(mock_is_banned, mock_jail_exists, mock_is_valid_ip):
    """Test ban IP that is already banned"""
    mock_is_valid_ip.return_value = True
    mock_jail_exists.return_value = True
    mock_is_banned.return_value = True
    
    from main import app
    client = TestClient(app)
    
    request_data = {
        "ip_address": "192.168.1.100"
    }
    
    response = client.post("/jails/sshd/ban-ip", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "info"
    assert "ya está baneada" in data["message"]

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
@patch('services.fail2ban.is_valid_ip')
@patch('services.fail2ban.jail_exists')
@patch('services.fail2ban.is_ip_banned')
def test_unban_ip_not_banned(mock_is_banned, mock_jail_exists, mock_is_valid_ip):
    """Test unban IP that is not banned"""
    mock_is_valid_ip.return_value = True
    mock_jail_exists.return_value = True
    mock_is_banned.return_value = False
    
    from main import app
    client = TestClient(app)
    
    request_data = {
        "ip_address": "192.168.1.100"
    }
    
    response = client.post("/jails/sshd/unban-ip", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "info"
    assert "no está baneada" in data["message"]

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
@patch('services.fail2ban.run_fail2ban_command')
def test_get_jails_list(mock_run_command):
    """Test get jails list endpoint"""
    mock_run_command.return_value = "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, apache2"
    
    from main import app
    client = TestClient(app)
    
    response = client.get("/jails")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert "sshd" in data
    assert "apache2" in data

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
def test_invalid_request_format():
    """Test invalid request format"""
    from main import app
    client = TestClient(app)
    
    # Missing required fields
    response = client.post("/jails/sshd/ban-ip", json={})
    assert response.status_code == 422  # Validation error
