from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
def test_logs_controller_import():
    """Test that logs controller can be imported without errors"""
    from controllers.logs import router
    assert router is not None

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http:/loki:3100/api/v1/query_range'})
@patch('httpx.AsyncClient.get')
async def test_fail2ban_logs_endpoint(mock_get):
    """Test fail2ban logs endpoint returns proper response"""
    # Mock Loki response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "result": [
                {
                    "stream": {"job": "fail2ban"},
                    "values": [
                        ["1640995200000000000", "2024-01-01 00:00:00 fail2ban.filter [123]: INFO Ban 192.168.1.100"]
                    ]
                }
            ]
        }
    }
    mock_get.return_value = mock_response
    
    from main import app
    client = TestClient(app)
    
    response = client.get("/fail2ban/logs?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "logs" in data
    assert "total" in data

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
@patch('httpx.AsyncClient.get')
async def test_fail2ban_logs_with_filters(mock_get):
    """Test fail2ban logs endpoint with filters"""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "result": [
                {
                    "stream": {"job": "fail2ban"},
                    "values": [
                        ["1640995200000000000", "2024-01-01 00:00:00 fail2ban.filter [123]: INFO Ban 192.168.1.100"]
                    ]
                }
            ]
        }
    }
    mock_get.return_value = mock_response
    
    from main import app
    client = TestClient(app)
    
    response = client.get("/fail2ban/logs?limit=5&jail=sshd&action=ban")
    assert response.status_code == 200
    data = response.json()
    assert "logs" in data

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
@patch('httpx.AsyncClient.get')
async def test_fail2ban_logs_error_handling(mock_get):
    """Test error handling when Loki is unavailable"""
    from httpx import RequestError
    mock_get.side_effect = RequestError("Connection failed")
    
    from main import app
    client = TestClient(app)
    
    response = client.get("/fail2ban/logs")
    assert response.status_code == 500
    data = response.json()
    assert "error" in data

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
@patch('httpx.AsyncClient.get')
async def test_fail2ban_stats_endpoint(mock_get):
    """Test fail2ban stats endpoint"""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "result": [
                {
                    "stream": {"job": "fail2ban"},
                    "values": [
                        ["1640995200000000000", "2024-01-01 00:00:00 fail2ban.filter [123]: INFO Ban 192.168.1.100"],
                        ["1640995300000000000", "2024-01-01 00:01:00 fail2ban.filter [124]: INFO Unban 192.168.1.101"]
                    ]
                }
            ]
        }
    }
    mock_get.return_value = mock_response
    
    from main import app
    client = TestClient(app)
    
    response = client.get("/fail2ban/stats")
    assert response.status_code == 200
    data = response.json()
    assert "stats" in data
    assert "total_events" in data["stats"]

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
@patch('services.fail2ban.get_currently_banned_ips')
async def test_banned_ips_endpoint(mock_banned_ips):
    """Test banned IPs endpoint"""
    mock_banned_ips.return_value = [
        {"ip": "192.168.1.100", "jail": "sshd", "time": "2024-01-01 00:00:00"},
        {"ip": "192.168.1.101", "jail": "apache", "time": "2024-01-01 00:01:00"}
    ]
    
    from main import app
    client = TestClient(app)
    
    response = client.get("/fail2ban/banned-ips")
    assert response.status_code == 200
    data = response.json()
    assert "banned_ips" in data
    assert len(data["banned_ips"]) == 2

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://loki:3100/api/v1/query_range'})
def test_health_endpoint():
    """Test health endpoint"""
    from main import app
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert "status" in response.json()
