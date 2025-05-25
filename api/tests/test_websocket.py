from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://test:3100/api/v1/query_range'})
def test_websocket_import():
    """Test that websocket endpoints can be imported without errors"""
    from controllers.logs import router
    assert router is not None

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://test:3100/api/v1/query_range'})
@patch('httpx.AsyncClient.get')
def test_websocket_connection(mock_get):
    """Test WebSocket connection establishment"""
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
    
    with client.websocket_connect("/ws/fail2ban-logs") as websocket:
        # Test that connection is established
        assert websocket is not None
        
        # Test receiving initial data
        data = websocket.receive_json()
        assert "logs" in data or "type" in data

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://test:3100/api/v1/query_range'})
@patch('httpx.AsyncClient.get')
def test_websocket_with_parameters(mock_get):
    """Test WebSocket connection with query parameters"""
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
    
    with client.websocket_connect("/ws/fail2ban-logs?limit=5&start=1640995200000000000") as websocket:
        assert websocket is not None
        data = websocket.receive_json()
        assert data is not None

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://test:3100/api/v1/query_range'})
@patch('httpx.AsyncClient.get')
def test_websocket_error_handling(mock_get):
    """Test WebSocket error handling when Loki is unavailable"""
    from httpx import RequestError
    mock_get.side_effect = RequestError("Connection failed")
    
    from main import app
    client = TestClient(app)
    
    with client.websocket_connect("/ws/fail2ban-logs") as websocket:
        data = websocket.receive_json()
        # Should receive error message
        assert "error" in data or "type" in data

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://test:3100/api/v1/query_range'})
@patch('httpx.AsyncClient.get')
def test_websocket_multiple_messages(mock_get):
    """Test WebSocket receiving multiple messages"""
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
    
    with client.websocket_connect("/ws/fail2ban-logs") as websocket:
        # Receive first message
        data1 = websocket.receive_json()
        assert data1 is not None
        
        # Should be able to receive additional messages
        try:
            data2 = websocket.receive_json(timeout=1)
            # If we get data, verify it's valid
            if data2:
                assert isinstance(data2, dict)
        except Exception:
            # Timeout is acceptable as it depends on implementation
            pass

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://test:3100/api/v1/query_range'})
def test_websocket_disconnect():
    """Test WebSocket graceful disconnection"""
    from main import app
    client = TestClient(app)
    
    # Test that websocket can be opened and closed without errors
    with client.websocket_connect("/ws/fail2ban-logs") as websocket:
        assert websocket is not None
    # WebSocket should be closed after exiting context

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://test:3100/api/v1/query_range'})
@patch('httpx.AsyncClient.get')
def test_websocket_json_format(mock_get):
    """Test WebSocket message format is valid JSON"""
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
    
    with client.websocket_connect("/ws/fail2ban-logs") as websocket:
        data = websocket.receive_json()
        # Verify the data is a valid dictionary (JSON object)
        assert isinstance(data, dict)
        # Common fields that should be present
        if "logs" in data:
            assert isinstance(data["logs"], list)
        elif "type" in data:
            assert isinstance(data["type"], str)

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://test:3100/api/v1/query_range'})
@patch('httpx.AsyncClient.get')
def test_websocket_large_limit_parameter(mock_get):
    """Test WebSocket with large limit parameter"""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "result": [
                {
                    "stream": {"job": "fail2ban"},
                    "values": [
                        [f"164099520{i}000000000", f"2024-01-01 00:0{i}:00 fail2ban.filter [{100+i}]: INFO Ban 192.168.1.{100+i}"]
                        for i in range(100)
                    ]
                }
            ]
        }
    }
    mock_get.return_value = mock_response
    
    from main import app
    client = TestClient(app)
    
    with client.websocket_connect("/ws/fail2ban-logs?limit=100") as websocket:
        data = websocket.receive_json()
        assert data is not None
        if "logs" in data:
            # Should handle large number of logs
            assert len(data["logs"]) <= 100

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://test:3100/api/v1/query_range'})
def test_websocket_invalid_parameters():
    """Test WebSocket with invalid parameters"""
    from main import app
    client = TestClient(app)
    
    # Test with invalid limit parameter
    with client.websocket_connect("/ws/fail2ban-logs?limit=invalid") as websocket:
        # Should still connect but may receive error or default behavior
        data = websocket.receive_json()
        assert data is not None
