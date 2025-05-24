import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

def test_imports():
    """Test that basic imports work"""
    try:
        from main import app
        from data.models import LogEntry, IPActionRequest, ActionResponse
        from services.fail2ban import is_valid_ip
        assert True
    except ImportError as e:
        pytest.fail(f"Import failed: {e}")

def test_ip_validation():
    """Test IP validation function"""
    from services.fail2ban import is_valid_ip
    
    # Valid IPs
    assert is_valid_ip("192.168.1.1") == True
    assert is_valid_ip("10.0.0.1") == True
    assert is_valid_ip("8.8.8.8") == True
    
    # Invalid IPs
    assert is_valid_ip("256.1.1.1") == False
    assert is_valid_ip("not.an.ip") == False
    assert is_valid_ip("") == False

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://test:3100/api/v1/query_range'})
def test_health_endpoint():
    """Test health endpoint"""
    from main import app
    from fastapi.testclient import TestClient
    
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert "status" in response.json()