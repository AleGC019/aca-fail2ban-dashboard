from fastapi.testclient import TestClient
from unittest.mock import patch

@patch.dict('os.environ', {'LOKI_QUERY_URL': 'http://test:3100/api/v1/query_range'})
def test_health_endpoint():
    """Test health endpoint"""
    from main import app
    Test Jira 
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert "status" in response.json()