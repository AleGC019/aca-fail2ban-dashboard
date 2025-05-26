import pytest
import os
from unittest.mock import patch

@pytest.fixture(autouse=True)
def setup_test_environment():
    """Setup environment variables for all tests"""
    with patch.dict(os.environ, {
        'LOKI_QUERY_URL': 'http://test-loki:3100/api/v1/query_range',
        'LOKI_WS_URL': 'ws://test-loki:3100/loki/api/v1/tail',
        'LOKI_PUSH_URL': 'http://test-loki:3100/loki/api/v1/push'
    }):
        yield