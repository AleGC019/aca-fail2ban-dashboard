# Test Commands for Fail2ban Dashboard

## Para ejecutar todos los tests:
pytest tests/ -v

## Para ejecutar tests específicos por categoría:

### Tests de Controllers:
pytest tests/controller_tests/ -v

### Tests de Services:
pytest tests/service_tests/ -v

## Para ejecutar tests específicos por archivo:

### Tests de autenticación:
pytest tests/controller_tests/auth_test.py -v
pytest tests/service_tests/auth_test.py -v

### Tests de usuarios:
pytest tests/controller_tests/users_test.py -v

### Tests de jails:
pytest tests/controller_tests/jails_test.py -v

### Tests de logs:
pytest tests/controller_tests/logs_test.py -v

### Tests de fail2ban:
pytest tests/service_tests/fail2ban_test.py -v

### Tests de loki:
pytest tests/service_tests/loki_test.py -v

## Para ejecutar tests con coverage:
pytest tests/ --cov=controllers --cov=services --cov-report=html

## Para ejecutar tests específicos:
pytest tests/controller_tests/auth_test.py::TestAuthController::test_register_success -v

## Para ejecutar tests en modo debug:
pytest tests/ -v -s

## Para ejecutar tests en paralelo (requiere pytest-xdist):
pytest tests/ -n auto

## Para ver solo fallos:
pytest tests/ --tb=short

## Para generar reporte XML (para CI/CD):
pytest tests/ --junitxml=test-results.xml
