# Tests para Fail2ban Dashboard API

Esta carpeta contiene una suite completa de tests para todos los controladores y servicios del backend de Fail2ban Dashboard.

## Estructura de Tests

```
tests/
├── conftest.py                 # Configuración global de pytest y fixtures
├── controller_tests/           # Tests para controllers
│   ├── __init__.py
│   ├── auth_test.py           # Tests para controllers/auth.py
│   ├── users_test.py          # Tests para controllers/users.py
│   ├── jails_test.py          # Tests para controllers/jails.py
│   └── logs_test.py           # Tests para controllers/logs.py
├── service_tests/             # Tests para services
│   ├── __init__.py
│   ├── auth_test.py           # Tests para services/auth.py
│   ├── fail2ban_test.py       # Tests para services/fail2ban.py
│   └── loki_test.py           # Tests para services/loki.py
├── TEST_COMMANDS.md           # Comandos para ejecutar tests
└── README.md                  # Este archivo
```

## Tipos de Tests Incluidos

### Controller Tests

#### auth_test.py
- ✅ Test de registro exitoso de usuario
- ✅ Test de registro con usuario existente
- ✅ Test de login exitoso
- ✅ Test de login con credenciales inválidas
- ✅ Test de obtener información del usuario actual
- ✅ Test de verificación de existencia de usuarios
- ✅ Test de validación de datos de entrada

#### users_test.py
- ✅ Test de obtener usuario por ID
- ✅ Test de obtener usuarios paginados
- ✅ Test de eliminar usuario (solo admin)
- ✅ Test de asignar rol admin
- ✅ Test de actualizar usuario (self y admin)
- ✅ Test de obtener estadísticas de usuarios
- ✅ Test de control de permisos y autorización

#### jails_test.py
- ✅ Test de banear IP exitosamente
- ✅ Test de desbanear IP exitosamente
- ✅ Test de validación de IP
- ✅ Test de verificación de jail existente
- ✅ Test de manejo de IPs ya baneadas/no baneadas
- ✅ Test de obtener lista de jails
- ✅ Test de control de permisos admin

#### logs_test.py
- ✅ Test de obtener IPs actualmente baneadas
- ✅ Test de obtener logs filtrados
- ✅ Test de estadísticas de Fail2ban
- ✅ Test de estadísticas de IPs baneadas
- ✅ Test de endpoints protegidos
- ✅ Test de manejo de errores de Loki

### Service Tests

#### auth_test.py
- ✅ Test de hash y verificación de contraseñas
- ✅ Test de creación y validación de tokens JWT
- ✅ Test de registro de usuarios (validaciones)
- ✅ Test de autenticación de usuarios
- ✅ Test de obtener usuario actual desde token
- ✅ Test de verificación de roles y permisos

#### fail2ban_test.py
- ✅ Test de validación de IPs (IPv4 e IPv6)
- ✅ Test de verificación de existencia de jails
- ✅ Test de verificación de IPs baneadas
- ✅ Test de obtener IPs actualmente baneadas
- ✅ Test de ejecutar comandos fail2ban
- ✅ Test de obtener duración de ban
- ✅ Test de formateo de duración
- ✅ Test de manejo de errores y timeouts

#### loki_test.py
- ✅ Test de consultas exitosas a Loki
- ✅ Test de manejo de respuestas vacías
- ✅ Test de manejo de errores de conexión
- ✅ Test de manejo de errores HTTP
- ✅ Test de parsing de múltiples streams
- ✅ Test de manejo de timeouts

## Configuración de Tests

### conftest.py
Contiene:
- Variables de entorno para testing
- Fixtures para usuarios de prueba
- Fixtures para tokens JWT
- Fixtures para respuestas mock de servicios externos
- Configuración global de pytest

### Mocking
Los tests utilizan mocking extensivo para:
- Llamadas a base de datos (MongoDB)
- Comandos del sistema (fail2ban-client)
- Llamadas HTTP a Loki
- Autenticación y autorización

## Cobertura de Tests

Los tests cubren:
- **Casos exitosos**: Funcionamiento normal de todas las funciones
- **Casos de error**: Manejo de errores, excepciones y fallos
- **Validación**: Validación de entrada y datos
- **Autorización**: Control de acceso y permisos
- **Edge cases**: Casos límite y situaciones especiales

## Cómo Ejecutar

### Prerrequisitos
```bash
pip install pytest pytest-asyncio httpx
```

### Comandos Básicos
```bash
# Todos los tests
pytest tests/ -v

# Solo controllers
pytest tests/controller_tests/ -v

# Solo services
pytest tests/service_tests/ -v

# Test específico
pytest tests/controller_tests/auth_test.py::TestAuthController::test_register_success -v
```

### Con Coverage
```bash
pytest tests/ --cov=controllers --cov=services --cov-report=html
```

## Fixtures Disponibles

- `mock_user`: Usuario de prueba con rol USER
- `mock_admin_user`: Usuario administrador de prueba
- `mock_jwt_token`: Token JWT válido para testing
- `mock_banned_ips`: Lista de IPs baneadas para testing
- `mock_loki_response`: Respuesta típica de Loki
- `mock_fail2ban_client`: Mock del cliente fail2ban

## Mejores Prácticas

1. **Aislamiento**: Cada test es independiente
2. **Mocking**: Se mockean todas las dependencias externas
3. **Claridad**: Nombres descriptivos y documentación clara
4. **Cobertura**: Se cubren tanto casos exitosos como de error
5. **Mantenibilidad**: Estructura organizada y reutilizable

## Notas Importantes

- Los tests no requieren servicios externos (Loki, MongoDB, fail2ban)
- Todos los tests son asincrónicos donde es necesario
- Se incluyen tests para validación de entrada y manejo de errores
- Los mocks están configurados para simular comportamiento real
