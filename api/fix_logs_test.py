#!/usr/bin/env python3

import re

# Leer el archivo
with open('tests/controller_tests/logs_test.py', 'r') as f:
    content = f.read()

# Reemplazar patches de get_current_user
# Patrón para encontrar @patch('controllers.logs.get_current_user')
content = re.sub(r"@patch\('controllers\.logs\.get_current_user'\)\s*\n", "", content)

# Reemplazar referencias a mock_get_current_user en parámetros de función
content = re.sub(r", mock_get_current_user", "", content)
content = re.sub(r"mock_get_current_user, ", "", content)

# Reemplazar líneas que configuran mock_get_current_user
content = re.sub(r"\s*mock_get_current_user\.return_value = admin_user\s*\n", "", content)

# Escribir el archivo actualizado
with open('tests/controller_tests/logs_test.py', 'w') as f:
    f.write(content)

print("Archivo actualizado exitosamente")
