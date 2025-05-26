#!/bin/bash

# Script para ejecutar pruebas con cobertura de código
echo "🧪 Ejecutando pruebas con cobertura de código..."

cd "$(dirname "$0")"

# Instalar dependencias si no están instaladas
pip install -r requirements.txt

# Ejecutar pruebas con cobertura
echo "📊 Ejecutando pytest con coverage..."
PYTHONPATH=. python -m pytest tests/ -v --tb=short --cov=. --cov-report=html --cov-report=term --cov-report=json --cov-fail-under=60

# Mostrar resultados
echo ""
echo "📈 Reporte de cobertura generado en: htmlcov/index.html"
echo "🎯 Objetivo mínimo: 60%"
echo ""
echo "Para ver el reporte HTML, ejecuta:"
echo "open htmlcov/index.html"
