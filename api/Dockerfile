FROM python:3.10

WORKDIR /app

# Instala fail2ban (que incluye fail2ban-client) y herramientas de red
# Se usa --no-install-recommends para minimizar el tamaño.
# fail2ban puede traer dependencias como rsyslog, iptables, etc. que pueden no ser necesarias
# solo para el cliente, pero es la forma más estándar de obtenerlo.
RUN apt-get update \
    && apt-get install -y --no-install-recommends fail2ban iputils-ping curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Instala dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Nota: El servicio fail2ban no se inicia aquí dentro del contenedor, solo necesitamos el cliente.
# El CMD sigue siendo para uvicorn.
# ... (resto de tu Dockerfile: FROM, WORKDIR, RUN apt-get, COPY, RUN pip, EXPOSE) ...

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]