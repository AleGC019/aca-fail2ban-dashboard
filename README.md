# Documentación del Servidor y Proyecto de Monitoreo Fail2ban

**Fecha de Documentación:** 21 de mayo de 2025
**Proyecto:** API y Backend para Dashboard de Monitoreo de Logs de Fail2ban
**Proveedor de VM:** DigitalOcean Droplet
**Sistema Operativo:** Ubuntu (ej. 22.04 LTS)
**Dominio Principal (Ejemplo):** `alertasfail2ban.duckdns.org` (o tu dominio propio de Namecheap, ej. `midominiofail2ban.com`)

## 1. Descripción General del Servidor

Este Droplet de DigitalOcean aloja el backend completo para el sistema de monitoreo de logs de Fail2ban. Los componentes principales y su interacción son:

* **Fail2ban (Host):** Se ejecuta directamente en el sistema operativo del Droplet. Monitorea los logs de servicios (como SSH) y aplica baneos de IP basados en reglas predefinidas.
* **Promtail (Contenedor Docker):** Actúa como un agente recolector de logs. Lee los logs generados por Fail2ban en el host y los envía a Loki.
* **Loki (Contenedor Docker):** Es el sistema de agregación y almacenamiento de logs. Recibe los logs de Promtail, los indexa y permite su consulta.
* **API FastAPI (Contenedor Docker):** Es el backend principal desarrollado en Python. Proporciona endpoints HTTP para:
    * Consultar logs de Fail2ban almacenados en Loki.
    * Gestionar baneos de Fail2ban (listar jails, banear/desbanear IPs) interactuando con el `fail2ban-client` del host.
    * Servir una página de inicio HTML.
    * Proporcionar un stream de logs en tiempo real a través de WebSockets (haciendo proxy al endpoint `/tail` de Loki).
* **Caddy (Host):** Actúa como un servidor web y proxy inverso. Se ejecuta directamente en el Droplet. Gestiona automáticamente los certificados SSL/TLS de Let's Encrypt para el dominio configurado, proporcionando HTTPS, y redirige el tráfico al contenedor de la API FastAPI.
* **Docker y Docker Compose:** Utilizados para definir, construir y orquestar los servicios en contenedores (Promtail, Loki, API).

## 2. Configuración Inicial del Droplet y Seguridad

### 2.1. Usuario No-Root con Privilegios `sudo`
* Se ha creado un usuario principal no-root (ej. `makuno`) para las operaciones diarias y la gestión del proyecto.
* Este usuario pertenece al grupo `sudo`, permitiéndole ejecutar comandos administrativos.
    * Creación: `sudo adduser makuno`
    * Añadir a sudo: `sudo usermod -aG sudo makuno`

### 2.2. Autenticación por Clave SSH
* El acceso SSH al Droplet para el usuario `makuno` está configurado para usar **exclusivamente claves SSH**.
* La autenticación por contraseña para SSH ha sido **deshabilitada** en el archivo `/etc/ssh/sshd_config`:
    ```
    PasswordAuthentication no
    ChallengeResponseAuthentication no
    ```
* Se recomienda que el inicio de sesión directo de `root` por SSH esté deshabilitado (`PermitRootLogin no`) o, como mínimo, restringido a `PermitRootLogin prohibit-password` (solo clave SSH para root).

### 2.3. Firewall
* **Cloud Firewall de DigitalOcean:** Es la primera línea de defensa y controla el tráfico entrante al Droplet.
    * **Puerto `22/TCP` (SSH):** Abierto. Idealmente, restringido a direcciones IP de confianza si es posible.
    * **Puerto `80/TCP` (HTTP):** Abierto a `All IPv4` y `All IPv6` (o `0.0.0.0/0, ::/0`). Necesario para la validación HTTP-01 de Let's Encrypt por Caddy.
    * **Puerto `443/TCP` (HTTPS):** Abierto a `All IPv4` y `All IPv6`. Para el tráfico de la API a través de Caddy.
    * **Puerto de la API (ej. `8000/TCP`):** Este puerto, donde escucha la API FastAPI dentro de Docker y es mapeado al host, **NO debe estar abierto al público en el Cloud Firewall**. Caddy accede a este puerto localmente en el Droplet.
* **`ufw` (Firewall del Sistema Operativo - Opcional):** Si se utiliza `ufw` en el Droplet, debe estar configurado para permitir el tráfico necesario (mínimo SSH en el puerto 22, y los puertos 80 y 443 para Caddy). El Cloud Firewall suele ser suficiente.

### 2.4. Actualizaciones del Sistema
* El sistema operativo Ubuntu y sus paquetes se mantienen actualizados ejecutando regularmente:
    ```bash
    sudo apt update && sudo apt upgrade -y
    ```

### 2.5. Zona Horaria del Servidor
* El servidor está configurado para usar la zona horaria **UTC** por defecto.
    * Verificar con: `date` o `timedatectl`.
* **Consideración:** Al revisar logs, es importante tener en cuenta la diferencia horaria con la zona horaria local del usuario (ej. Centroamérica UTC-6).

## 3. Software Esencial Instalado en el Host del Droplet

* **Git:** Para la gestión del código fuente del proyecto.
    * Instalación: `sudo apt install git -y`
* **Docker Engine:** Plataforma de contenedores.
    * Instalación: `sudo apt install docker.io -y`
    * Servicio: Habilitado para iniciar al arranque (`sudo systemctl enable docker && sudo systemctl start docker`).
    * El usuario no-root (`makuno`) ha sido añadido al grupo `docker` para ejecutar comandos Docker sin `sudo` (`sudo usermod -aG docker makuno`, requiere nuevo login).
* **Docker Compose V2:** Herramienta para definir y ejecutar aplicaciones Docker multi-contenedor.
    * Instalación: `sudo apt install docker-compose-v2 -y` (o el método de plugin para Docker).
    * Uso: `docker compose ...`
* **Fail2ban:** Servicio de prevención de intrusiones.
    * Instalación: `sudo apt install fail2ban -y`
    * Servicio: Habilitado para iniciar al arranque (`sudo systemctl enable fail2ban && sudo systemctl start fail2ban`).
* **Caddy v2:** Servidor web moderno y proxy inverso con HTTPS automático.
    * Instalación: Siguiendo la guía oficial de Caddy para Ubuntu (usando su repositorio APT).
    * Servicio: Habilitado para iniciar al arranque (`sudo systemctl enable caddy && sudo systemctl start caddy`).

## 4. Despliegue del Proyecto

1.  **Clonación del Repositorio:**
    * El código del proyecto (que incluye la API, Dockerfile, docker-compose.yaml, y configuraciones de Loki/Promtail) se clona desde un repositorio Git en un directorio del usuario no-root (ej. `/home/makuno/aca-fail2ban-dashboard`).

2.  **Archivo de Entorno `.env`:**
    * Ubicado en la raíz del directorio del proyecto clonado.
    * Creado a partir de un archivo `_env.example_` (o similar).
    * **Variables de entorno críticas definidas:**
        * `LOKI_QUERY_URL=http://loki:3100/loki/api/v1/query_range`
        * `LOKI_WS_URL=ws://loki:3100/loki/api/v1/tail`
        * `FAIL2BAN_LOG_PATH=/var/log/fail2ban.log` (o la ruta real del log de Fail2ban en el Droplet).
        * `API_PORT=8000` (puerto en el host al que se mapea el contenedor de la API).
        * `LOKI_PORT=3100` (puerto en el host al que se mapea el contenedor de Loki, si se expone directamente, aunque el acceso principal es vía API/Caddy).

3.  **Ejecución de Servicios con Docker Compose:**
    * Desde el directorio raíz del proyecto (donde está `docker-compose.yaml`):
        ```bash
        docker compose up -d --build
        ```
    * Esto construye la imagen de la API si es necesario y levanta los servicios `api`, `loki`, y `promtail` en modo detached.
    * Todos los servicios Docker tienen configurada la política `restart: unless-stopped` en `docker-compose.yaml` para asegurar que se inicien automáticamente si el Droplet se reinicia o si el servicio Docker se reinicia.

## 5. Configuración de Servicios Detallada

### 5.1. Fail2ban (Host)
* **Configuración Local:** Principalmente en `/etc/fail2ban/jail.local` (o archivos dentro de `/etc/fail2ban/jail.d/`).
* **Jails Activos:** Mínimo `[sshd]` para proteger el acceso SSH. Otros jails pueden estar configurados para servicios adicionales.
* **Log de Fail2ban:** Escribe en la ruta especificada por `FAIL2BAN_LOG_PATH` (ej. `/var/log/fail2ban.log`). Esta ruta se monta en el contenedor de Promtail.
* **`ignoreip`:** Es crucial añadir las direcciones IP estáticas de los administradores/desarrolladores en la directiva `ignoreip` (dentro de `[DEFAULT]` o en jails específicos) para evitar auto-baneos durante el desarrollo y las pruebas.
* **Socket para `fail2ban-client`:** El socket `/var/run/fail2ban/fail2ban.sock` del host se monta en el contenedor de la API para permitir la interacción con `fail2ban-client`.

### 5.2. Promtail (Contenedor Docker)
* **Archivo de Configuración:** Montado desde `promtail/promtail.yaml` del repositorio.
* **Configuración Clave:**
    * `server`: Define `http_listen_port` y `grpc_listen_port` internos.
    * `positions`: `/tmp/positions.yaml` (dentro del contenedor, para guardar el progreso de lectura de logs).
    * `clients`: `url: ${LOKI_PUSH_URL}` (usa la variable de entorno, que apunta a `http://loki:3100/loki/api/v1/push`).
    * `scrape_configs`:
        * `job_name: fail2ban`.
        * `static_configs`: `labels: { job: "fail2ban", __path__: "${FAIL2BAN_LOG_PATH}" }`.
        * `pipeline_stages`:
            * `multiline`: Para agrupar logs de Fail2ban.
            * `regex`: Para parsear los logs y extraer campos (`time`, `component`, `pid`, `level`, `jail`, `msg`).
            * `timestamp`: Para usar el `time` extraído como timestamp del log.
            * `labels`: Para crear etiquetas en Loki (`component`, `pid`, `level`, `jail`).
            * `output`: Para definir el mensaje principal del log.

### 5.3. Loki (Contenedor Docker)
* **Archivo de Configuración:** Montado desde `loki/config.yaml` del repositorio.
* **Configuración Clave:**
    * `auth_enabled: false` (para simplificar la comunicación interna en la red Docker).
    * `server.http_listen_port: 3100`.
    * `storage_config`, `common.storage`, `schema_config`: Configurado para `boltdb-shipper` y `filesystem`, con almacenamiento en `/loki` dentro del contenedor.
* **Persistencia de Datos:** A través del volumen Docker nombrado `loki_data`, mapeado a `/loki` dentro del contenedor.
* **Endpoints de API Relevantes:**
    * `/loki/api/v1/query_range`: Usado por la API FastAPI para consultas HTTP.
    * `/loki/api/v1/tail`: Usado por la API FastAPI para el streaming de logs vía WebSocket.

### 5.4. API FastAPI (Contenedor Docker)
* **Estructura del Proyecto:** Organizada en `main.py`, `controllers/`, `services/`, `data/`, `configuration/`, `static/`, `templates/`.
* **`main.py`:**
    * Inicializa la aplicación FastAPI.
    * Configura CORS (actualmente permisivo con `allow_origins=["*"]`).
    * Monta el directorio `static/` para servir archivos CSS (y opcionalmente JS/imágenes).
    * Configura `Jinja2Templates` para servir HTML desde el directorio `templates/`.
    * Define la ruta raíz (`/`) que sirve la página de inicio `index.html`.
    * Incluye los routers de los directorios `controllers/`.
* **`configuration/settings.py`:**
    * Carga y valida variables de entorno desde `.env` usando un objeto `settings` (incluyendo `LOKI_QUERY_URL`, `LOKI_WS_URL`).
* **`Dockerfile` (`api/Dockerfile`):**
    * Basado en una imagen Python (ej. `python:3.10-alpine` o `python:3.10-slim`).
    * Instala dependencias del sistema como `fail2ban` (para `fail2ban-client`).
    * Instala dependencias Python desde `requirements.txt` (incluyendo `fastapi`, `uvicorn`, `httpx`, `jinja2`, `websockets`).
    * Copia el código de la API a `/app` en el contenedor.
    * Expone el puerto `8000` (o el que use Uvicorn).
    * Comando `CMD`: `["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]`. Esto es crucial para que FastAPI funcione correctamente detrás de Caddy y genere URLs HTTPS.
* **Endpoints:** Proporciona la página de inicio, documentación (`/docs`, `/redoc`), y los endpoints funcionales para logs y gestión de jails.

### 5.5. Caddy (Host)
* **Archivo de Configuración:** `/etc/caddy/Caddyfile`.
* **Configuración Clave para el Dominio:**
    ```caddyfile
    tu-dominio.com { # Reemplazar con el dominio real (ej. alertasfail2ban.duckdns.org)
        reverse_proxy localhost:8000 # Reemplazar 8000 si API_PORT es diferente
    }
    ```
* **Funcionalidad:**
    * Sirve el dominio especificado.
    * Maneja automáticamente la obtención y renovación de certificados SSL/TLS de Let's Encrypt, proporcionando HTTPS.
    * Redirige automáticamente el tráfico HTTP a HTTPS.
    * Actúa como proxy inverso, reenviando el tráfico al contenedor de la API FastAPI.

## 6. Dominio y DNS

* **Proveedor y Dominio:**
    * Opción 1: DuckDNS (ej. `alertasfail2ban.duckdns.org`).
        * Un script (`/home/makuno/duckdns/duck.sh` o `/home/duckdns/duck.sh`) se ejecuta vía `cron` (configurado para el usuario `makuno` o `root` con la ruta correcta) cada 5 minutos para actualizar la IP en DuckDNS. El script usa el token y dominio correctos.
    * Opción 2: Dominio propio de Namecheap (ej. `midominiofail2ban.com`).
        * Se configuran registros `A` (y opcionalmente `CNAME` para `www`) en el panel de DNS de Namecheap para que apunten a la IP pública del Droplet.
* **HTTPS:** Gestionado íntegramente por Caddy utilizando certificados de Let's Encrypt.

## 7. Mantenimiento y Operación

* **Actualizar el Proyecto:**
    1.  En el Droplet, navegar al directorio del proyecto.
    2.  `git pull origin main` (o la rama correspondiente).
    3.  `docker compose up -d --build --force-recreate --remove-orphans` (para una actualización completa).
* **Ver Logs de Servicios:**
    * Docker: `docker compose logs <nombre_servicio>` (ej. `api`, `loki`, `promtail`).
    * Caddy: `sudo journalctl -u caddy -f --no-pager`.
    * Fail2ban: `sudo tail -f /var/log/fail2ban.log` o `sudo journalctl -u fail2ban -f`.
    * Script DuckDNS (si aplica): `cat /ruta/al/duck.log`.
* **Reiniciar Servicios:**
    * Docker Compose: `docker compose restart <nombre_servicio>` o `docker compose down && docker compose up -d`.
    * Servicios del Host: `sudo systemctl restart <nombre_servicio>` (ej. `caddy`, `fail2ban`, `docker`, `ssh`).
* **Verificar Inicio Automático al Arranque del Sistema:**
    * Servicios systemd (Caddy, Fail2ban, Docker, SSH): `sudo systemctl is-enabled <nombre_servicio>`. Deben estar `enabled`. Si no, usar `sudo systemctl enable <nombre_servicio>`.
    * Contenedores Docker: Deben tener `restart: unless-stopped` (o `always`) en el archivo `docker-compose.yaml`.

## 8. Consideraciones de Seguridad Adicionales

* **CORS en API:** La configuración actual de `allow_origins=["*"]` es permisiva. Para producción, debería restringirse al dominio específico del frontend que consumirá la API.
* **Autenticación de API:** La API actualmente no implementa autenticación de usuarios o tokens. Si va a ser expuesta o usada por múltiples clientes/aplicaciones, se debería considerar añadir una capa de autenticación (ej. tokens JWT, OAuth2).
* **Autenticación de Loki:** Actualmente `auth_enabled: false`. Dado que Loki solo es accesible internamente por la API y Promtail dentro de la red Docker, esto es aceptable. Si se fuera a exponer Loki directamente (no recomendado), se debería habilitar la autenticación.
* **Actualizaciones de Seguridad del SO y Paquetes:** Es crucial mantener el sistema operativo Ubuntu y todos los paquetes instalados actualizados regularmente para mitigar vulnerabilidades.
* **Backup de Datos de Loki:** Si la persistencia a largo plazo de los logs de Fail2ban es crítica, se debe implementar una estrategia de backup para el volumen Docker `loki_data`.
* **Revisión de Permisos:** Asegurar que los archivos y directorios tengan los permisos mínimos necesarios.
* **Monitoreo de Recursos del Droplet:** Vigilar el uso de CPU, memoria y disco para asegurar que el Droplet no se sobrecargue.

---
