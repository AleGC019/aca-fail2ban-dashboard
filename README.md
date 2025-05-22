# 📄 Documentación del Servidor y Proyecto de Monitoreo Fail2ban

**🗓️ Fecha de Documentación:** 21 de mayo de 2025
**🏷️ Proyecto:** API y Backend para Dashboard de Monitoreo de Logs de Fail2ban
**☁️ Proveedor de VM:** DigitalOcean Droplet
**🐧 Sistema Operativo:** Ubuntu (ej. 22.04 LTS)
**🌐 Dominio Principal:** `alertasfail2ban.xmakuno.com` (Registrado en Namecheap)

## 1. 🗺️ Descripción General del Servidor

Este Droplet de DigitalOcean aloja el backend completo para el sistema de monitoreo de logs de Fail2ban. Los componentes principales y su interacción son:

* **🛡️ Fail2ban (Host):** Se ejecuta directamente en el sistema operativo del Droplet. Monitorea los logs de servicios (como SSH) y aplica baneos de IP basados en reglas predefinidas.
* **📜 Promtail (Contenedor Docker):** Actúa como un agente recolector de logs. Lee los logs generados por Fail2ban en el host y los envía a Loki.
* **🗄️ Loki (Contenedor Docker):** Es el sistema de agregación y almacenamiento de logs. Recibe los logs de Promtail, los indexa y permite su consulta.
* **⚙️ API FastAPI (Contenedor Docker):** Es el backend principal desarrollado en Python. Proporciona endpoints HTTP para:
    * Consultar logs de Fail2ban almacenados en Loki.
    * Gestionar baneos de Fail2ban (listar jails, banear/desbanear IPs) interactuando con el `fail2ban-client` del host.
    * Servir una página de inicio HTML.
    * Proporcionar un stream de logs en tiempo real a través de WebSockets (haciendo proxy al endpoint `/tail` de Loki).
* **🔒 Caddy (Host):** Actúa como un servidor web y proxy inverso. Se ejecuta directamente en el Droplet. Gestiona automáticamente los certificados SSL/TLS de Let's Encrypt para el dominio configurado, proporcionando HTTPS, y redirige el tráfico al contenedor de la API FastAPI.
* **🐳 Docker y Docker Compose:** Utilizados para definir, construir y orquestar los servicios en contenedores (Promtail, Loki, API).

## 2. 🛠️ Configuración Inicial del Droplet y Seguridad

### 2.1. 👤 Usuario No-Root con Privilegios `sudo`
* Se ha creado un usuario principal no-root (ej. `makuno`) para las operaciones diarias y la gestión del proyecto.
* Este usuario pertenece al grupo `sudo`, permitiéndole ejecutar comandos administrativos.
    * Creación: `sudo adduser makuno`
    * Añadir a sudo: `sudo usermod -aG sudo makuno`

### 2.2. 🔑 Autenticación por Clave SSH
* El acceso SSH al Droplet para el usuario `makuno` está configurado para usar **exclusivamente claves SSH**.
* La autenticación por contraseña para SSH ha sido **deshabilitada** en el archivo `/etc/ssh/sshd_config`:
    ```
    PasswordAuthentication no
    ChallengeResponseAuthentication no
    ```
* **Recomendación Importante:** El inicio de sesión directo de `root` por SSH debería estar deshabilitado (`PermitRootLogin no`) o, como mínimo, restringido a `PermitRootLogin prohibit-password` (solo clave SSH para root).

### 2.3. 🔥 Firewall
* **Cloud Firewall de DigitalOcean:** Es la primera línea de defensa y controla el tráfico entrante al Droplet.
    * **Puerto `22/TCP` (SSH):** Abierto. *Idealmente, restringido a direcciones IP de confianza si es posible.*
    * **Puerto `80/TCP` (HTTP):** Abierto a `All IPv4` y `All IPv6` (o `0.0.0.0/0, ::/0`). Necesario para la validación HTTP-01 de Let's Encrypt por Caddy.
    * **Puerto `443/TCP` (HTTPS):** Abierto a `All IPv4` y `All IPv6`. Para el tráfico de la API a través de Caddy.
    * **Puerto de la API (ej. `8000/TCP`):**
        > **Importante:** Este puerto, donde escucha la API FastAPI dentro de Docker y es mapeado al host, **NO debe estar abierto al público en el Cloud Firewall**. Caddy accede a este puerto localmente en el Droplet.

* **`ufw` (Firewall del Sistema Operativo - Opcional):** Si se utiliza `ufw` en el Droplet, debe estar configurado para permitir el tráfico necesario (mínimo SSH en el puerto 22, y los puertos 80 y 443 para Caddy). El Cloud Firewall suele ser suficiente y más fácil de gestionar centralizadamente.

### 2.4. 🔄 Actualizaciones del Sistema
* El sistema operativo Ubuntu y sus paquetes se mantienen actualizados ejecutando regularmente:
    ```bash
    sudo apt update && sudo apt upgrade -y
    ```

### 2.5. ⏰ Zona Horaria del Servidor
* El servidor está configurado para usar la zona horaria **UTC** por defecto.
    * Verificar con: `date` o `timedatectl`.
* **Consideración:** Al revisar logs, es importante tener en cuenta la diferencia horaria con la zona horaria local del usuario (ej. Centroamérica UTC-6).

## 3. 📦 Software Esencial Instalado en el Host del Droplet

* **Git:** Para la gestión del código fuente del proyecto.
    * Instalación: `sudo apt install git -y`
* **Docker Engine:** Plataforma de contenedores.
    * Instalación: `sudo apt install docker.io -y`
    * Servicio: Habilitado para iniciar al arranque (`sudo systemctl enable docker && sudo systemctl start docker`).
    * El usuario no-root (`makuno`) ha sido añadido al grupo `docker` para ejecutar comandos Docker sin `sudo` (`sudo usermod -aG docker makuno`, requiere nuevo login).
* **Docker Compose V2:** Herramienta para definir y ejecutar aplicaciones Docker multi-contenedor.
    * Instalación: `sudo apt install docker-compose-v2 -y` (o el método de plugin para Docker).
    * Uso: `docker compose ...` (ej. `docker compose up -d`).
* **Fail2ban:** Servicio de prevención de intrusiones.
    * Instalación: `sudo apt install fail2ban -y`
    * Servicio: Habilitado para iniciar al arranque (`sudo systemctl enable fail2ban && sudo systemctl start fail2ban`).
* **Caddy v2:** Servidor web moderno y proxy inverso con HTTPS automático.
    * Instalación: Siguiendo la guía oficial de Caddy para Ubuntu (usando su repositorio APT).
    * Servicio: Habilitado para iniciar al arranque (`sudo systemctl enable caddy && sudo systemctl start caddy`).

## 4. 🚀 Despliegue del Proyecto

1.  **Clonación del Repositorio:**
    * El código del proyecto (API, Dockerfile, docker-compose.yaml, configs de Loki/Promtail) se clona desde un repositorio Git en un directorio del usuario no-root (ej. `/home/makuno/aca-fail2ban-dashboard`).

2.  **Archivo de Entorno `.env`:**
    * Ubicado en la raíz del directorio del proyecto clonado.
    * Creado a partir de un archivo `_env.example_` (o similar).
    * **Variables de entorno críticas definidas:**
        * `LOKI_QUERY_URL=http://loki:3100/loki/api/v1/query_range`
        * `LOKI_WS_URL=ws://loki:3100/loki/api/v1/tail`
        * `FAIL2BAN_LOG_PATH=/var/log/fail2ban.log` (o la ruta real del log de Fail2ban en el Droplet).
        * `API_PORT=8000` (puerto en el host al que se mapea el contenedor de la API).
        * `LOKI_PORT=3100` (puerto en el host al que se mapea el contenedor de Loki, si se expone directamente).
    > **Nota:** Es crucial que el archivo `.env` esté presente y correctamente configurado antes de iniciar los servicios.

3.  **Ejecución de Servicios con Docker Compose:**
    * Desde el directorio raíz del proyecto (donde está `docker-compose.yaml`):
        ```bash
        docker compose up -d --build
        ```
    * Esto construye la imagen de la API si es necesario y levanta los servicios `api`, `loki`, y `promtail` en modo detached.
    * Todos los servicios Docker tienen configurada la política `restart: unless-stopped` en `docker-compose.yaml` para asegurar que se inicien automáticamente si el Droplet se reinicia o si el servicio Docker se reinicia.

## 5. ⚙️ Configuración de Servicios Detallada

### 5.1. Fail2ban (Host)
* **Configuración Local:** Principalmente en `/etc/fail2ban/jail.local` (o archivos dentro de `/etc/fail2ban/jail.d/`). Se recomienda usar `jail.local` para sobreescribir o añadir configuraciones de `jail.conf` sin modificar el archivo original.
* **Jails Activos:** Mínimo `[sshd]` para proteger el acceso SSH. Otros jails pueden estar configurados para servicios adicionales (ej. para Caddy si se detectan muchos errores 4xx).
* **Log de Fail2ban:** Escribe en la ruta especificada por `FAIL2BAN_LOG_PATH` (ej. `/var/log/fail2ban.log`). Esta ruta se monta como volumen en el contenedor de Promtail.
* **`ignoreip`:**
    > **¡Muy Importante!** Añadir las direcciones IP estáticas de los administradores/desarrolladores en la directiva `ignoreip` (dentro de `[DEFAULT]` o en jails específicos) para evitar auto-baneos durante el desarrollo y las pruebas.
* **Socket para `fail2ban-client`:** El socket `/var/run/fail2ban/fail2ban.sock` del host se monta como volumen en el contenedor de la API para permitir la interacción con `fail2ban-client` desde la API.

### 5.2. Promtail (Contenedor Docker)
* **Archivo de Configuración:** Montado desde `promtail/promtail.yaml` del repositorio.
* **Puntos Clave de Configuración:**
    * `server`: Define `http_listen_port` y `grpc_listen_port` internos.
    * `positions`: `/tmp/positions.yaml` (dentro del contenedor, para guardar el progreso de lectura de logs).
    * `clients`: `url: ${LOKI_PUSH_URL}` (usa la variable de entorno, que apunta a `http://loki:3100/loki/api/v1/push`).
    * `scrape_configs`:
        * `job_name: fail2ban`.
        * `static_configs`: `labels: { job: "fail2ban", __path__: "${FAIL2BAN_LOG_PATH}" }`.
        * `pipeline_stages`: Incluye `multiline`, `regex` (para parsear los logs y extraer campos como `time`, `component`, `pid`, `level`, `jail`, `msg`), `timestamp`, `labels` (crea etiquetas en Loki para `component`, `pid`, `level`, `jail`), y `output`.

### 5.3. Loki (Contenedor Docker)
* **Archivo de Configuración:** Montado desde `loki/config.yaml` del repositorio.
* **Puntos Clave de Configuración:**
    * `auth_enabled: false` (para simplificar la comunicación interna en la red Docker).
    * `server.http_listen_port: 3100`.
    * `storage_config`, `common.storage`, `schema_config`: Configurado para `boltdb-shipper` y `filesystem`, con almacenamiento en `/loki` dentro del contenedor.
* **Persistencia de Datos:** A través del volumen Docker nombrado `loki_data`, mapeado a `/loki` dentro del contenedor.
* **Endpoints de API Relevantes para nuestra API:**
    * `/loki/api/v1/query_range`: Usado por la API FastAPI para consultas HTTP.
    * `/loki/api/v1/tail`: Usado por la API FastAPI para el streaming de logs vía WebSocket.

### 5.4. API FastAPI (Contenedor Docker)
* **Estructura del Proyecto:** Organizada en `main.py`, `controllers/`, `services/`, `data/`, `configuration/`, `static/`, `templates/`.
* **`main.py`:**
    * Inicializa la aplicación FastAPI.
    * Configura CORS (actualmente permisivo con `allow_origins=["*"]`).
    * Monta el directorio `static/` para servir archivos CSS.
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
    alertasfail2ban.xmakuno.com { # O el dominio configurado
        reverse_proxy localhost:8000 # O el API_PORT configurado
    }
    ```
* **Funcionalidad:**
    * Sirve el dominio especificado.
    * Maneja automáticamente la obtención y renovación de certificados SSL/TLS de Let's Encrypt, proporcionando HTTPS.
    * Redirige automáticamente el tráfico HTTP a HTTPS.
    * Actúa como proxy inverso, reenviando el tráfico al contenedor de la API FastAPI.

## 6. 🌐 Dominio y DNS

* **Proveedor y Dominio:** Namecheap (`alertasfail2ban.xmakuno.com`).
    * Se configuran registros `A` (para `@` y opcionalmente para `api` si se usa un subdominio como `api.alertasfail2ban.xmakuno.com`) en el panel de DNS de Namecheap para que apunten a la IP pública del Droplet.
    * Se puede configurar un registro `CNAME` para `www` apuntando al dominio raíz (ej. `alertasfail2ban.xmakuno.com`).
    * Ya no se utiliza el script de actualización de DuckDNS si el dominio principal es de Namecheap y la IP del Droplet es estática.
* **HTTPS:** Gestionado íntegramente por Caddy utilizando certificados de Let's Encrypt.

## 7. 🛠️ Mantenimiento y Operación

* **Actualizar el Proyecto:**
    1.  En el Droplet, navegar al directorio del proyecto.
    2.  `git pull origin main` (o la rama correspondiente).
    3.  `docker compose up -d --build --force-recreate --remove-orphans` (para una actualización completa y limpia).
* **Ver Logs de Servicios:**
    * Docker: `docker compose logs <nombre_servicio>` (ej. `api`, `loki`, `promtail`).
    * Caddy: `sudo journalctl -u caddy -f --no-pager`.
    * Fail2ban: `sudo tail -f /var/log/fail2ban.log` o `sudo journalctl -u fail2ban -f`.
* **Reiniciar Servicios:**
    * Docker Compose: `docker compose restart <nombre_servicio>` o `docker compose down && docker compose up -d`.
    * Servicios del Host: `sudo systemctl restart <nombre_servicio>` (ej. `caddy`, `fail2ban`, `docker`, `ssh`).
* **Verificar Inicio Automático al Arranque del Sistema:**
    * Servicios systemd (Caddy, Fail2ban, Docker, SSH): `sudo systemctl is-enabled <nombre_servicio>`. Deben estar `enabled`. Si no, usar `sudo systemctl enable <nombre_servicio>`.
    * Contenedores Docker: Deben tener `restart: unless-stopped` (o `always`) en el archivo `docker-compose.yaml`.
* **Uso de Disco:**
    * Revisar periódicamente el uso de disco: `df -h`.
    * Prestar atención al volumen de Loki (`loki_data`), ya que los logs pueden crecer. Considerar políticas de retención en Loki.

## 8. 🔐 Consideraciones de Seguridad Adicionales

* **CORS en API:** La configuración actual de `allow_origins=["*"]` es permisiva.
    > Para producción, debería restringirse al dominio específico del frontend que consumirá la API.
* **Autenticación de API:** La API actualmente no implementa autenticación de usuarios o tokens.
    > Si va a ser expuesta o usada por múltiples clientes/aplicaciones, se debería considerar añadir una capa de autenticación (ej. tokens JWT, OAuth2).
* **Autenticación de Loki:** Actualmente `auth_enabled: false`. Dado que Loki solo es accesible internamente por la API y Promtail dentro de la red Docker, esto es aceptable. Si se fuera a exponer Loki directamente (no recomendado), se debería habilitar la autenticación.
* **Actualizaciones de Seguridad del SO y Paquetes:** Es crucial mantener el sistema operativo Ubuntu y todos los paquetes instalados actualizados regularmente para mitigar vulnerabilidades.
* **Backup de Datos de Loki:** Si la persistencia a largo plazo de los logs de Fail2ban es crítica, se debe implementar una estrategia de backup para el volumen Docker `loki_data`.
* **Revisión de Permisos:** Asegurar que los archivos y directorios tengan los permisos mínimos necesarios.
* **Monitoreo de Recursos del Droplet:** Vigilar el uso de CPU, memoria y disco para asegurar que el Droplet no se sobrecargue.
* **Seguridad de Fail2ban:** Revisar y ajustar las reglas de los jails de Fail2ban para que sean efectivas pero no demasiado agresivas con tráfico legítimo.

## 9. 🩺 Troubleshooting Común

* **"No se puede encontrar el servidor" / Problemas de DNS:**
    * Verificar que el dominio en Namecheap apunta a la IP correcta del Droplet.
    * Esperar la propagación del DNS (puede tardar).
    * Limpiar caché de DNS local en el dispositivo cliente.
    * Probar con DNS públicos (Google `8.8.8.8`, Cloudflare `1.1.1.1`) en el dispositivo cliente.
* **Sitio no carga con HTTPS / Errores de Certificado:**
    * Verificar que los puertos 80 y 443 estén abiertos en el Cloud Firewall de DigitalOcean.
    * Revisar los logs de Caddy (`sudo journalctl -u caddy`) para errores en la obtención/renovación de certificados. Asegurarse de que Caddy pueda alcanzar los servidores de Let's Encrypt.
    * Verificar que el nombre de dominio en el `Caddyfile` sea exacto.
* **API no responde o devuelve errores 5xx:**
    * Revisar los logs del contenedor de la API: `docker compose logs api`.
    * Verificar que el contenedor de la API esté corriendo: `docker compose ps`.
    * Asegurarse de que Caddy esté haciendo proxy al puerto correcto donde la API escucha (ej. `localhost:8000`).
    * Revisar si hay problemas de recursos en el Droplet (CPU, memoria).
* **Logs no aparecen en Loki / API:**
    * Verificar logs de Promtail: `docker compose logs promtail`. Buscar errores de conexión a Loki o problemas para leer el archivo de log de Fail2ban.
    * Asegurarse de que `FAIL2BAN_LOG_PATH` en `.env` sea correcto y que el volumen esté bien montado en Promtail.
    * Verificar logs de Loki: `docker compose logs loki`.
* **Acceso SSH bloqueado:**
    * Verificar si Fail2ban ha baneado tu IP: Acceder vía consola de DigitalOcean y ejecutar `sudo fail2ban-client status sshd`.
    * Desbanear IP: `sudo fail2ban-client set sshd unbanip <TU_IP>`
    * Añadir IP a `ignoreip` en `/etc/fail2ban/jail.local` y reiniciar Fail2ban.

## 10. 🚀 Mejoras Futuras / Próximos Pasos

* **Frontend Dashboard:** Desarrollar la interfaz de usuario en NextJS para consumir la API y visualizar los datos.
* **Autenticación para la API:** Implementar un sistema de autenticación (ej. JWT) si la API necesita ser protegida.
* **Alertas Avanzadas:** Configurar alertas en Loki/Grafana (si se añade Grafana) o a través de la API para notificar sobre eventos críticos de Fail2ban.
* **Backups:**
    * Configurar backups regulares del Droplet.
    * Implementar una estrategia de backup para el volumen `loki_data` si los logs son críticos.
* **Optimización de Recursos:** Monitorizar y ajustar la configuración de Loki (retención, indexación) y otros servicios para un uso eficiente de los recursos.
* **Configuración de Jails de Fail2ban más Específicos:** Añadir jails para proteger otros servicios que puedan estar corriendo en el Droplet o incluso para la propia API si se detectan patrones de abuso.
* **Pruebas Unitarias y de Integración:** Para la API FastAPI.

---
