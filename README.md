# Dashboard de Monitoreo de Logs de Fail2ban

Este proyecto implementa un sistema para recolectar, almacenar y visualizar logs del servicio Fail2ban utilizando Promtail, Loki, una API FastAPI personalizada y un dashboard interactivo en NextJS (frontend no incluido en esta configuración).

## Arquitectura del Servidor

1.  **Fail2ban**: (Se asume instalado y configurado en el servidor host) Genera logs de actividad y gestiona baneos.
2.  **Promtail**: Recolecta los logs de Fail2ban y los envía a Loki.
3.  **Loki**: Almacena y permite consultar los logs.
4.  **API (FastAPI)**: Expone endpoints para:
    * Consultar logs de Fail2ban desde Loki.
    * Listar jails activos de Fail2ban.
    * Bloquear direcciones IP usando Fail2ban.
    * Desbloquear direcciones IP usando Fail2ban.

## Prerrequisitos

* Docker
* Docker Compose (v1.27+ o Docker Compose V2)
* Git
* Fail2ban instalado y corriendo en la máquina host, generando logs en la ruta especificada en `.env` (por defecto `/var/log/fail2ban.log`) y con su socket de control accesible (por defecto `/var/run/fail2ban/fail2ban.sock`).

## Configuración Inicial

1.  **Clonar el repositorio:**
    ```bash
    git clone <URL_DEL_REPOSITORIO>
    cd fail2ban-dashboard-monitoring
    ```

2.  **Configurar Variables de Entorno:**
    Copia el archivo de ejemplo `.env.example` a `.env`:
    ```bash
    cp .env.example .env
    ```
    Edita el archivo `.env` y ajusta las variables según tu entorno. La más importante a verificar es `FAIL2BAN_LOG_PATH`.

3.  **Verificar Ruta del Socket de Fail2ban:**
    El archivo `docker-compose.yaml` monta `/var/run/fail2ban/fail2ban.sock` del host al contenedor de la API. Si tu socket de Fail2ban está en una ruta diferente en el host, actualiza esta ruta en `docker-compose.yaml` para el servicio `api`.

## Ejecución

1.  **Construir y levantar los servicios con Docker Compose:**
    Desde la raíz del proyecto, ejecuta:
    ```bash
    docker-compose up -d --build
    ```
    Esto construirá las imágenes necesarias (para la API) y levantará todos los servicios en segundo plano (`-d`).

2.  **Verificar los servicios:**
    * **Loki**: Debería estar accesible en `http://localhost:<LOKI_PORT>` (ej. `http://localhost:3100`).
    * **Promtail**: Puedes verificar sus logs con `docker-compose logs promtail`.
    * **API**: Debería estar accesible en `http://localhost:<API_PORT>` (ej. `http://localhost:8000`).
        * Health check: `GET http://localhost:8000/health`
        * Ver documentación de la API interactiva: `http://localhost:8000/docs`

## API Endpoints

Accede a `http://localhost:<API_PORT>/docs` para la documentación interactiva de Swagger UI.

### Logs
* **`GET /fail2ban-logs`**: Obtiene los logs de Fail2ban.
    * Query params: `start` (timestamp), `end` (timestamp), `limit` (int).

### Gestión de Fail2ban

**Importante:** Para que los endpoints de gestión de baneos funcionen:
1.  El paquete `fail2ban` debe estar instalado en el contenedor de la API (gestionado por el `Dockerfile`).
2.  El socket de control de Fail2ban del host (ej. `/var/run/fail2ban/fail2ban.sock`) debe estar correctamente montado en el contenedor de la API en la misma ruta (gestionado por `docker-compose.yaml`).
3.  El usuario que ejecuta el demonio Docker (o el propio demonio Docker) debe tener los permisos necesarios para acceder a dicho socket en el host.

* **`GET /jails`**: Obtiene una lista de los nombres de los jails activos en Fail2ban.
    * Respuesta Ejemplo: `["sshd", "apache-badbots"]`

* **`POST /jails/{jail_name}/ban-ip`**: Bloquea una dirección IP en un jail específico.
    * Path param: `jail_name` (ej. `sshd`).
    * Request Body (JSON): `{"ip_address": "1.2.3.4"}`
    * Respuesta: Información sobre la acción y salida del comando.

* **`POST /jails/{jail_name}/unban-ip`**: Desbloquea una dirección IP en un jail específico.
    * Path param: `jail_name` (ej. `sshd`).
    * Request Body (JSON): `{"ip_address": "1.2.3.4"}`
    * Respuesta: Información sobre la acción y salida del comando.

## Detener los servicios

```bash
docker-compose down