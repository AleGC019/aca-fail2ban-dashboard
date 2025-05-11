import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Body, Path
from fastapi.middleware.cors import CORSMiddleware
import httpx
from pydantic import BaseModel, Field
from typing import List, Optional
import subprocess
import re

# Carga .env en desarrollo local (Docker Compose inyecta vars también)
load_dotenv()

LOKI_QUERY_URL = os.getenv("LOKI_QUERY_URL")
if not LOKI_QUERY_URL:
    raise RuntimeError("La variable LOKI_QUERY_URL no está configurada")

FAIL2BAN_SOCKET_PATH = "/var/run/fail2ban/fail2ban.sock" # Ruta del socket dentro del contenedor

app = FastAPI(
    title="Fail2ban Log API",
    description="API para consultar logs de Fail2ban y gestionar baneos.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción, restringir
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# --- Modelos ---
class LogEntry(BaseModel):
    timestamp: str
    line: str
    labels: dict

class IPActionRequest(BaseModel):
    ip_address: str = Field(..., example="192.168.1.100", description="La dirección IP a bloquear o desbloquear.")

class ActionResponse(BaseModel):
    status: str
    message: str
    ip_address: Optional[str] = None
    jail: Optional[str] = None
    command_output: Optional[str] = None

# --- Funciones Auxiliares ---
def is_valid_ip(ip: str) -> bool:
    """Valida un formato de dirección IPV4."""
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

def run_fail2ban_command(command_args: List[str]) -> str:
    """Ejecuta un comando fail2ban-client y devuelve la salida."""
    try:
        # Comentado ya que el socket se monta, si no existe en host el montaje fallará antes.
        # if not os.path.exists(FAIL2BAN_SOCKET_PATH):
        #     raise HTTPException(status_code=500, detail=f"Fail2ban socket no encontrado en {FAIL2BAN_SOCKET_PATH}")

        base_command = ["fail2ban-client"]
        # Si el socket es diferente al por defecto que busca fail2ban-client, se podría añadir -s /path/to/socket
        # pero al montarlo en la ruta estándar dentro del contenedor, no debería ser necesario.
        
        process = subprocess.run(
            base_command + command_args,
            capture_output=True,
            text=True,
            check=False # Manejar errores manualmente basado en salida y código de retorno
        )

        if process.returncode != 0:
            # Para 'set jail unbanip <IP>' si la IP no está baneada, devuelve 255 y un mensaje.
            # Consideramos esto un "éxito" informativo, no un error de la API.
            if "is not banned" in process.stdout or "already banned" in process.stdout:
                 return process.stdout.strip() # Devolver el mensaje informativo
            # Otros errores
            error_message = process.stderr.strip() if process.stderr else process.stdout.strip()
            raise HTTPException(status_code=400, detail=f"Error ejecutando comando Fail2ban ({process.returncode}): {error_message}")

        return process.stdout.strip() if process.stdout else "Comando ejecutado. No hubo salida estándar."

    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="fail2ban-client no encontrado. Asegúrate de que está instalado y en el PATH del contenedor API.")
    except HTTPException: # Re-lanzar HTTPExceptions ya manejadas
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error inesperado al ejecutar comando Fail2ban: {str(e)}")

# --- Endpoints ---
@app.get("/health")
async def health():
    return {"status": "ok", "message": "API de Logs y Gestión de Fail2ban funcionando"}

@app.get("/fail2ban-logs", response_model=List[LogEntry])
async def get_fail2ban_logs(
    start: Optional[str] = Query(None, description="RFC3339 o timestamp UNIX (ns) para el inicio del rango de tiempo."),
    end: Optional[str] = Query(None, description="RFC3339 o timestamp UNIX (ns) para el fin del rango de tiempo."),
    limit: int = Query(100, ge=1, le=1000, description="Número máximo de entradas de log a devolver."),
):
    params = {
        "query": '{job="fail2ban"}',
        "limit": limit,
    }
    if start:
        params["start"] = start
    if end:
        params["end"] = end

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(LOKI_QUERY_URL, params=params, timeout=10.0)
            resp.raise_for_status() # Lanza excepción para códigos de error HTTP 4xx/5xx
        except httpx.RequestError as exc:
            raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {exc}")
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=f"Error de Loki: {exc.response.text}")

    raw_data = resp.json().get("data", {})
    if not raw_data or "result" not in raw_data:
        raise HTTPException(status_code=500, detail="Respuesta de Loki inválida o sin datos 'result'.")
        
    raw_result = raw_data.get("result", [])
    entries: List[LogEntry] = []
    for stream in raw_result:
        labels = stream.get("stream", {})
        for ts, line in stream.get("values", []):
            entries.append(LogEntry(timestamp=ts, line=line, labels=labels))
    
    return entries

@app.post("/jails/{jail_name}/ban-ip", response_model=ActionResponse)
async def ban_ip_in_jail(
    jail_name: str = Path(..., description="El nombre del jail de Fail2ban (ej. 'sshd')."),
    request_body: IPActionRequest = Body(...)
):
    if not is_valid_ip(request_body.ip_address):
        raise HTTPException(status_code=400, detail="Formato de dirección IP inválido.")
    
    try:
        output = run_fail2ban_command(["set", jail_name, "banip", request_body.ip_address])
        return ActionResponse(
            status="success",
            message=f"Solicitud de baneo para IP {request_body.ip_address} en jail '{jail_name}' procesada.",
            ip_address=request_body.ip_address,
            jail=jail_name,
            command_output=output
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/jails/{jail_name}/unban-ip", response_model=ActionResponse)
async def unban_ip_in_jail(
    jail_name: str = Path(..., description="El nombre del jail de Fail2ban (ej. 'sshd')."),
    request_body: IPActionRequest = Body(...)
):
    if not is_valid_ip(request_body.ip_address):
        raise HTTPException(status_code=400, detail="Formato de dirección IP inválido.")

    try:
        output = run_fail2ban_command(["set", jail_name, "unbanip", request_body.ip_address])
        return ActionResponse(
            status="success",
            message=f"Solicitud de desbaneo para IP {request_body.ip_address} en jail '{jail_name}' procesada.",
            ip_address=request_body.ip_address,
            jail=jail_name,
            command_output=output
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/jails", response_model=List[str])
async def get_jails():
    """Obtiene una lista de los nombres de los jails activos en Fail2ban."""
    try:
        raw_output = run_fail2ban_command(["status"])
        jail_list_line = [line for line in raw_output.split('\n') if "Jail list:" in line]
        
        if not jail_list_line:
            if "Currently no jail is activated" in raw_output or "Sorry but currently no jails are activated" in raw_output : # Ajustado para posibles variaciones de mensaje
                return []
            raise HTTPException(status_code=500, detail=f"No se pudo parsear la lista de jails de la salida. Salida recibida: {raw_output}")

        jails_str = jail_list_line[0].split("Jail list:")[1].strip()
        if not jails_str: # Si después de "Jail list:" no hay nada
            return []
        return [jail.strip() for jail in jails_str.split(',') if jail.strip()]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener la lista de jails: {str(e)}")

# Para ejecutar localmente sin Docker (para desarrollo)
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)