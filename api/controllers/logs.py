from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from httpx import AsyncClient, RequestError, HTTPStatusError
from configuration.settings import settings
import asyncio
import time
import re

router = APIRouter()

# web socket para recibir logs de fail2ban en tiempo real
@router.websocket("/ws/fail2ban-logs")
async def websocket_fail2ban_logs(websocket: WebSocket):
    await websocket.accept()
    last_timestamp = None

    try:
        while True:
            params = {
                "query": '{job="fail2ban"}',
                "limit": 100,
            }

            if last_timestamp:
                params["start"] = str(int(last_timestamp) + 1)

            async with AsyncClient() as client:
                try:
                    response = await client.get(settings.LOKI_QUERY_URL, params=params, timeout=10.0)
                    response.raise_for_status()
                except (RequestError, HTTPStatusError) as exc:
                    await websocket.send_json({"error": f"Error al contactar Loki: {str(exc)}"})
                    await asyncio.sleep(5)
                    continue

            data = response.json().get("data", {})
            results = data.get("result", [])

            for stream in results:
                labels = stream.get("stream", {})
                service = labels.get("job", "desconocido")
                level = labels.get("level", "info")

                for ts, line in stream.get("values", []):
                    last_timestamp = ts
                    message_data = {
                        "timestamp": ts,
                        "service": service,
                        "message": line,
                        "level": level,
                    }
                    await websocket.send_json(message_data)

            await asyncio.sleep(5)

    except WebSocketDisconnect:
        print("Cliente desconectado")
    except Exception as e:
        await websocket.send_json({"error": f"Error inesperado: {str(e)}"})
        await websocket.close()

# Ruta pa obtener las ips baneadas
@router.get("/fail2ban/banned-ips")
async def get_banned_ips(
    page: int = Query(0, ge=0, description="Número de página."),
    size: int = Query(10, ge=1, le=100, description="Tamaño de página."),
):
    start = int(time.time() - 3600) * 1_000_000_000  # último 1 hora en ns
    params = {
        "query": '{job="fail2ban"} |= "Ban"',
        "start": str(start),
        "limit": size * (page + 1),
    }

    async with AsyncClient() as client:
        try:
            response = await client.get(settings.LOKI_QUERY_URL, params=params, timeout=10.0)
            response.raise_for_status()
        except (RequestError, HTTPStatusError) as exc:
            raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {str(exc)}")

    results = response.json().get("data", {}).get("result", [])
    entries = []

    for stream in results:
        labels = stream.get("stream", {})
        for ts, line in stream.get("values", []):
            match = re.search(r"Ban (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                jail = labels.get("jail", "desconocido")
                ban_time = ts
                # opcional: buscar intentos fallidos si están en el mensaje
                attempts_match = re.search(r"(\d+) failed", line)
                failed_attempts = int(attempts_match.group(1)) if attempts_match else None

                entries.append({
                    "ip": ip,
                    "jail": jail,
                    "ban_time": ban_time,
                    "failed_attempts": failed_attempts
                })

    # aplicar paginación
    start_idx = page * size
    end_idx = start_idx + size
    return entries[start_idx:end_idx]

@router.get("/fail2ban/logs")
async def get_filtered_logs(
    page: int = Query(0, ge=0),
    size: int = Query(10, ge=1, le=100),
    start: int = Query(None, description="Inicio del rango de tiempo (timestamp en ns)."),
    end: int = Query(None, description="Fin del rango de tiempo (timestamp en ns)."),
    service: str = Query(None, description="Nombre del servicio."),
    level: str = Query(None, description="Nivel del log (info, error, warning, etc)."),
    event_type: str = Query(None, description="Texto a buscar en el mensaje del log."),
):
    query = '{job="fail2ban"}'
    if service:
        query = f'{query},job="{service}"'
    if level:
        query += f' |= "{level}"'
    if event_type:
        query += f' |= "{event_type}"'

    params = {
        "query": query,
        "limit": size * (page + 1),
    }
    if start:
        params["start"] = str(start)
    if end:
        params["end"] = str(end)

    async with AsyncClient() as client:
        try:
            response = await client.get(settings.LOKI_QUERY_URL, params=params, timeout=10.0)
            response.raise_for_status()
        except (RequestError, HTTPStatusError) as exc:
            raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {str(exc)}")

    results = response.json().get("data", {}).get("result", [])
    entries = []

    for stream in results:
        labels = stream.get("stream", {})
        service_name = labels.get("job", "desconocido")
        level_value = labels.get("level", "info")

        for ts, line in stream.get("values", []):
            entries.append({
                "timestamp": ts,
                "service": service_name,
                "message": line,
                "level": level_value
            })

    start_idx = page * size
    end_idx = start_idx + size
    return entries[start_idx:end_idx]