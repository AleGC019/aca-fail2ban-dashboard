# controllers/logs.py

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from httpx import AsyncClient, RequestError, HTTPStatusError
# --- CAMBIO AQUÍ ---
# Se importa LOKI_QUERY_URL directamente, no 'settings'
from configuration.settings import settings
# -------------------
import asyncio

import time
import re
from typing import Optional  # Añadido Optional para claridad si se usa
from datetime import datetime
import math
from datetime import timedelta
import websockets
from urllib.parse import urlencode
from starlette.websockets import WebSocketState
from collections import defaultdict, Counter
import json

# Importaciones necesarias que podrían faltar según el contexto completo
# Asegúrate de que estas u otras dependencias necesarias estén aquí si las usas en otras partes del archivo
# from data.models import LogEntry # Necesario si devuelves este modelo en alguna ruta de este archivo
# from services.loki import query_loki # Necesario si llamas a esta función aquí

router = APIRouter()


# --- INICIO: Código de la versión más completa de controllers/logs.py ---
@router.websocket("/ws/fail2ban-logs")
async def websocket_fail2ban_logs_stream(
    websocket: WebSocket,
    limit: int = Query(10, description="Líneas iniciales."),
    start: Optional[int] = Query(None, description="Timestamp UNIX en ns para inicio.")
):
    await websocket.accept()
    client_host = websocket.client.host
    client_port = websocket.client.port
    print(f"Cliente WebSocket {client_host}:{client_port} conectado a /ws/fail2ban-logs-stream")

    logql_query = '{job="fail2ban"}'
    query_params_dict = {"query": logql_query, "limit": str(limit)}
    if start:
        query_params_dict["start"] = str(start)
    loki_target_ws_url = f"{settings.LOKI_WS_URL}?{urlencode(query_params_dict)}"

    try:
        async with websockets.connect(loki_target_ws_url) as loki_ws_client:
            print(f"Conectado al WebSocket de Loki: {loki_target_ws_url}")

            async def loki_to_client_task():
                try:
                    async for message_from_loki in loki_ws_client:
                        import json
                        data = json.loads(message_from_loki)
                        if "streams" in data and data["streams"]:
                            for stream in data["streams"]:
                                labels = stream.get("stream", {})
                                service = labels.get("job", "desconocido")
                                for ts, line in stream.get("values", []):
                                    # Extract log level
                                    import re
                                    level_match = re.search(r"]:\s*(\w+)", line)
                                    level = level_match.group(1).upper() if level_match else "INFO"
                                    level_importance_map = {
                                        "CRITICAL": "alta",
                                        "ERROR": "alta",
                                        "WARNING": "media",
                                        "INFO": "baja",
                                        "DEBUG": "baja"
                                    }
                                    importance = level_importance_map.get(level, "baja")
                                    # Format timestamp
                                    from datetime import datetime
                                    try:
                                        dt = datetime.fromtimestamp(int(ts) / 1_000_000_000)
                                        timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                                    except Exception:
                                        timestamp = ts
                                    message_data = {
                                        "timestamp": timestamp,
                                        "service": service,
                                        "message": line,
                                        "level": level,
                                        "importance": importance,
                                    }
                                    await websocket.send_json(message_data)
                except websockets.exceptions.ConnectionClosedOK:
                    print(f"Conexión a Loki para {client_host}:{client_port} cerrada limpiamente por Loki.")
                except websockets.exceptions.ConnectionClosedError as e:
                    print(f"Conexión a Loki para {client_host}:{client_port} cerrada con error por Loki: {e}")
                    await websocket.close(code=e.code)
                except WebSocketDisconnect:
                    print(f"Cliente API {client_host}:{client_port} desconectado (en loki_to_client_task).")

            task_l2c = asyncio.create_task(loki_to_client_task())
            done, pending = await asyncio.wait([task_l2c], return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done:
                if task.exception():
                    raise task.exception()

    except websockets.exceptions.InvalidURI:
        err_msg = f"Error: URI de WebSocket de Loki inválida: {loki_target_ws_url}"
        print(err_msg)
        await websocket.send_json({"error": err_msg})
    except websockets.exceptions.WebSocketException as e:
        err_msg = f"No se pudo conectar al WebSocket de Loki en {loki_target_ws_url}: {type(e).__name__} - {e}"
        print(err_msg)
        await websocket.send_json({"error": err_msg})
    except WebSocketDisconnect:
        print(f"Cliente WebSocket {client_host}:{client_port} desconectado.")
    except Exception as e:
        err_msg = f"Error general en /ws/fail2ban-logs-stream para {client_host}:{client_port}: {type(e).__name__} - {e}"
        print(err_msg)
        try:
            if websocket.application_state != WebSocketState.DISCONNECTED:
                await websocket.send_json({"error": "Error interno del servidor en el stream de logs."})
        except Exception as send_err:
            print(f"No se pudo enviar mensaje de error final al WebSocket: {send_err}")
    finally:
        print(f"Cerrando WebSocket para {client_host}:{client_port} en /ws/fail2ban-logs-stream")

# nueva version del websocket, con los nuevos parametros solicitados
@router.websocket("/ws/fail2ban-logs-v2")
async def websocket_fail2ban_logs_stream_v2(
    websocket: WebSocket,
    limit: int = Query(10, description="Líneas iniciales."),
    start: Optional[int] = Query(None, description="Timestamp UNIX en ns para inicio.")
):
    await websocket.accept()
    client_host = websocket.client.host
    client_port = websocket.client.port
    print(f"Cliente WebSocket {client_host}:{client_port} conectado a /ws/fail2ban-logs-stream")

    logql_query = '{job="fail2ban"}'
    query_params_dict = {"query": logql_query, "limit": str(limit)}
    if start:
        query_params_dict["start"] = str(start)
    loki_target_ws_url = f"{settings.LOKI_WS_URL}?{urlencode(query_params_dict)}"

    # Estructuras de datos para agregaciones
    events_per_minute = defaultdict(lambda: {"Found": 0, "Ban": 0, "Unban": 0})
    detections_per_minute = defaultdict(int)
    ip_counts = Counter()
    found_timestamps = {}  # {ip: datetime} para rastrear el último "Found"
    time_diffs = []  # Lista de diferencias de tiempo entre "Found" y "Ban"
    THRESHOLD_ATTEMPTS = 5  # Umbral para alertas

    async def process_log_line(line, ts):
        """Procesa una línea de log y actualiza las estructuras de datos."""
        # Convertir timestamp de nanosegundos a datetime
        try:
            event_time = datetime.fromtimestamp(int(ts) / 1_000_000_000)
            minute_key = event_time.strftime("%H:%M")
        except Exception:
            return  # Saltar si el timestamp es inválido

        # Extraer tipo de evento e IP (ajusta la regex según tu formato de log)
        match = re.search(r"(Found|Ban|Unban)\s+(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            event_type, ip = match.groups()

            # Actualizar conteos
            events_per_minute[minute_key][event_type] += 1
            if event_type == "Found":
                detections_per_minute[minute_key] += 1
                ip_counts[ip] += 1
                found_timestamps[ip] = event_time
            elif event_type == "Ban" and ip in found_timestamps:
                found_time = found_timestamps[ip]
                time_diff = (event_time - found_time).total_seconds()
                time_diffs.append(time_diff)
                del found_timestamps[ip]  # Eliminar tras calcular

    async def send_aggregated_data():
        """Envía datos agregados cada 5 segundos."""
        while True:
            await asyncio.sleep(5)
            data = {
                "ban_unban_per_minute": [
                    {"minute": minute, "ban": counts["Ban"], "unban": counts["Unban"]}
                    for minute, counts in events_per_minute.items()
                ],
                "detections_per_minute": [
                    {"minute": minute, "count": count}
                    for minute, count in detections_per_minute.items()
                ],
                "top_ips": [
                    {"ip": ip, "detections": count}
                    for ip, count in ip_counts.most_common(5)
                ],
                "avg_detect_to_ban_sec": (
                    sum(time_diffs) / len(time_diffs) if time_diffs else 0
                ),
                "alerts": [
                    {"ip": ip, "attempts": count}
                    for ip, count in ip_counts.items() if count >= THRESHOLD_ATTEMPTS
                ]
            }
            try:
                await websocket.send_json(data)
            except WebSocketDisconnect:
                break

    try:
        async with websockets.connect(loki_target_ws_url) as loki_ws_client:
            print(f"Conectado al WebSocket de Loki: {loki_target_ws_url}")

            # Iniciar tarea para enviar datos agregados
            send_task = asyncio.create_task(send_aggregated_data())

            async def loki_to_client_task():
                try:
                    async for message_from_loki in loki_ws_client:
                        data = json.loads(message_from_loki)
                        if "streams" in data and data["streams"]:
                            for stream in data["streams"]:
                                for ts, line in stream.get("values", []):
                                    await process_log_line(line, ts)
                except websockets.exceptions.ConnectionClosedOK:
                    print(f"Conexión a Loki para {client_host}:{client_port} cerrada limpiamente por Loki.")
                except websockets.exceptions.ConnectionClosedError as e:
                    print(f"Conexión a Loki para {client_host}:{client_port} cerrada con error por Loki: {e}")
                    await websocket.close(code=e.code)
                except WebSocketDisconnect:
                    print(f"Cliente API {client_host}:{client_port} desconectado (en loki_to_client_task).")

            task_l2c = asyncio.create_task(loki_to_client_task())
            done, pending = await asyncio.wait(
                [task_l2c, send_task], return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            for task in done:
                if task.exception():
                    raise task.exception()

    except websockets.exceptions.InvalidURI:
        err_msg = f"Error: URI de WebSocket de Loki inválida: {loki_target_ws_url}"
        print(err_msg)
        await websocket.send_json({"error": err_msg})
    except websockets.exceptions.WebSocketException as e:
        err_msg = f"No se pudo conectar al WebSocket de Loki en {loki_target_ws_url}: {type(e).__name__} - {e}"
        print(err_msg)
        await websocket.send_json({"error": err_msg})
    except WebSocketDisconnect:
        print(f"Cliente WebSocket {client_host}:{client_port} desconectado.")
    except Exception as e:
        err_msg = f"Error general en /ws/fail2ban-logs-stream para {client_host}:{client_port}: {type(e).__name__} - {e}"
        print(err_msg)
        try:
            if websocket.application_state != WebSocketState.DISCONNECTED:
                await websocket.send_json({"error": "Error interno del servidor en el stream de logs."})
        except Exception as send_err:
            print(f"No se pudo enviar mensaje de error final al WebSocket: {send_err}")
    finally:
        print(f"Cerrando WebSocket para {client_host}:{client_port} en /ws/fail2ban-logs-stream")

@router.websocket("/ws/fail2ban-logs2")
async def websocket_fail2ban_logs(websocket: WebSocket):
    await websocket.accept()

    # Obtener timestamp de hace 24 horas (en nanosegundos)
    start_time_ns = int((datetime.utcnow() - timedelta(hours=24)).timestamp() * 1_000_000_000)
    last_timestamp = None
    first_query = True  # Para usar el timestamp inicial solo la primera vez

    try:
        while True:
            params = {
                "query": '{job="fail2ban"}',
                "limit": 100,
                "direction": "forward",
            }

            if last_timestamp:
                params["start"] = str(int(last_timestamp) + 1)
            elif first_query:
                params["start"] = str(start_time_ns)
                first_query = False

            async with AsyncClient() as client:
                try:
                    response = await client.get(settings.LOKI_QUERY_URL, params=params, timeout=10.0)
                    response.raise_for_status()
                except (RequestError, HTTPStatusError) as exc:
                    try:
                        await websocket.send_json({"error": f"Error al contactar Loki: {str(exc)}"})
                    except WebSocketDisconnect:
                        break
                    except Exception as send_exc:
                        print(f"Error al enviar mensaje por websocket: {send_exc}")
                        break
                    await asyncio.sleep(5)
                    continue

            data = response.json().get("data", {})
            results = data.get("result", [])

            new_entries = []
            for stream in results:
                labels = stream.get("stream", {})
                service = labels.get("job", "desconocido")

                values = sorted(stream.get("values", []), key=lambda x: int(x[0]))

                for ts, line in values:
                    if last_timestamp is None or int(ts) > int(last_timestamp):
                        last_timestamp = ts

                    level_match = re.search(r"]:\s*(\w+)", line)
                    level = level_match.group(1).upper() if level_match else "INFO"

                    # Obtener el nivel de importancia

                    level_importance_map = {
                        "CRITICAL": "alta",
                        "ERROR": "alta",
                        "WARNING": "media",
                        "INFO": "baja",
                        "DEBUG": "baja"
                    }

                    importance = level_importance_map.get(level, "baja")

                    message_data = {
                        "timestamp": datetime.fromtimestamp(int(ts) / 1_000_000_000).strftime("%Y-%m-%d %H:%M:%S"),
                        "service": service,
                        "message": line,
                        "level": level,
                        "importance": importance,
                    }
                    new_entries.append((int(ts), message_data))

            new_entries.sort(key=lambda x: x[0], reverse=True)

            for _, message_data in new_entries:
                try:
                    await websocket.send_json(message_data)
                except WebSocketDisconnect:
                    print("Cliente desconectado mientras se enviaban mensajes.")
                    return
                except Exception as send_exc:
                    print(f"Error al enviar mensaje por websocket: {send_exc}")

            await asyncio.sleep(5)

    except WebSocketDisconnect:
        print("Cliente desconectado.")
    except Exception as e:
        print(f"Error inesperado en el websocket: {str(e)}")
        try:
            await websocket.send_json({"error": f"Error inesperado del servidor: {str(e)}"})
        except Exception as final_send_exc:
            print(f"No se pudo enviar el mensaje de error final: {final_send_exc}")


@router.get("/fail2ban/banned-ips")
async def get_banned_ips(
        page: int = Query(0, ge=0, description="Número de página."),
        size: int = Query(10, ge=1, le=100, description="Tamaño de página."),
):
    # Últimas 24 horas en nanosegundos
    start_time_sec = int(time.time()) - 86400  # 86400 segundos = 24 horas
    start_ns = start_time_sec * 1_000_000_000

    params = {
        "query": '{job="fail2ban"} |= "Ban"',
        "start": str(start_ns),
        "limit": 1000,
        "direction": "backward",
    }

    async with AsyncClient() as client:
        try:
            response = await client.get(settings.LOKI_QUERY_URL, params=params, timeout=10.0)
            response.raise_for_status()
        except (RequestError, HTTPStatusError) as exc:
            raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {str(exc)}")

    results = response.json().get("data", {}).get("result", [])
    entries = []
    banned_ips = set()
    all_values = []

    for stream in results:
        for ts, line in stream.get("values", []):
            all_values.append({'ts': ts, 'line': line})

    all_values.sort(key=lambda x: int(x['ts']), reverse=True)

    for log_entry in all_values:
        line = log_entry['line']

        match = re.search(r"(?:Ban|already banned)\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
        if not match:
            continue

        ip = match.group(1)
        if ip in banned_ips:
            continue

        jail_match = re.findall(r"\[([^\]]+)\]", line)
        jail = jail_match[1] if len(jail_match) > 1 else "desconocido"

        attempts_match = re.search(r"after\s+(\d+)\s+failures?", line, re.IGNORECASE)
        failed_attempts = int(attempts_match.group(1)) if attempts_match else 1

        ban_time_ns = int(log_entry['ts'])
        ban_time_str = datetime.utcfromtimestamp(ban_time_ns / 1_000_000_000).strftime('%Y-%m-%d %H:%M:%S')

        entries.append({
            "ip": ip,
            "jail": jail,
            "ban_time": ban_time_str,
            "failed_attempts": failed_attempts,
            "raw_log": line
        })
        banned_ips.add(ip)

    total_count = len(entries)
    start_idx = page * size
    end_idx = start_idx + size
    paginated_entries = entries[start_idx:end_idx]
    total_pages = math.ceil(total_count / size)

    return {
        "totalCount": total_count,
        "totalPages": total_pages,
        "hasNextPage": end_idx < total_count,
        "hasPreviousPage": start_idx > 0,
        "currentPage": page,
        "values": paginated_entries,
    }


# Ruta para obtener logs filtrados (similar a la función query_loki pero con más filtros)
@router.get("/fail2ban/logs")
async def get_filtered_logs(
        page: int = Query(0, ge=0),
        size: int = Query(10, ge=1, le=100),
        start: Optional[int] = Query(None, description="Inicio del rango de tiempo (timestamp UNIX en segundos)."),
        end: Optional[int] = Query(None, description="Fin del rango de tiempo (timestamp UNIX en segundos)."),
        service: Optional[str] = Query(None, description="Filtrar por etiqueta 'job' (e.g., 'fail2ban')."),
        level: Optional[str] = Query(None, description="Filtrar por nivel de log (buscar texto en el mensaje)."),
        filter_text: Optional[str] = Query(None, description="Texto libre a buscar en el mensaje del log.")
):
    # Establecer valores por defecto si no se proporcionan
    now_sec = int(time.time())
    if end is None:
        end = now_sec
    if start is None:
        start = end - 86400  # 24 horas antes

    query_parts = ['{job="fail2ban"}']
    if service:
        query_parts[0] = f'{{job="{service}"}}'
    if level:
        query_parts.append(f'|= `{level}`')
    if filter_text:
        query_parts.append(f'|= `{filter_text}`')

    logql_query = " ".join(query_parts)

    params = {
        "query": logql_query,
        "limit": 1000,
        "direction": "backward",
        "start": str(start * 1_000_000_000),
        "end": str(end * 1_000_000_000),
    }

    async with AsyncClient() as client:
        try:
            response = await client.get(settings.LOKI_QUERY_URL, params=params, timeout=10.0)
            response.raise_for_status()
        except (RequestError, HTTPStatusError) as exc:
            raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {str(exc)}")

    results = response.json().get("data", {}).get("result", [])
    all_values = []

    for stream in results:
        service_name = stream.get("stream", {}).get("job", "desconocido")
        for ts, line in stream.get("values", []):
            timestamp = datetime.fromtimestamp(int(ts) / 1_000_000_000)
            readable_date = timestamp.strftime("%Y-%m-%d %H:%M:%S")

            pid_match = re.search(r"\[(\d+)]", line)
            pid = pid_match.group(1) if pid_match else None

            ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", line)
            ip = ip_match.group(0) if ip_match else None

            level_match = re.search(r"\b(INFO|DEBUG|WARNING|ERROR|CRITICAL|NOTICE)\b", line)
            log_level = level_match.group(1).upper() if level_match else "INFO"

            event_match = re.search(r"\] (Found|Processing|Total|Ban|Unban|Started|Stopped|Banned|Unbanned)", line)
            event_type = event_match.group(1) if event_match else "Unknown"

            # Filtrar por nivel de log y texto libre

            level_importance_map = {
                "CRITICAL": "alta",
                "ERROR": "alta",
                "WARNING": "media",
                "NOTICE": "media",
                "INFO": "baja",
                "DEBUG": "baja"
            }
            event_importance_map = {
                "Ban": "alta",
                "Banned": "alta",
                "Unban": "media",
                "Unbanned": "media",
                "Started": "baja",
                "Stopped": "baja",
                "Processing": "baja",
                "Found": "baja",
                "Total": "baja"
            }

            importance = level_importance_map.get(log_level, "baja")
            if event_type in event_importance_map:
                # Si el evento tiene mayor importancia, toma la más alta
                importance = max(importance, event_importance_map[event_type],
                                 key=lambda x: ["baja", "media", "alta"].index(x))

            all_values.append({
                "date": readable_date,
                "timestamp": readable_date,
                "service": service_name,
                "pid": pid,
                "ip": ip,
                "level": log_level,
                "eventType": event_type,
                "importance": importance,
                "message": line.strip()
            })

    all_values.sort(key=lambda x: x["timestamp"], reverse=True)

    total = len(all_values)
    start_idx = page * size
    end_idx = start_idx + size

    paginated = all_values[start_idx:end_idx]
    total_pages = math.ceil(total / size)

    return {
        "totalCount": total,
        "totalPages": total_pages,
        "currentPage": page,
        "hasNextPage": end_idx < total,
        "hasPreviousPage": page > 0,
        "values": paginated,
    }


@router.get("/fail2ban/stats", summary="Fail2ban statistics overview")
async def get_stats(
    start: Optional[int] = Query(None, description="Inicio del rango de tiempo (timestamp UNIX en segundos)."),
    end: Optional[int] = Query(None, description="Fin del rango de tiempo (timestamp UNIX en segundos)."),
    service: Optional[str] = Query("fail2ban", description="Etiqueta 'job' para filtrar (por defecto: fail2ban)")
):
    # Compilamos regex para IPs (IPv4) y los tipos de eventos
    ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    found_regex = re.compile(r"\bfound\b", re.IGNORECASE)
    ban_regex = re.compile(r"\bban\b", re.IGNORECASE)
    unban_regex = re.compile(r"\bunban\b", re.IGNORECASE)

    # Establecer valores por defecto si no se proporcionan
    now = int(time.time())
    if end is None:
        end = now
    if start is None:
        start = end - 3600

    query = '{job="%s"} |= "Found" or |= "Ban" or |= "Unban"' % service

    params = {
        "query": query,
        "limit": 10000,
        "direction": "forward",
        "start": str(start * 1_000_000_000),
        "end": str(end * 1_000_000_000),
    }

    async with AsyncClient() as client:
        try:
            response = await client.get(settings.LOKI_QUERY_URL, params=params, timeout=10.0)
            response.raise_for_status()
        except (RequestError, HTTPStatusError) as exc:
            raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {str(exc)}")

    results = response.json().get("data", {}).get("result", [])

    failures = bans = unbans = 0
    ip_set = set()

    for entry in results:
        values = entry.get("values", [])
        for _, log_line in values:
            # Extraer IP si existe
            ip_match = ip_regex.search(log_line)
            if ip_match:
                ip_set.add(ip_match.group(0))

            # Buscar tipo de evento solo una vez
            if found_regex.search(log_line):
                failures += 1
            elif unban_regex.search(log_line):
                unbans += 1
            elif ban_regex.search(log_line):
                bans += 1

    return {
        "overview": {
            "totalFailures": {"value": failures, "deltaPct": None},
            "totalBans": {"value": bans, "deltaPct": None},
            "uniqueIPs": {"value": len(ip_set), "deltaPct": None},
            "activeBans": {"value": bans - unbans, "deltaPct": None},
        },
        "windowSeconds": end - start,
        "note": "Análisis optimizado del contenido de logs sin uso de labels ni stream."
    }


# --- FIN: Código de la versión más completa de controllers/logs.py ---

# Mantén la ruta /health y /fail2ban-logs si también las necesitas
# Si las rutas anteriores reemplazan la funcionalidad de /fail2ban-logs, puedes eliminarla.

# Ejemplo de cómo podría quedar si mantienes las rutas de la SEGUNDA versión que proporcionaste:
# Necesitarías importar LogEntry y query_loki si usas estas.
# from data.models import LogEntry
# from services.loki import query_loki

@router.get("/health")
async def health():
    return {"status": "ok", "message": "API de Logs y Gestión de Fail2ban funcionando"}
