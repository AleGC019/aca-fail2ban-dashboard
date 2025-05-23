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


@router.get("/fail2ban/stats", summary="Fail2ban statistics overview", tags=["fail2ban"])
async def get_stats(
    start: Optional[int] = Query(None, description="Start of time window (UNIX timestamp, seconds). Default: 1 hour ago."),
    end: Optional[int] = Query(None, description="End of time window (UNIX timestamp, seconds). Default: now."),
    service: Optional[str] = Query("fail2ban", description="Log 'job' label to filter (default: fail2ban)")
):
    """
    Returns statistics for Fail2ban events in the given time window, including:
    - Total failures (Found)
    - Total bans
    - Unique IPs detected
    - Active bans (bans - unbans)
    Also returns percentage change (delta) compared to the previous window.
    """
    now = int(time.time())
    if end is None:
        end = now
    if start is None:
        start = end - 3600

    # Enforce window size limits
    MIN_WINDOW = 60  # 1 minute
    MAX_WINDOW = 3600  # 1 hour
    window = end - start
    if window < MIN_WINDOW:
        start = end - MIN_WINDOW
        window = MIN_WINDOW
    elif window > MAX_WINDOW:
        start = end - MAX_WINDOW
        window = MAX_WINDOW

    prev_start = start - window
    prev_end = start

    # Correct f-string for Loki label selector
    expr_base = f'{{job="{service}"}}'

    async def quick_count(label: str, s: int, e: int) -> int:
        params = {
            "query": f'count_over_time({expr_base} |= "{label}" [{window}s])',
            "start": str(s * 1_000_000_000),
            "end": str(e * 1_000_000_000),
            "step": str(window)
        }
        async with AsyncClient() as client:
            try:
                res = await client.get(settings.LOKI_QUERY_URL, params=params, timeout=5.0)
                res.raise_for_status()
                data = res.json().get("data", {}).get("result", [])
                if data and data[0]["values"]:
                    return int(float(data[0]["values"][-1][1]))
                return 0
            except Exception as exc:
                print("Count error:", exc)
                return None

    async def fast_ip_count(s: int, e: int) -> int:
        # Try to use count_values_over_time for unique IPs if Loki supports it
        params = {
            "query": f'count_values_over_time("ip", {expr_base} |= "Found" | regexp "(?P<ip>\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b)" [{window}s])',
            "start": str(s * 1_000_000_000),
            "end": str(e * 1_000_000_000),
            "step": str(window)
        }
        async with AsyncClient() as client:
            try:
                res = await client.get(settings.LOKI_QUERY_URL, params=params, timeout=5.0)
                res.raise_for_status()
                data = res.json().get("data", {}).get("result", [])
                if data and data[0]["values"]:
                    # The value is the count of unique IPs
                    return int(float(data[0]["values"][-1][1]))
                return 0
            except Exception as exc:
                print("IP count error (count_values_over_time):", exc)
                # Fallback to old method if not supported
                params_fallback = {
                    "query": f'{expr_base} |= "Found"',
                    "start": str(s * 1_000_000_000),
                    "end": str(e * 1_000_000_000),
                    "limit": 500,
                    "direction": "backward"
                }
                try:
                    res = await client.get(settings.LOKI_QUERY_URL, params=params_fallback, timeout=5.0)
                    res.raise_for_status()
                    results = res.json().get("data", {}).get("result", [])
                    ips = set()
                    for stream in results:
                        for _, line in stream.get("values", []):
                            match = re.search(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", line)
                            if match:
                                ips.add(match.group(0))
                    return len(ips)
                except Exception as exc2:
                    print("IP count error (fallback):", exc2)
                    return None

    def with_delta(current: int, previous: int):
        if current is None:
            return {"value": None, "deltaPct": None}
        if previous in (None, 0):
            return { "value": current, "deltaPct": None }
        delta = round(((current - previous) / previous) * 100, 2)
        return {"value": current, "deltaPct": delta}

    # Run all queries in parallel
    results = await asyncio.gather(
        quick_count("Found", start, end),
        quick_count("Found", prev_start, prev_end),
        quick_count("Ban", start, end),
        quick_count("Ban", prev_start, prev_end),
        quick_count("Unban", start, end),
        quick_count("Unban", prev_start, prev_end),
        fast_ip_count(start, end),
        fast_ip_count(prev_start, prev_end),
        return_exceptions=True
    )
    (
        current_failures, previous_failures,
        current_bans, previous_bans,
        current_unbans, previous_unbans,
        current_ips, previous_ips
    ) = results

    # If any are None or exception, handle gracefully
    def safe(val):
        return val if isinstance(val, int) else None

    current_active_bans = max(0, safe(current_bans) - safe(current_unbans)) if safe(current_bans) is not None and safe(current_unbans) is not None else None
    previous_active_bans = max(0, safe(previous_bans) - safe(previous_unbans)) if safe(previous_bans) is not None and safe(previous_unbans) is not None else None

    return {
        "overview": {
            "totalFailures": with_delta(safe(current_failures), safe(previous_failures)),
            "totalBans":     with_delta(safe(current_bans), safe(previous_bans)),
            "uniqueIPs":     with_delta(safe(current_ips), safe(previous_ips)),
            "activeBans":    with_delta(current_active_bans, previous_active_bans),
        },
        "windowSeconds": window,
        "note": "If any value is null, it means the query failed or is not supported by Loki."
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
