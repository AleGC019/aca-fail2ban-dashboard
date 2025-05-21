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
import json
import ast

# Importaciones necesarias que podrían faltar según el contexto completo
# Asegúrate de que estas u otras dependencias necesarias estén aquí si las usas en otras partes del archivo
# from data.models import LogEntry # Necesario si devuelves este modelo en alguna ruta de este archivo
# from services.loki import query_loki # Necesario si llamas a esta función aquí

router = APIRouter()


# --- INICIO: Código de la versión más completa de controllers/logs.py ---
@router.websocket("/ws/fail2ban-logs-stream")
async def websocket_fail2ban_logs_stream(websocket: WebSocket):
    await websocket.accept()
    try:
        loki_ws = f"{settings.LOKI_WS_URL}?query={{job=\"fail2ban\"}}"
        async with AsyncClient() as client:
            async with client.stream("GET", loki_ws) as ws:
                async for message in ws.aiter_text():
                    if not message:
                        continue
                    print("Received from Loki:", message)  # Debug

                    try:
                        data = json.loads(message)
                        if "streams" in data and data["streams"]:
                            for stream in data["streams"]:
                                labels = stream.get("stream", {})
                                service = labels.get("job", "desconocido")

                                for ts, line in stream.get("values", []):
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
                        else:
                            await websocket.send_json({"info": "No log streams received yet."})
                    except json.JSONDecodeError:
                        print(f"Failed to parse Loki message: {message}")
                    except Exception as e:
                        print(f"Error processing Loki message: {str(e)}")
    except WebSocketDisconnect:
        print("Client disconnected")
    except Exception as e:
        print(f"Unexpected websocket error: {str(e)}")
        try:
            await websocket.send_json({"error": f"Server error: {str(e)}"})
        except Exception:
            pass

@router.websocket("/ws/fail2ban-logs")
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

            level_match = re.search(r"\b(INFO|DEBUG|WARNING|ERROR|CRITICAL)\b", line)
            log_level = level_match.group(1).upper() if level_match else "INFO"

            event_match = re.search(r"\] (Found|Processing|Total|Ban|Unban|Started|Stopped|Banned|Unbanned)", line)
            event_type = event_match.group(1) if event_match else "Unknown"

            # Filtrar por nivel de log y texto libre

            level_importance_map = {
                "CRITICAL": "alta",
                "ERROR": "alta",
                "WARNING": "media",
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


@router.get("/fail2ban/stats")
async def get_stats(
        start: Optional[int] = Query(None, description="Inicio del rango de tiempo (timestamp UNIX en segundos)."),
        end: Optional[int] = Query(None, description="Fin del rango de tiempo (timestamp UNIX en segundos)."),
        service: Optional[str] = Query("fail2ban", description="Etiqueta 'job' (por defecto: fail2ban)")
):
    now = int(time.time())
    if end is None:
        end = now
    if start is None:
        start = end - 86400  # últimos 24h

    window = end - start
    prev_start = start - window
    prev_end = start

    async def query_count_over_time(expr: str, s: int, e: int) -> int:
        params = {
            "query": f'count_over_time({expr} [{window}s])',
            "start": str(s * 1_000_000_000),
            "end": str(e * 1_000_000_000),
            "step": str(window)
        }
        async with AsyncClient() as client:
            try:
                res = await client.get(settings.LOKI_QUERY_URL, params=params, timeout=10.0)
                res.raise_for_status()
                results = res.json().get("data", {}).get("result", [])
                if results and results[0]["values"]:
                    return int(float(results[0]["values"][-1][1]))
                return 0
            except (RequestError, HTTPStatusError) as exc:
                raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {str(exc)}")

    async def query_ips(expr: str, s: int, e: int) -> int:
        """Extrae IPs únicas del log crudo, porque Loki no tiene distinct."""
        params = {
            "query": expr,
            "start": str(s * 1_000_000_000),
            "end": str(e * 1_000_000_000),
            "limit": 1000,
            "direction": "backward",
        }
        async with AsyncClient() as client:
            try:
                res = await client.get("http://localhost:3100/loki/api/v1/query", params=params, timeout=10.0)
                res.raise_for_status()
                results = res.json().get("data", {}).get("result", [])
                ip_set = set()
                for stream in results:
                    for ts, line in stream.get("values", []):
                        match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", line)
                        if match:
                            ip_set.add(match.group(0))
                return len(ip_set)
            except (RequestError, HTTPStatusError) as exc:
                raise HTTPException(status_code=503, detail=f"Error al extraer IPs: {str(exc)}")

    def with_delta(current: int, previous: int):
        if previous == 0:
            return {"value": current, "deltaPct": None}
        delta = round(((current - previous) / previous) * 100, 2)
        return {"value": current, "deltaPct": delta}

    expr_base = f'{{job="{service}"}}'

    # Ejecutar en paralelo
    from asyncio import gather

    current_failures, previous_failures, \
        current_bans, previous_bans, \
        current_unbans, previous_unbans, \
        current_ips, previous_ips = await gather(
        query_count_over_time(f'{expr_base} |= "Found"', start, end),
        query_count_over_time(f'{expr_base} |= "Found"', prev_start, prev_end),
        query_count_over_time(f'{expr_base} |= "Ban" != "Unban"', start, end),
        query_count_over_time(f'{expr_base} |= "Ban" != "Unban"', prev_start, prev_end),
        query_count_over_time(f'{expr_base} |= "Unban"', start, end),
        query_count_over_time(f'{expr_base} |= "Unban"', prev_start, prev_end),
        query_ips(expr_base, start, end),
        query_ips(expr_base, prev_start, prev_end),
    )

    current_active_bans = current_bans - current_unbans
    previous_active_bans = previous_bans - previous_unbans

    return {
        "overview": {
            "totalFailures": with_delta(current_failures, previous_failures),
            "totalBans": with_delta(current_bans, previous_bans),
            "uniqueIPs": with_delta(current_ips, previous_ips),
            "activeBans": with_delta(current_active_bans, previous_active_bans),
        }
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
