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
import json
from starlette.websockets import WebSocketState

# Importaciones necesarias que podrían faltar según el contexto completo
# Asegúrate de que estas u otras dependencias necesarias estén aquí si las usas en otras partes del archivo
# from data.models import LogEntry # Necesario si devuelves este modelo en alguna ruta de este archivo
# from services.loki import query_loki # Necesario si llamas a esta función aquí

router = APIRouter()

# --- INICIO: Código de la versión más completa de controllers/logs.py ---
@router.websocket("/ws/fail2ban-logs-stream")  # Tu ruta para el tail real de Loki
async def websocket_fail2ban_logs_stream(websocket: WebSocket,
                                         limit: int = Query(10, description="Líneas iniciales."),
                                         start: Optional[int] = Query(None,
                                                                      description="Timestamp UNIX en ns para inicio.")):  # 'start' aquí es el que pasas a Loki
    await websocket.accept()
    client_host = websocket.client.host if websocket.client else "desconocido"
    client_port = websocket.client.port if websocket.client else "desconocido"
    print(f"Cliente WebSocket {client_host}:{client_port} conectado a /ws/fail2ban-logs-stream")

    logql_query = '{job="fail2ban"}'  # Query específico

    query_params_dict = {"query": logql_query, "limit": str(limit)}
    if start:  # Si el cliente proporciona un 'start' timestamp para Loki
        query_params_dict["start"] = str(start)

    # settings.LOKI_WS_URL debería ser algo como "ws://loki:3100/loki/api/v1/tail"
    loki_target_ws_url = f"{settings.LOKI_WS_URL}?{urlencode(query_params_dict)}"

    try:
        # Usamos el subprotocolo que Loki espera para el streaming de JSON
        async with websockets.connect(loki_target_ws_url,
                                      subprotocols=["json. व्यासपी.લોકી.ગ્રાફના.com"]) as loki_ws_client:
            print(f"Conectado al WebSocket de Loki: {loki_target_ws_url}")

            # Tarea para enviar mensajes del cliente API a Loki (generalmente no se usa para tail)
            async def client_to_loki_task():
                try:
                    while True:
                        data = await websocket.receive_text()
                        # En un tail simple, no se espera que el cliente envíe mucho,
                        # pero podrías implementar lógica aquí si es necesario.
                        # await loki_ws_client.send(data) # Descomentar si necesitas enviar a Loki
                        print(
                            f"Proxy WS: Mensaje de cliente API {client_host}:{client_port} (no reenviado a Loki): {data}")
                except WebSocketDisconnect:
                    print(f"Proxy WS: Cliente API {client_host}:{client_port} desconectado (en client_to_loki_task).")
                except websockets.exceptions.ConnectionClosed:  # La conexión a Loki ya fue cerrada por la otra tarea
                    print(
                        f"Proxy WS: Conexión a Loki cerrada, terminando client_to_loki_task para {client_host}:{client_port}.")
                    pass
                except Exception as e_c2l:  # Cualquier otra excepción en esta tarea
                    print(
                        f"Proxy WS: Error inesperado en client_to_loki_task para {client_host}:{client_port}: {type(e_c2l).__name__} {e_c2l}")

            # Tarea para enviar mensajes de Loki al cliente API (tu frontend)
            async def loki_to_client_task():
                try:
                    async for message_from_loki_str in loki_ws_client:
                        # message_from_loki_str es una cadena JSON de Loki
                        # Aquí es donde aplicarías el formato de timestamp y el mapeo de importancia
                        try:
                            loki_data_batch = json.loads(message_from_loki_str)
                            if "streams" in loki_data_batch:
                                for stream in loki_data_batch["streams"]:
                                    labels = stream.get("stream", {})
                                    service = labels.get("job", "desconocido")
                                    level_from_labels = labels.get("level", "INFO")

                                    for ts_str, line_content in stream.get("values", []):
                                        try:
                                            timestamp_dt = datetime.fromtimestamp(int(ts_str) / 1_000_000_000)
                                            formatted_timestamp = timestamp_dt.strftime("%Y-%m-%d %H:%M:%S")
                                        except Exception:
                                            formatted_timestamp = ts_str

                                        level_importance_map = {
                                            "CRITICAL": "alta", "ERROR": "alta",
                                            "WARNING": "media", "NOTICE": "media",
                                            "INFO": "baja", "DEBUG": "baja"
                                        }
                                        importance = level_importance_map.get(level_from_labels.upper(), "baja")

                                        client_message = {
                                            "timestamp": formatted_timestamp,
                                            "service": service,
                                            "message": line_content,
                                            "level": level_from_labels,
                                            "importance": importance,
                                            "raw_labels": labels
                                        }
                                        await websocket.send_json(client_message)
                        except json.JSONDecodeError:
                            print(
                                f"Proxy WS: No se pudo parsear mensaje JSON de Loki: {message_from_loki_str[:200]}...")
                            # Si no se puede parsear, podrías enviar el texto crudo o un mensaje de error
                            # await websocket.send_text(message_from_loki_str) # Opción: enviar crudo
                        except WebSocketDisconnect:  # Si nuestro cliente API se desconecta mientras procesamos
                            print(
                                f"Proxy WS: Cliente API {client_host}:{client_port} desconectado (procesando msg de Loki).")
                            raise  # Re-lanzar para que la tarea principal termine y cierre loki_ws_client
                        except Exception as e_proc:
                            print(
                                f"Proxy WS: Error procesando/enviando mensaje de Loki: {type(e_proc).__name__} - {e_proc}")
                            # Considera si enviar un error al cliente aquí

                except websockets.exceptions.ConnectionClosedOK:
                    print(f"Proxy WS: Conexión a Loki para {client_host}:{client_port} cerrada limpiamente por Loki.")
                except websockets.exceptions.ConnectionClosedError as e:
                    print(
                        f"Proxy WS: Conexión a Loki para {client_host}:{client_port} cerrada con error por Loki: {e.code} {e.reason}")
                    if websocket.application_state != WebSocketState.DISCONNECTED:  # <--- USO DE WebSocketState
                        await websocket.close(code=1011)  # Código genérico para error del servidor
                except WebSocketDisconnect:  # Si nuestro cliente API se desconecta
                    print(f"Proxy WS: Cliente API {client_host}:{client_port} desconectado (en loki_to_client_task).")
                except Exception as e_l2c:  # Cualquier otra excepción en esta tarea
                    print(
                        f"Proxy WS: Error inesperado en loki_to_client_task para {client_host}:{client_port}: {type(e_l2c).__name__} - {e_l2c}")
                    if websocket.application_state != WebSocketState.DISCONNECTED:  # <--- USO DE WebSocketState
                        await websocket.close(code=1011)

            # Ejecutar ambas tareas y esperar a que la primera termine (o falle)
            task_l2c = asyncio.create_task(loki_to_client_task())
            task_c2l = asyncio.create_task(client_to_loki_task())

            done, pending = await asyncio.wait(
                [task_l2c, task_c2l],
                return_when=asyncio.FIRST_COMPLETED
            )

            for task_to_cancel in pending:
                task_to_cancel.cancel()
                try:
                    await task_to_cancel  # Esperar a que la cancelación se complete
                except asyncio.CancelledError:
                    print(
                        f"Proxy WS: Tarea pendiente {task_to_cancel.get_name()} cancelada limpiamente para {client_host}:{client_port}.")
                except Exception as e_cancel:
                    print(
                        f"Proxy WS: Excepción al cancelar tarea pendiente {task_to_cancel.get_name()} para {client_host}:{client_port}: {type(e_cancel).__name__} - {e_cancel}")

            for task_done in done:  # Re-propagar la excepción si una de las tareas 'done' falló
                if task_done.exception():
                    print(
                        f"Proxy WS: Tarea {task_done.get_name()} para {client_host}:{client_port} finalizada con excepción: {task_done.exception()}")
                    raise task_done.exception()

    # Manejo de excepciones para la conexión principal del endpoint con el cliente API o la conexión inicial a Loki
    except websockets.exceptions.InvalidURI:
        err_msg = f"Error: URI de WebSocket de Loki inválida: {loki_target_ws_url}"
        print(err_msg)
        # --- CORRECCIÓN DE USO DE WebSocketState ---
        if websocket.application_state != WebSocketState.DISCONNECTED:
            await websocket.send_json({"error": err_msg, "type": "error_config"})
    except websockets.exceptions.WebSocketException as e:
        # Esto captura errores de conexión como ConnectionRefused, HandshakeError, etc., al intentar conectar a Loki.
        err_msg = f"No se pudo conectar al WebSocket de Loki en {loki_target_ws_url}: {type(e).__name__} ({e.rc if hasattr(e, 'rc') else e.code if hasattr(e, 'code') else 'N/A'}) - {str(e)}"
        print(err_msg)
        # --- CORRECCIÓN DE USO DE WebSocketState ---
        if websocket.application_state != WebSocketState.DISCONNECTED:
            await websocket.send_json({"error": err_msg, "type": "error_backend_connection"})
    except WebSocketDisconnect:
        print(f"Cliente WebSocket {client_host}:{client_port} desconectado de /ws/fail2ban-logs-stream.")
    except Exception as e:
        err_msg = f"Error general en /ws/fail2ban-logs-stream para {client_host}:{client_port}: {type(e).__name__} - {e}"
        print(err_msg)
        try:
            # --- LÍNEA PROBLEMÁTICA ORIGINAL Y SU CORRECCIÓN ---
            if websocket.application_state != WebSocketState.DISCONNECTED:  # Ahora WebSocketState está definido
                # --- FIN DE CORRECCIÓN ---
                await websocket.send_json(
                    {"error": "Error interno del servidor en el stream de logs.", "type": "error_server"})
        except Exception as send_err:
            print(f"No se pudo enviar mensaje de error final al WebSocket: {send_err}")
    finally:
        print(
            f"Cerrando y limpiando conexión WebSocket para el cliente {client_host}:{client_port} en /ws/fail2ban-logs-stream")
        # FastAPI/Uvicorn manejan el cierre del websocket del cliente (websocket) si la función del endpoint termina.
        # El `async with websockets.connect(...)` asegura que loki_ws_client se cierre al salir de ese bloque.
        # Si quieres ser explícito o necesitas un código de cierre específico para el cliente:
        if websocket.application_state != WebSocketState.DISCONNECTED:
            await websocket.close(code=1000)  # Cierre normal

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
