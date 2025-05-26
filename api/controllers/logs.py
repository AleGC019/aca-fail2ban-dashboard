# controllers/logs.py

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from httpx import AsyncClient, RequestError, HTTPStatusError
# --- CAMBIO AQUÍ ---
# Se importa LOKI_QUERY_URL directamente, no 'settings'
from services.fail2ban import get_currently_banned_ips, jail_exists
from configuration.settings import settings
# -------------------
import asyncio

import time
import re
from typing import Optional  # Añadido Optional para claridad si se usa
from datetime import datetime
import math
import websockets
from urllib.parse import urlencode
from starlette.websockets import WebSocketState
from collections import defaultdict, Counter
import json
import httpx
from urllib.parse import quote
import random

# Importaciones necesarias que podrían faltar según el contexto completo
# Asegúrate de que estas u otras dependencias necesarias estén aquí si las usas en otras partes del archivo
# from data.models import LogEntry # Necesario si devuelves este modelo en alguna ruta de este archivo
# from services.loki import query_loki # Necesario si llamas a esta función aquí

router = APIRouter()

# Funciones auxiliares
async def query_loki_with_retry(client, url, max_retries=3, base_delay=1):
    """
    Función auxiliar para realizar una consulta a Loki con reintentos y backoff exponencial.
    
    :param client: Instancia de httpx.AsyncClient
    :param url: URL completa de la consulta a Loki
    :param max_retries: Número máximo de reintentos
    :param base_delay: Retraso base en segundos para el backoff exponencial
    :return: Respuesta JSON de Loki o None si falla después de los reintentos
    """
    for attempt in range(max_retries):
        try:
            response = await client.get(url)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                # Calcular el tiempo de espera con backoff exponencial y jitter
                wait_time = base_delay * (2 ** attempt) + random.uniform(0, 1)
                print(f"Recibido 429. Esperando {wait_time:.2f} segundos antes de reintentar...")
                await asyncio.sleep(wait_time)
            else:
                raise ValueError(f"Query failed with status {response.status_code}")
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            wait_time = base_delay * (2 ** attempt) + random.uniform(0, 1)
            print(f"Error en la consulta: {e}. Esperando {wait_time:.2f} segundos antes de reintentar...")
            await asyncio.sleep(wait_time)
    return None

async def query_loki_with_retry_banned_ips(client: AsyncClient, url: str, max_retries: int = 3, base_delay: float = 1.0) -> dict:
    """
    Realiza una consulta a Loki con reintentos y backoff exponencial.
    """
    for attempt in range(max_retries):
        try:
            response = await client.get(url)
            response.raise_for_status()
            print(f"Consulta a Loki exitosa en intento {attempt + 1}: {url}")
            return response.json()
        except HTTPStatusError as e:
            if e.response.status_code == 429:
                wait_time = base_delay * (2 ** attempt) + random.uniform(0, 0.1)
                print(f"Error 429 en intento {attempt + 1}. Esperando {wait_time:.2f} segundos...")
                await asyncio.sleep(wait_time)
            else:
                raise HTTPException(
                    status_code=503,
                    detail=f"Error en consulta a Loki (estado {e.response.status_code}): {str(e)}"
                )
        except Exception as e:
            if attempt == max_retries - 1:
                raise HTTPException(
                    status_code=503,
                    detail=f"Error al contactar Loki tras {max_retries} intentos: {str(e)}"
                )
            wait_time = base_delay * (2 ** attempt) + random.uniform(0, 0.1)
            print(f"Error en consulta a Loki en intento {attempt + 1}: {str(e)}. Esperando {wait_time:.2f} segundos...")
            await asyncio.sleep(wait_time)
    return {}

# --- INICIO: Código de la versión más completa de controllers/logs.py ---

# nueva version del websocket, con los nuevos parametros solicitados
@router.websocket("/ws/fail2ban-logs")
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


#@router.get("/fail2ban/banned-ips")
#async def get_banned_ips(
#    page: int = Query(0, ge=0, description="Número de página"),
#    size: int = Query(10, ge=1, le=100, description="Tamaño de página"),
#    hours: int = Query(24, ge=1, le=168, description="Rango de tiempo en horas hacia atrás"),
#    jail: str = Query("sshd", description="Nombre del jail de Fail2ban")
#) -> dict:
#    """
#    Obtiene IPs actualmente baneadas en un jail específico y busca sus logs de baneo en Loki.
#    """
#    # Verificar si el jail existe
#    if not jail_exists(jail):
#        raise HTTPException(status_code=400, detail=f"El jail {jail} no existe.")
#
#    # Obtener IPs actualmente baneadas directamente de Fail2ban
#    try:
#        currently_banned_ips = set(get_currently_banned_ips(jail))
#        print(f"IPs actualmente baneadas en {jail}: {currently_banned_ips}")
#    except Exception as e:
#        raise HTTPException(status_code=400, detail=f"Error al obtener IPs baneadas: {str(e)}")
#
#    if not currently_banned_ips:
#        print("No hay IPs baneadas actualmente")
#        return {
#            "totalCount": 0,
#            "totalPages": 1,
#            "hasNextPage": False,
#            "hasPreviousPage": False,
#            "currentPage": page,
#            "values": []
#        }
#
#    # Consultar logs en Loki para cada IP baneada
#    start_time_sec = int(time.time()) - (hours * 3600)
#    start_ns = start_time_sec * 1_000_000_000
#    end_ns = int(time.time()) * 1_000_000_000
#
#    ban_entries = []
#    async with AsyncClient(timeout=10.0) as client:
#        for ip in currently_banned_ips:
#            # Consulta específica para la IP con cualquier variante de "ban"
#            params_ban = {
#                "query": f'{{job="fail2ban", jail="{jail}"}} |= "{ip}" |= "[Bb][Aa][Nn](?:ned)?"',
#                "start": str(start_ns),
#                "end": str(end_ns),
#                "limit": 1,  # Solo necesitamos el log más reciente de baneo
#                "direction": "backward",
#            }
#            try:
#                ban_response = await query_loki_with_retry(client, f"{settings.LOKI_QUERY_URL}?{urlencode(params_ban)}")
#                ban_results = ban_response.get("data", {}).get("result", [])
#
#                if ban_results:
#                    # Tomar el log más reciente
#                    for stream in ban_results:
#                        for ts, line in stream.get("values", []):
#                            ban_time_ns = int(ts)
#                            ban_time_str = datetime.utcfromtimestamp(ban_time_ns / 1_000_000_000).strftime('%Y-%m-%d %H:%M:%S')
#                            ban_entries.append({
#                                "ip": ip,
#                                "jail": jail,
#                                "ban_time": ban_time_str,
#                                "failed_attempts": 1,  # Placeholder
#                                "raw_log": line
#                            })
#                            break  # Solo tomar el primer log
#                        break  # Solo procesar el primer stream
#                else:
#                    print(f"No se encontraron logs de baneo para IP {ip} en Loki")
#                    # Fallback para IPs sin logs
#                    ban_entries.append({
#                        "ip": ip,
#                        "jail": jail,
#                        "ban_time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
#                        "failed_attempts": 1,
#                        "raw_log": "No disponible (obtenido directamente de Fail2ban)"
#                    })
#            except Exception as exc:
#                print(f"Error al consultar Loki para IP {ip}: {str(exc)}")
#                # Fallback en caso de error
#                ban_entries.append({
#                    "ip": ip,
#                    "jail": jail,
#                    "ban_time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
#                    "failed_attempts": 1,
#                    "raw_log": "Error al consultar Loki"
#                })
#
#    # Paginación
#    total_count = len(ban_entries)
#    start_idx = page * size
#    end_idx = start_idx + size
#    paginated_entries = ban_entries[start_idx:end_idx]
#    total_pages = math.ceil(total_count / size) if total_count > 0 else 1
#
#    print(f"Entradas de baneo procesadas: {len(ban_entries)}")
#    print(f"Jail consultado: {jail}")
#    print(f"Entradas finales: {total_count}")
#
#    return {
#        "totalCount": total_count,
#        "totalPages": total_pages,
#        "hasNextPage": end_idx < total_count,
#        "hasPreviousPage": start_idx > 0,
#        "currentPage": page,
#        "values": paginated_entries,
#    }

@router.get("/fail2ban/banned-ips")
async def get_banned_ips(
    page: int = Query(0, ge=0, description="Número de página"),
    size: int = Query(10, ge=1, le=100, description="Tamaño de página"),
    hours: int = Query(24, ge=1, le=168, description="Rango de tiempo en horas hacia atrás"),
    jail: str = Query("sshd", description="Nombre del jail de Fail2ban")
) -> dict:
    """
    Obtiene IPs actualmente baneadas y sus logs de baneo desde Loki, buscando el formato exacto:
    '2025-05-25 16:59:22,667 fail2ban.actions [pid]: NOTICE [jail] Ban ip'.
    """
    # Verificar si el jail existe
    if not jail_exists(jail):
        raise HTTPException(status_code=400, detail=f"El jail {jail} no existe.")

    # Obtener IPs actualmente baneadas
    try:
        currently_banned_ips = set(get_currently_banned_ips(jail))
        print(f"IPs actualmente baneadas en {jail}: {currently_banned_ips}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al obtener IPs baneadas: {str(e)}")

    if not currently_banned_ips:
        print("No hay IPs baneadas actualmente")
        return {
            "totalCount": 0,
            "totalPages": 1,
            "hasNextPage": False,
            "hasPreviousPage": False,
            "currentPage": page,
            "values": []
        }

    # Regex para validar el formato exacto del log
    # Ejemplo: "2025-05-25 16:59:22,667 fail2ban.actions [128145]: NOTICE [sshd] Ban 192.168.1.100"
    log_pattern = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+'
        r'fail2ban\.actions\s*\[(?P<pid>\d+)\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+'
        r'Ban\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})$'
    )

    # Consultar Loki para cada IP
    ban_entries = []
    start_time_sec = int(time.time()) - (hours * 3600)
    start_ns = start_time_sec * 1_000_000_000
    end_ns = int(time.time()) * 1_000_000_000

    async with AsyncClient(timeout=10.0) as client:
        for ip in currently_banned_ips:
            # Consulta específica para la IP con el formato exacto
            params_ban = {
                #"query": f'{{job="fail2ban", jail="{jail}"}} |= "{ip}" |= "NOTICE" |= "Ban"',
                "query": f'{{job="fail2ban""}} |= "{ip}" |= "NOTICE" |= "Ban" , |= "[{jail}]',
                "start": str(start_ns),
                "end": str(end_ns),
                "limit": 1,  # Solo el log más reciente
                "direction": "backward",
            }

            try:
                ban_response = await query_loki_with_retry(client, f"{settings.LOKI_QUERY_URL}?{urlencode(params_ban)}")
                ban_results = ban_response.get("data", {}).get("result", [])

                if ban_results:
                    for stream in ban_results:
                        for ts, line in stream.get("values", []):
                            line = line.strip()
                            # Validar el formato exacto del log
                            match = log_pattern.match(line)
                            if match:
                                timestamp_str = match.group('timestamp')
                                log_jail = match.group('jail')
                                log_ip = match.group('ip')
                                if log_jail == jail and log_ip == ip:
                                    try:
                                        ban_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f').strftime('%Y-%m-%d %H:%M:%S')
                                        ban_entries.append({
                                            "ip": ip,
                                            "jail": jail,
                                            "ban_time": ban_time,
                                            "failed_attempts": 1,  # Placeholder
                                            "raw_log": line
                                        })
                                        print(f"Log de baneo encontrado para IP {ip}: {line}")
                                        break
                                    except ValueError as e:
                                        print(f"Error al parsear timestamp en log para IP {ip}: {line}, error: {str(e)}")
                            else:
                                print(f"Log no coincide con el formato esperado para IP {ip}: {line}")
                        if ban_entries and ban_entries[-1]["ip"] == ip:
                            break  # Log encontrado, pasar a la siguiente IP
                else:
                    print(f"No se encontraron logs de baneo para IP {ip} en Loki")
                    ban_entries.append({
                        "ip": ip,
                        "jail": jail,
                        "ban_time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                        "failed_attempts": 1,
                        "raw_log": "No disponible (log no encontrado)"
                    })
            except Exception as exc:
                print(f"Error al consultar Loki para IP {ip}: {str(exc)}")
                ban_entries.append({
                    "ip": ip,
                    "jail": jail,
                    "ban_time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                    "failed_attempts": 1,
                    "raw_log": f"Error al consultar Loki: {str(exc)}"
                })

    # Paginación
    total_count = len(ban_entries)
    start_idx = page * size
    end_idx = start_idx + size
    paginated_entries = ban_entries[start_idx:end_idx]
    total_pages = math.ceil(total_count / size) if total_count > 0 else 1

    print(f"Entradas de baneo procesadas: {len(ban_entries)}")
    print(f"Jail consultado: {jail}")
    print(f"Entradas finales: {total_count}")

    return {
        "totalCount": total_count,
        "totalPages": total_pages,
        "hasNextPage": end_idx < total_count,
        "hasPreviousPage": start_idx > 0,
        "currentPage": page,
        "values": paginated_entries,
    }

@router.get("/fail2ban/current-banned-ips")
async def get_current_banned_ips(jail: str = "sshd"):
    if not jail_exists(jail):
        raise HTTPException(status_code=400, detail=f"El jail {jail} no existe.")
    try:
        banned_ips = get_currently_banned_ips(jail)
        return {"banned_ips": banned_ips}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al obtener IPs baneadas: {str(e)}")

#async def get_banned_ips(
#        page: int = Query(0, ge=0, description="Número de página."),
#        size: int = Query(10, ge=1, le=100, description="Tamaño de página."),
#):
#    # Últimas 24 horas en nanosegundos
#    start_time_sec = int(time.time()) - 86400  # 86400 segundos = 24 horas
#    start_ns = start_time_sec * 1_000_000_000
#
#    params = {
#        "query": '{job="fail2ban"} |= "Ban"',
#        "start": str(start_ns),
#        "limit": 1000,
#        "direction": "backward",
#    }
#
#    async with AsyncClient() as client:
#        try:
#            response = await client.get(settings.LOKI_QUERY_URL, params=params, timeout=10.0)
#            response.raise_for_status()
#        except (RequestError, HTTPStatusError) as exc:
#            raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {str(exc)}")
#
#    results = response.json().get("data", {}).get("result", [])
#    entries = []
#    banned_ips = set()
#    all_values = []
#
#    for stream in results:
#        for ts, line in stream.get("values", []):
#            all_values.append({'ts': ts, 'line': line})
#
#    all_values.sort(key=lambda x: int(x['ts']), reverse=True)
#
#    for log_entry in all_values:
#        line = log_entry['line']
#
#        match = re.search(r"(?:Ban|already banned)\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
#        if not match:
#            continue
#
#        ip = match.group(1)
#        if ip in banned_ips:
#            continue
#
#        jail_match = re.findall(r"\[([^\]]+)\]", line)
#        jail = jail_match[1] if len(jail_match) > 1 else "desconocido"
#
#        attempts_match = re.search(r"after\s+(\d+)\s+failures?", line, re.IGNORECASE)
#        failed_attempts = int(attempts_match.group(1)) if attempts_match else 1
#
#        ban_time_ns = int(log_entry['ts'])
#        ban_time_str = datetime.utcfromtimestamp(ban_time_ns / 1_000_000_000).strftime('%Y-%m-%d %H:%M:%S')
#
#        entries.append({
#            "ip": ip,
#            "jail": jail,
#            "ban_time": ban_time_str,
#            "failed_attempts": failed_attempts,
#            "raw_log": line
#        })
#        banned_ips.add(ip)
#
#    total_count = len(entries)
#    start_idx = page * size
#    end_idx = start_idx + size
#    paginated_entries = entries[start_idx:end_idx]
#    total_pages = math.ceil(total_count / size)
#
#    return {
#        "totalCount": total_count,
#        "totalPages": total_pages,
#        "hasNextPage": end_idx < total_count,
#        "hasPreviousPage": start_idx > 0,
#        "currentPage": page,
#        "values": paginated_entries,
#    }


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
async def get_fail2ban_stats():

    end_time = int(time.time())  # Tiempo actual en segundos (UNIX timestamp)
    start_time_current = end_time - 3600  # Hace 1 hora
    start_time_previous = end_time - 7200  # Hace 2 horas

    queries = [
        # Logs en la última hora
        'sum(count_over_time({job="fail2ban"} [1h]))',
        # Logs en la hora anterior
        'sum(count_over_time({job="fail2ban"} [1h] offset 1h))',
        # Logs con "action" o "jail" en la última hora
        'sum(count_over_time({job="fail2ban"} |~ "action|jail" [1h]))',
        # Eventos de baneo en la última hora
        'sum(count_over_time({job="fail2ban"} |= "Ban" [1h]))',
        # Logs con "WARNING" o "ERROR" en la última hora
        'sum(count_over_time({job="fail2ban"} |~ "WARNING|ERROR" [1h]))'
    ]

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Crear URLs para cada consulta
            urls = [
                f"{settings.LOKI_QUERY_URL}?query={quote(queries[0])}&start={start_time_current}&end={end_time}&step=3600",
                f"{settings.LOKI_QUERY_URL}?query={quote(queries[1])}&start={start_time_previous}&end={start_time_current}&step=3600",
                f"{settings.LOKI_QUERY_URL}?query={quote(queries[2])}&start={start_time_current}&end={end_time}&step=3600",
                f"{settings.LOKI_QUERY_URL}?query={quote(queries[3])}&start={start_time_current}&end={end_time}&step=3600",
                f"{settings.LOKI_QUERY_URL}?query={quote(queries[4])}&start={start_time_current}&end={end_time}&step=3600"
            ]

            # Ejecutar todas las consultas con reintentos
            tasks = [query_loki_with_retry(client, url) for url in urls]
            results = await asyncio.gather(*tasks)

            # Procesar los resultados
            processed_results = []
            for result in results:
                if result and result["data"]["resultType"] == "matrix" and result["data"]["result"]:
                    # Tomar el valor más reciente de la serie temporal
                    value = float(result["data"]["result"][0]["values"][-1][1])
                    processed_results.append(value)
                else:
                    processed_results.append(0.0)  # Si no hay datos, devolver 0

            # Asignar resultados
            logs_current, logs_previous, matched_logs, ban_events, warn_error_logs = processed_results

            # Calcular métricas
            logs_difference = logs_current - logs_previous
            parse_rate = (matched_logs / logs_current) * 100 if logs_current > 0 else 0

            # Formato de respuesta JSON
            stats_json = {
                "logs_difference": logs_difference,
                "parse_rate": parse_rate,
                "ban_events": ban_events,
                "warn_error_logs": warn_error_logs
            }

            return stats_json

    except Exception as e:
        return {"error": str(e)}


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
