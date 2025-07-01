# controllers/logs.py

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException, Depends
from httpx import AsyncClient, RequestError, HTTPStatusError
# --- CAMBIO AQUÍ ---
# Se importa LOKI_QUERY_URL directamente, no 'settings'
from services.fail2ban import (
    get_currently_banned_ips, 
    jail_exists, 
    get_banned_ips_with_details, 
    get_jail_ban_duration,
    get_ip_ban_history,
    get_jail_context_info,
    calculate_threat_level,
    get_peak_attack_hour,
    get_ban_info_from_logs,
    get_ban_temporal_info
)
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
from services.auth import get_current_user

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
    start: Optional[int] = Query(None, description="Timestamp UNIX en ns para inicio."),
    current_user: dict = Depends(get_current_user)
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


@router.get("/fail2ban/banned-ips")
async def get_banned_ips(
    page: int = Query(0, ge=0, description="Número de página"),
    size: int = Query(10, ge=1, le=100, description="Tamaño de página"),
    hours: int = Query(24, ge=1, le=168, description="Rango de tiempo en horas hacia atrás"),
    jail: str = Query("sshd", description="Nombre del jail de Fail2ban"),
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Obtiene IPs actualmente baneadas con información detallada desde Loki.
    Optimizado para una sola consulta y extracción completa de datos.
    """
    # TODO: Eliminar prints de debug después de las pruebas
    print(f"🔍 [DEBUG] Iniciando get_banned_ips para jail={jail}, hours={hours}")
    
    # Verificar si el jail existe
    if not jail_exists(jail):
        print(f"❌ [DEBUG] El jail {jail} no existe")
        raise HTTPException(status_code=400, detail=f"El jail {jail} no existe.")

    # Obtener IPs actualmente baneadas
    try:
        currently_banned_ips = set(get_currently_banned_ips(jail))
        print(f"[DEBUG] IPs actualmente baneadas en {jail}: {currently_banned_ips}")
    except Exception as e:
        print(f"[DEBUG] Error obteniendo IPs baneadas: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error al obtener IPs baneadas: {str(e)}")

    if not currently_banned_ips:
        print("[DEBUG] No hay IPs baneadas actualmente")
        return {
            "totalCount": 0,
            "totalPages": 1,
            "hasNextPage": False,
            "hasPreviousPage": False,
            "currentPage": page,
            "values": []
        }

    # Obtener la duración de ban por defecto del jail
    ban_duration_seconds = get_jail_ban_duration(jail)
    print(f"⏱️ [DEBUG] Duración de ban para {jail}: {ban_duration_seconds} segundos")
    
    # Obtener contexto del jail una sola vez (información compartida)
    jail_context = get_jail_context_info(jail)
    print(f"🏢 [DEBUG] Contexto del jail obtenido: {jail_context}")

    # Configurar rango de tiempo para la consulta
    start_time_sec = int(time.time()) - (hours * 3600)
    start_ns = start_time_sec * 1_000_000_000
    end_ns = int(time.time()) * 1_000_000_000
    
    print(f"🕐 [DEBUG] Rango de tiempo: {start_time_sec} - {int(time.time())} (últimas {hours}h)")

    # Hacer una consulta única para obtener todos los logs relacionados con las IPs baneadas
    ips_query = "|".join(currently_banned_ips)  # Crear regex para todas las IPs
    
    # TODO: Eliminar debug después de las pruebas - Consulta simplificada para debuggear
    print(f"🔍 [DEBUG] IPs para buscar: {ips_query}")
    
    # Consulta optimizada que obtiene logs de Found y Ban para todas las IPs
    # Cambiando a consulta más simple para evitar error 400
    logql_query = f'{{job="fail2ban", jail="{jail}"}}'
    
    params = {
        "query": logql_query,
        "start": str(start_ns),
        "end": str(end_ns),
        "limit": 5000, 
        "direction": "backward" 
    }
    
    print(f"🔍 [DEBUG] Consulta Loki (simplificada): {logql_query}")
    print(f"📊 [DEBUG] Parámetros: limit={params['limit']}, direction={params['direction']}")

    ban_entries = []
    
    async with AsyncClient(timeout=30.0) as client:
        try:
            print("🌐 [DEBUG] Ejecutando consulta a Loki...")
            response = await query_loki_with_retry(client, f"{settings.LOKI_QUERY_URL}?{urlencode(params)}")
            results = response.get("data", {}).get("result", [])
            
            print(f"📈 [DEBUG] Loki devolvió {len(results)} streams")
            
            # Procesar todos los logs y agrupar por IP
            ip_logs = {}  # {ip: {"found_logs": [], "ban_log": None}}
            
            total_logs_processed = 0
            total_logs_filtered = 0
            
            for stream in results:                
                for ts, message in stream.get("values", []):
                    total_logs_processed += 1
                    
                    # Filtrar solo mensajes que contengan alguna de nuestras IPs baneadas
                    relevant_for_ip = None
                    for banned_ip in currently_banned_ips:
                        if banned_ip in message:
                            relevant_for_ip = banned_ip
                            break
                    
                    if not relevant_for_ip:
                        continue  # Saltar logs que no contienen nuestras IPs
                    
                    total_logs_filtered += 1
                    timestamp_dt = datetime.fromtimestamp(int(ts) / 1_000_000_000)
                    
                    # Buscar patrones de Found y Ban
                    found_match = re.search(r'Found\s+(\d{1,3}(?:\.\d{1,3}){3})', message)
                    ban_match = re.search(r'Ban\s+(\d{1,3}(?:\.\d{1,3}){3})', message)
                    
                    if found_match:
                        ip = found_match.group(1)
                        if ip in currently_banned_ips:
                            if ip not in ip_logs:
                                ip_logs[ip] = {"found_logs": [], "ban_log": None}
                            ip_logs[ip]["found_logs"].append({
                                "timestamp": timestamp_dt,
                                "message": message,
                                "ts": ts
                            })
                            print(f"🔍 [DEBUG] Found log para {ip}: {message[:50]}...")
                    
                    elif ban_match:
                        ip = ban_match.group(1)
                        if ip in currently_banned_ips:
                            if ip not in ip_logs:
                                ip_logs[ip] = {"found_logs": [], "ban_log": None}
                            # Solo mantener el ban más reciente si hay múltiples
                            if not ip_logs[ip]["ban_log"] or timestamp_dt > ip_logs[ip]["ban_log"]["timestamp"]:
                                ip_logs[ip]["ban_log"] = {
                                    "timestamp": timestamp_dt,
                                    "message": message,
                                    "ts": ts
                                }
                                print(f"🚫 [DEBUG] Ban log para {ip}: {message[:50]}...")
            
            print(f"📊 [DEBUG] Total logs procesados: {total_logs_processed}")
            print(f"📊 [DEBUG] Logs relevantes (con nuestras IPs): {total_logs_filtered}")
            print(f"📋 [DEBUG] IPs con logs encontrados: {list(ip_logs.keys())}")
            
            # Construir la respuesta final
            for ip in currently_banned_ips:
                ip_data = ip_logs.get(ip, {"found_logs": [], "ban_log": None})
                
                # Obtener información del baneo
                if ip_data["ban_log"]:
                    ban_time = ip_data["ban_log"]["timestamp"].strftime('%Y-%m-%d %H:%M:%S')
                    raw_log = ip_data["ban_log"]["message"]
                    print(f"✅ [DEBUG] IP {ip}: Ban encontrado en {ban_time}")
                else:
                    ban_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    raw_log = f"IP actualmente baneada en jail {jail} (log de ban no encontrado en el rango de {hours}h)"
                    print(f"⚠️ [DEBUG] IP {ip}: Ban log no encontrado, usando fallback")
                
                # Contar intentos fallidos
                failed_attempts = len(ip_data["found_logs"])
                print(f"📊 [DEBUG] IP {ip}: {failed_attempts} intentos fallidos encontrados")
                
                # Calcular duración de ban en formato legible
                ban_duration_minutes = ban_duration_seconds // 60
                ban_duration_formatted = f"{ban_duration_minutes} minutos"
                if ban_duration_minutes >= 60:
                    ban_duration_hours = ban_duration_minutes // 60
                    remaining_minutes = ban_duration_minutes % 60
                    ban_duration_formatted = f"{ban_duration_hours}h {remaining_minutes}m"
                
                # 1. Historial básico (cuántas veces baneada antes)
                ban_history = get_ip_ban_history(ip, jail, days_back=30)
                print(f"📜 [DEBUG] Historial para {ip}: {ban_history}")
                
                # 2. Nivel de amenaza (score basado en patrones)
                threat_level = calculate_threat_level(ban_history, failed_attempts, jail_context, {})
                print(f"⚠️ [DEBUG] Nivel de amenaza para {ip}: {threat_level}")
                
                # Construir entrada completa con toda la información
                ban_entry = {
                    # Información básica original
                    "ip": ip,
                    "jail": jail,
                    "ban_time": ban_time,
                    "ban_duration_time": ban_duration_formatted,
                    "failed_attempts": failed_attempts,
                    "raw_log": raw_log,
                    
                    "reputation": {
                        "previous_bans_count": ban_history.get("previous_bans_count", 0),
                        "total_bans_ever": ban_history.get("total_bans_ever", 1),
                        "first_seen": ban_history.get("first_seen", "Desconocido"),
                        "last_ban_before": ban_history.get("last_ban_before", "Primer ban"),
                        "is_repeat_offender": ban_history.get("is_repeat_offender", False),
                        "attack_frequency": ban_history.get("attack_frequency", "desconocida"),
                        "days_since_first_seen": ban_history.get("days_since_first_seen", 0)
                    },
                    
                    "threat_level": {
                        "score": threat_level.get("score", 1),
                        "max_score": threat_level.get("max_score", 10),
                        "level": threat_level.get("level", "LOW"),
                        "reasons": threat_level.get("reasons", []),
                        "recommended_action": threat_level.get("recommended_action", "Continuar monitoreo")
                    }
                }
                
                ban_entries.append(ban_entry)
                print(f"📋 [DEBUG] Entrada completa creada para {ip} con nivel de amenaza {threat_level.get('level', 'LOW')}")
        
        except Exception as exc:
            print(f"❌ [DEBUG] Error en consulta Loki: {str(exc)}")
            # Crear entradas de fallback para todas las IPs
            for ip in currently_banned_ips:
                ban_entries.append({
                    # Información básica de fallback
                    "ip": ip,
                    "jail": jail,
                    "ban_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "ban_duration_time": f"{ban_duration_seconds // 60} minutos",
                    "ban_duration_seconds": ban_duration_seconds,
                    "failed_attempts": 0,
                    "raw_log": f"Error al consultar Loki: {str(exc)}",
                    
                    # Información de reputación de fallback
                    "reputation": {
                        "previous_bans_count": 0,
                        "total_bans_ever": 1,
                        "first_seen": "Desconocido",
                        "last_ban_before": "Primer ban",
                        "is_repeat_offender": False,
                        "attack_frequency": "desconocida",
                        "days_since_first_seen": 0
                    },
                    
                    # Nivel de amenaza de fallback
                    "threat_level": {
                        "score": 1,
                        "max_score": 10,
                        "level": "LOW",
                        "reasons": ["Error al consultar información"],
                        "recommended_action": "Revisar manualmente"
                    }
                })

    # Ordenar por tiempo de ban (más reciente primero)
    ban_entries.sort(key=lambda x: x["ban_time"], reverse=True)
    
    # Paginación
    total_count = len(ban_entries)
    start_idx = page * size
    end_idx = start_idx + size
    paginated_entries = ban_entries[start_idx:end_idx]
    total_pages = math.ceil(total_count / size) if total_count > 0 else 1

    print(f"[DEBUG] Resultado final: {total_count} entradas, página {page}, {len(paginated_entries)} en esta página")
    print(f"[DEBUG] get_banned_ips completado exitosamente")

    return {
        # Información de paginación
        "totalCount": total_count,
        "totalPages": total_pages,
        "hasNextPage": end_idx < total_count,
        "hasPreviousPage": start_idx > 0,
        "currentPage": page,
        "values": paginated_entries,
    }

@router.get("/fail2ban/current-banned-ips")
async def get_current_banned_ips(jail: str = "sshd", current_user: dict = Depends(get_current_user)):
    if not jail_exists(jail):
        raise HTTPException(status_code=400, detail=f"El jail {jail} no existe.")
    try:
        banned_ips = get_currently_banned_ips(jail)
        return {"banned_ips": banned_ips}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al obtener IPs baneadas: {str(e)}")


# Ruta para obtener logs filtrados (similar a la función query_loki pero con más filtros)
@router.get("/fail2ban/logs")
async def get_filtered_logs(
        page: int = Query(0, ge=0),
        size: int = Query(10, ge=1, le=100),
        start: Optional[int] = Query(None, description="Inicio del rango de tiempo (timestamp UNIX en segundos)."),
        end: Optional[int] = Query(None, description="Fin del rango de tiempo (timestamp UNIX en segundos)."),
        service: Optional[str] = Query(None, description="Filtrar por etiqueta 'job' (e.g., 'fail2ban')."),
        level: Optional[str] = Query(None, description="Filtrar por nivel de log (buscar texto en el mensaje)."),
        filter_text: Optional[str] = Query(None, description="Texto libre a buscar en el mensaje del log."),
        current_user: dict = Depends(get_current_user)
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
            log_level = level_match.group(1).upper() if level_match else "UNKNOWN"

            event_match = re.search(r"\b(Found|Processing|Total|Ban|Unban|Started|Stopped|Banned|Unbanned)\b", line)
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
async def get_fail2ban_stats(current_user: dict = Depends(get_current_user)):

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

@router.get("/protected-stats", summary="Estadísticas protegidas con autenticación")
async def get_protected_stats(current_user: dict = Depends(get_current_user)):
    """
    Endpoint protegido que requiere autenticación JWT.
    Demuestra cómo usar el token Bearer en Swagger.
    """
    return {
        "message": f"Hola {current_user['email']}, tienes acceso a las estadísticas protegidas",
        "user_email": current_user["email"],
        "timestamp": datetime.now().isoformat(),
        "protected_data": {
            "admin_level": True,
            "can_modify_jails": True,
            "last_login": datetime.now().isoformat()
        }
    }

# ruta extra de prueba para lo de las ips baneadas
@router.get("/fail2ban/banned-ips-testing")
async def get_banned_ips_testing(
    page: int = Query(0, ge=0, description="Número de página"),
    size: int = Query(10, ge=1, le=100, description="Tamaño de página"),
    hours: int = Query(24, ge=1, le=168, description="Rango de tiempo en horas hacia atrás"),
    jail: str = Query("sshd", description="Nombre del jail de Fail2ban")
) -> dict:
    """
    Obtiene IPs baneadas para una jail, con hora del ban y mensaje del log.

    Returns:
        dict: Información paginada con ip, jail, ban_time, raw_log.
    """
    ban_entries = get_banned_ips_with_details(jail, hours)

    # Paginación
    total_count = len(ban_entries)
    start_idx = page * size
    end_idx = start_idx + size
    paginated_entries = ban_entries[start_idx:end_idx]
    total_pages = math.ceil(total_count / size) if total_count > 0 else 1

    return {
        "totalCount": total_count,
        "totalPages": total_pages,
        "hasNextPage": end_idx < total_count,
        "hasPreviousPage": start_idx > 0,
        "currentPage": page,
        "values": paginated_entries
    }

@router.get("/fail2ban/banned-ips-simple")
async def banned_ips_simple(
    page: int = Query(0, ge=0, description="Número de página"),
    size: int = Query(10, ge=1, le=100, description="Tamaño de página"),
    jail: str = Query("sshd", description="Nombre del jail de Fail2ban"),
    current_user: dict = Depends(get_current_user)
):
    """
    Endpoint simplificado que obtiene solo las IPs baneadas con información básica.
    """
    try:
        # Verificar si el jail existe
        if not jail_exists(jail):
            raise HTTPException(status_code=400, detail=f"El jail {jail} no existe.")
        
        # Obtener IPs baneadas
        banned_ips = get_currently_banned_ips(jail)
        
        if not banned_ips:
            return {
                "totalCount": 0,
                "totalPages": 1,
                "hasNextPage": False,
                "hasPreviousPage": False,
                "currentPage": page,
                "values": []
            }
        
        # Crear respuesta con información básica
        entries = []
        current_time = datetime.now()
        
        for ip in banned_ips:
            entries.append({
                "ip": ip,
                "jail": jail,
                "ban_time": current_time.strftime('%Y-%m-%d %H:%M:%S'),
                "failed_attempts": 1,  # Valor por defecto
                "raw_log": f"IP actualmente baneada en jail {jail} (obtenido via fail2ban-client)"
            })
        
        # Paginación
        total_count = len(entries)
        start_idx = page * size
        end_idx = start_idx + size
        paginated_entries = entries[start_idx:end_idx]
        total_pages = math.ceil(total_count / size) if total_count > 0 else 1
        
        return {
            "totalCount": total_count,
            "totalPages": total_pages,
            "hasNextPage": end_idx < total_count,
            "hasPreviousPage": start_idx > 0,
            "currentPage": page,
            "values": paginated_entries
        }
        
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error obteniendo IPs baneadas: {str(e)}")

@router.get("/fail2ban/banned-ips-stats")
async def get_banned_ips_stats(
    jail: str = Query("sshd", description="Nombre del jail de Fail2ban"),
    hours: int = Query(24, ge=1, le=168, description="Rango de tiempo en horas para análisis histórico"),
    current_user: dict = Depends(get_current_user)
):
    """
    Obtiene estadísticas completas sobre IPs baneadas utilizando las funciones disponibles de fail2ban.
    
    Incluye:
    - Conteo actual de IPs baneadas
    - Análisis de amenazas
    - Información de duración de bans
    - Estadísticas de reincidencia
    - Información del jail
    """
    try:
        # Verificar que el jail existe
        if not jail_exists(jail):
            raise HTTPException(status_code=400, detail=f"El jail {jail} no existe.")
        
        print(f"🔍 [DEBUG] Generando estadísticas para jail {jail}")
        
        # 1. Obtener IPs actualmente baneadas
        currently_banned_ips = get_currently_banned_ips(jail)
        current_banned_count = len(currently_banned_ips)
        
        print(f"📊 [DEBUG] IPs actualmente baneadas: {current_banned_count}")
        
        # 2. Obtener información del jail (configuración y contexto)
        jail_context = get_jail_context_info(jail)
        ban_duration_seconds = get_jail_ban_duration(jail)
        peak_attack_hour = get_peak_attack_hour(jail)
        
        # 3. Análisis detallado de cada IP baneada
        ip_analysis = []
        threat_levels = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        total_failed_attempts = 0
        repeat_offenders = 0
        
        for ip in currently_banned_ips:
            # Obtener historial de la IP
            ban_history = get_ip_ban_history(ip, jail, days_back=30)
            
            # Obtener información detallada del ban actual
            ban_info = get_ban_info_from_logs(jail, ip, hours)
            failed_attempts = ban_info.get("failed_attempts", 0)
            total_failed_attempts += failed_attempts
            
            # Obtener información temporal del ban
            temporal_info = get_ban_temporal_info(jail, ip, ban_duration_seconds)
            
            # Calcular nivel de amenaza
            threat_level = calculate_threat_level(ban_history, failed_attempts, jail_context, temporal_info)
            threat_level_name = threat_level.get("level", "LOW")
            threat_levels[threat_level_name] += 1
            
            # Verificar si es reincidente
            if ban_history.get("is_repeat_offender", False):
                repeat_offenders += 1
            
            ip_analysis.append({
                "ip": ip,
                "threat_level": threat_level_name,
                "threat_score": threat_level.get("score", 0),
                "failed_attempts": failed_attempts,
                "previous_bans": ban_history.get("previous_bans_count", 0),
                "is_repeat_offender": ban_history.get("is_repeat_offender", False),
                "first_seen": ban_history.get("first_seen", "Desconocido"),
                "ban_time": ban_info.get("ban_time", "Desconocido"),
                "estimated_unban_time": temporal_info.get("estimated_unban_time", "Desconocido"),
                "time_remaining": temporal_info.get("time_remaining_formatted", "Desconocido")
            })
        
        # 4. Calcular estadísticas agregadas
        avg_failed_attempts = total_failed_attempts / current_banned_count if current_banned_count > 0 else 0
        repeat_offender_rate = (repeat_offenders / current_banned_count * 100) if current_banned_count > 0 else 0
        
        # 5. Formatear duración de ban
        ban_duration_minutes = ban_duration_seconds // 60
        ban_duration_formatted = f"{ban_duration_minutes} minutos"
        if ban_duration_minutes >= 60:
            ban_duration_hours = ban_duration_minutes // 60
            remaining_minutes = ban_duration_minutes % 60
            ban_duration_formatted = f"{ban_duration_hours}h {remaining_minutes}m"
        
        # 6. TOP 5 IPs más peligrosas (por threat score)
        top_threat_ips = sorted(ip_analysis, key=lambda x: x["threat_score"], reverse=True)[:5]
        
        # 7. Ordenar análisis por nivel de amenaza para respuesta completa
        ip_analysis.sort(key=lambda x: (
            ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x["threat_level"]),
            -x["threat_score"]
        ), reverse=True)
        
        # 8. Construir respuesta completa
        stats = {
            # Estadísticas generales
            "summary": {
                "jail_name": jail,
                "total_banned_ips": current_banned_count,
                "ban_duration": ban_duration_formatted,
                "ban_duration_seconds": ban_duration_seconds,
                "peak_attack_hour": peak_attack_hour,
                "analysis_period_hours": hours
            },
            
            # Estadísticas de actividad
            "activity_stats": {
                "total_failed_attempts": total_failed_attempts,
                "avg_failed_attempts_per_ip": round(avg_failed_attempts, 2),
                "repeat_offenders_count": repeat_offenders,
                "repeat_offender_rate_percent": round(repeat_offender_rate, 2)
            },
            
            # Distribución por nivel de amenaza
            "threat_distribution": {
                "critical": threat_levels["CRITICAL"],
                "high": threat_levels["HIGH"], 
                "medium": threat_levels["MEDIUM"],
                "low": threat_levels["LOW"]
            },
            
            # Información del jail
            "jail_info": {
                "service_type": jail_context.get("service_type", "Desconocido"),
                "common_attack_patterns": jail_context.get("common_attack_patterns", []),
                "protection_level": jail_context.get("protection_level", "Estándar"),
                "max_retry": jail_context.get("max_retry", "Desconocido"),
                "find_time": jail_context.get("find_time", "Desconocido")
            },
            
            # TOP amenazas
            "top_threats": [
                {
                    "ip": ip_data["ip"],
                    "threat_level": ip_data["threat_level"],
                    "threat_score": ip_data["threat_score"],
                    "failed_attempts": ip_data["failed_attempts"],
                    "previous_bans": ip_data["previous_bans"],
                    "time_remaining": ip_data["time_remaining"]
                }
                for ip_data in top_threat_ips
            ],
            
            # Análisis completo de todas las IPs (opcional, puede ser grande)
            "detailed_analysis": ip_analysis
        }
        
        print(f"✅ [DEBUG] Estadísticas generadas exitosamente para {current_banned_count} IPs")
        
        return stats
        
    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"❌ [DEBUG] Error generando estadísticas: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Error al generar estadísticas de IPs baneadas: {str(e)}"
        )

