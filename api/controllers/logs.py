# controllers/logs.py

from collections import defaultdict
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from httpx import AsyncClient, RequestError, HTTPStatusError
# --- CAMBIO AQUÍ ---
# Se importa LOKI_QUERY_URL directamente, no 'settings'
from configuration.settings import settings
# -------------------
import asyncio

import time
import re
from typing import Optional # Añadido Optional para claridad si se usa
from datetime import datetime
import math
from datetime import timedelta

# Importaciones necesarias que podrían faltar según el contexto completo
# Asegúrate de que estas u otras dependencias necesarias estén aquí si las usas en otras partes del archivo
# from data.models import LogEntry # Necesario si devuelves este modelo en alguna ruta de este archivo
# from services.loki import query_loki # Necesario si llamas a esta función aquí

router = APIRouter()

# --- INICIO: Código de la versión más completa de controllers/logs.py ---

@router.websocket("/ws/fail2ban-logs")
async def websocket_fail2ban_logs(websocket: WebSocket):
    await websocket.accept()

    start_time_ns = int((datetime.utcnow() - timedelta(hours=1)).timestamp() * 1_000_000_000)
    last_timestamp = None
    first_query = True

    eventos_por_minuto = defaultdict(lambda: {"ban": 0, "unban": 0, "found": 0})
    detecciones_por_ip = defaultdict(int)
    tiempos_detect_ban = defaultdict(lambda: {"found": None, "ban": None})

    try:
        while True:
            params = {
                "query": '{job="fail2ban"}',
                "limit": 500,
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
                    await websocket.send_json({"error": f"Error al contactar Loki: {str(exc)}"})
                    await asyncio.sleep(5)
                    continue

            results = response.json().get("data", {}).get("result", [])

            for stream in results:
                values = sorted(stream.get("values", []), key=lambda x: int(x[0]))

                for ts, line in values:
                    if last_timestamp is None or int(ts) > int(last_timestamp):
                        last_timestamp = ts

                    dt = datetime.fromtimestamp(int(ts) / 1_000_000_000)
                    minute = dt.strftime("%H:%M")

                    event_type = ""
                    if "Ban" in line:
                        event_type = "ban"
                    elif "Unban" in line:
                        event_type = "unban"
                    elif "Found" in line:
                        event_type = "found"

                    ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", line)
                    ip = ip_match.group(0) if ip_match else None

                    if event_type:
                        eventos_por_minuto[minute][event_type] += 1

                    if event_type == "found" and ip:
                        detecciones_por_ip[ip] += 1
                        tiempos_detect_ban[ip]["found"] = int(ts)
                    elif event_type == "ban" and ip:
                        tiempos_detect_ban[ip]["ban"] = int(ts)

            # Cálculo de promedio entre detección y baneo
            delays = []
            for ip, t in tiempos_detect_ban.items():
                if t["found"] and t["ban"]:
                    diff = (t["ban"] - t["found"]) / 1_000_000_000
                    if diff >= 0:
                        delays.append(diff)

            avg_delay = round(sum(delays) / len(delays), 2) if delays else 0.0

            # Top 5 IPs
            top_ips = sorted(detecciones_por_ip.items(), key=lambda x: x[1], reverse=True)[:5]
            top_ip_data = [{"ip": ip, "detections": count} for ip, count in top_ips]

            # Tendencia detecciones
            deteccion_trend = [{"minute": m, "count": v["found"]} for m, v in sorted(eventos_por_minuto.items())]

            # Ban/Unban por minuto
            ban_unban = [{"minute": m, "ban": v["ban"], "unban": v["unban"]} for m, v in sorted(eventos_por_minuto.items())]

            # Alertas
            alertas = [{"ip": ip, "attempts": count} for ip, count in detecciones_por_ip.items() if count > 20]

            resumen = {
                "ban_unban_per_minute": ban_unban,
                "detections_per_minute": deteccion_trend,
                "top_ips": top_ip_data,
                "avg_detect_to_ban_sec": avg_delay,
                "alerts": alertas
            }

            try:
                await websocket.send_json(resumen)
            except WebSocketDisconnect:
                print("Cliente desconectado.")
                return

            await asyncio.sleep(5)

    except Exception as e:
        print(f"Error en WebSocket: {str(e)}")
        try:
            await websocket.send_json({"error": f"Error inesperado del servidor: {str(e)}"})
        except Exception:
            pass


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
                importance = max(importance, event_importance_map[event_type], key=lambda x: ["baja", "media", "alta"].index(x))
        

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
    start: Optional[int] = Query(None),
    end: Optional[int] = Query(None),
    service: Optional[str] = Query("fail2ban")
):
    now = int(time.time())
    if end is None:
        end = now
    if start is None:
        start = end - 3600

    # Limita la ventana máxima
    MAX_WINDOW = 3600
    if end - start > MAX_WINDOW:
        start = end - MAX_WINDOW

    window = end - start
    prev_start = start - window
    prev_end = start

    expr_base = f'{{job="{service}"}}'

    async def quick_count(label: str, s: int, e: int) -> int:
        """Usa Loki count_over_time para eventos."""
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
                return 0

    async def fast_ip_count(s: int, e: int) -> int:
        """Cuenta IPs únicas sin sobrecargar Loki."""
        params = {
            "query": f'{expr_base} |= "Found"',
            "start": str(s * 1_000_000_000),
            "end": str(e * 1_000_000_000),
            "limit": 500,
            "direction": "backward"
        }
        async with AsyncClient() as client:
            try:
                res = await client.get(settings.LOKI_QUERY_URL, params=params, timeout=5.0)
                res.raise_for_status()
                results = res.json().get("data", {}).get("result", [])
                ips = set()
                for stream in results:
                    for _, line in stream.get("values", []):
                        match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                        if match:
                            ips.add(match.group(0))
                return len(ips)
            except Exception as exc:
                print("IP count error:", exc)
                return 0

    def with_delta(current: int, previous: int):
        if previous == 0:
            return { "value": current, "deltaPct": None }
        delta = round(((current - previous) / previous) * 100, 2)
        return { "value": current, "deltaPct": delta }

    # Ejecutar menos tareas en paralelo
    current_failures, previous_failures, current_bans, previous_bans = await asyncio.gather(
        quick_count("Found", start, end),
        quick_count("Found", prev_start, prev_end),
        quick_count("Ban", start, end),
        quick_count("Ban", prev_start, prev_end),
    )

    current_unbans, previous_unbans = await asyncio.gather(
        quick_count("Unban", start, end),
        quick_count("Unban", prev_start, prev_end),
    )

    current_ips, previous_ips = await asyncio.gather(
        fast_ip_count(start, end),
        fast_ip_count(prev_start, prev_end),
    )

    current_active_bans = current_bans - current_unbans
    previous_active_bans = previous_bans - previous_unbans

    return {
        "overview": {
            "totalFailures": with_delta(current_failures, previous_failures),
            "totalBans":     with_delta(current_bans, previous_bans),
            "uniqueIPs":     with_delta(current_ips, previous_ips),
            "activeBans":    with_delta(current_active_bans, previous_active_bans),
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

