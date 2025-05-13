# controllers/logs.py

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from httpx import AsyncClient, RequestError, HTTPStatusError
# --- CAMBIO AQUÍ ---
# Se importa LOKI_QUERY_URL directamente, no 'settings'
from configuration.settings import LOKI_QUERY_URL
# -------------------
import asyncio
import time
import re
from typing import List, Optional # Añadido Optional para claridad si se usa
from datetime import datetime

# Importaciones necesarias que podrían faltar según el contexto completo
# Asegúrate de que estas u otras dependencias necesarias estén aquí si las usas en otras partes del archivo
# from data.models import LogEntry # Necesario si devuelves este modelo en alguna ruta de este archivo
# from services.loki import query_loki # Necesario si llamas a esta función aquí

router = APIRouter()

# --- INICIO: Código de la versión más completa de controllers/logs.py ---

# web socket para recibir logs de fail2ban en tiempo real
#@router.websocket("/ws/fail2ban-logs")
#async def websocket_fail2ban_logs(websocket: WebSocket):
#    await websocket.accept()
#    last_timestamp = None
#
#    try:
#        while True:
#            params = {
#                "query": '{job="fail2ban"}',
#                "limit": 100,
#            }
#
#            if last_timestamp:
#                params["start"] = str(int(last_timestamp) + 1) # Suma 1 nanosegundo para evitar duplicados
#
#            async with AsyncClient() as client:
#                try:
#                    # --- CAMBIO AQUÍ ---
#                    # Usa LOKI_QUERY_URL directamente
#                    response = await client.get(LOKI_QUERY_URL, params=params, timeout=10.0)
#                    # -------------------
#                    response.raise_for_status()
#                except (RequestError, HTTPStatusError) as exc:
#                    try:
#                        await websocket.send_json({"error": f"Error al contactar Loki: {str(exc)}"})
#                    except WebSocketDisconnect: # Manejar desconexión si ocurre al enviar error
#                        break
#                    except Exception as send_exc: # Manejar otros errores de envío
#                        print(f"Error al enviar mensaje de error por websocket: {send_exc}")
#                        break # Salir si no se puede enviar
#                    await asyncio.sleep(5)
#                    continue # Reintentar la conexión a Loki
#
#            data = response.json().get("data", {})
#            results = data.get("result", [])
#
#            new_entries = []
#            for stream in results:
#                labels = stream.get("stream", {})
#                service = labels.get("job", "desconocido")
#                level = labels.get("level", "info") # Asumiendo que 'level' puede estar en las etiquetas de Loki
#
#                # Ordenar valores por timestamp (ya suelen venir ordenados, pero por seguridad)
#                values = sorted(stream.get("values", []), key=lambda x: int(x[0]))
#
#                for ts, line in values:
#                    # Actualizar last_timestamp con el timestamp MÁS RECIENTE procesado
#                    if last_timestamp is None or int(ts) > int(last_timestamp):
#                       last_timestamp = ts
#
#                    message_data = {
#                        "timestamp": ts,
#                        "service": service,
#                        "message": line,
#                        "level": level,
#                    }
#                    new_entries.append((int(ts), message_data)) # Guardar con timestamp numérico para ordenar
#
#            # Ordenar todas las entradas nuevas de todos los streams por timestamp
#            new_entries.sort(key=lambda x: x[0])
#
#            # Enviar entradas ordenadas
#            for _, message_data in new_entries:
#                 try:
#                     await websocket.send_json(message_data)
#                 except WebSocketDisconnect:
#                     print("Cliente desconectado mientras se enviaban mensajes.")
#                     return # Salir de la función si el cliente se desconecta
#                 except Exception as send_exc:
#                     print(f"Error al enviar mensaje por websocket: {send_exc}")
#                     # Considerar si continuar o detenerse ante errores de envío
#
#            # Esperar antes de la siguiente consulta
#            await asyncio.sleep(5)
#
#    except WebSocketDisconnect:
#        print("Cliente desconectado.")
#    except Exception as e:
#        print(f"Error inesperado en el websocket: {str(e)}")
#        # Intentar enviar un mensaje de error final si la conexión aún está activa
#        try:
#            await websocket.send_json({"error": f"Error inesperado del servidor: {str(e)}"})
#        except Exception as final_send_exc:
#             print(f"No se pudo enviar el mensaje de error final: {final_send_exc}")
#        finally:
#             # Asegurarse de cerrar el websocket en caso de error inesperado no manejado
#             # await websocket.close() # Comentado porque uvicorn/fastapi suelen manejarlo
#             pass
@router.websocket("/ws/fail2ban-logs")
async def websocket_fail2ban_logs(websocket: WebSocket):
    await websocket.accept()
    last_timestamp = None

    try:
        while True:
            params = {
                "query": '{job="fail2ban"}',  # Puedes filtrar más si necesitas
                "limit": 100,
            }

            if last_timestamp:
                params["start"] = str(int(last_timestamp) + 1)  # Sumar 1 nanosegundo para evitar duplicados

            async with AsyncClient() as client:
                try:
                    response = await client.get(LOKI_QUERY_URL, params=params, timeout=10.0)
                    response.raise_for_status()
                except (RequestError, HTTPStatusError) as exc:
                    try:
                        await websocket.send_json({"error": f"Error al contactar Loki: {str(exc)}"})
                    except WebSocketDisconnect:
                        break  # Cliente desconectado, salimos del loop
                    except Exception as send_exc:
                        print(f"Error al enviar mensaje por websocket: {send_exc}")
                        break
                    await asyncio.sleep(5)  # Reintentar después de 5 segundos
                    continue

            data = response.json().get("data", {})
            results = data.get("result", [])

            new_entries = []
            for stream in results:
                labels = stream.get("stream", {})
                service = labels.get("job", "desconocido")
                level = labels.get("level", "info")  # Asumir "info" si no se encuentra

                values = sorted(stream.get("values", []), key=lambda x: int(x[0]))

                for ts, line in values:
                    if last_timestamp is None or int(ts) > int(last_timestamp):
                        last_timestamp = ts

                    message_data = {
                        "timestamp": datetime.fromtimestamp(int(ts) / 1_000_000_000).strftime("%Y-%m-%d %H:%M:%S"),
                        "service": service,
                        "message": line,
                        "level": level,
                    }
                    new_entries.append((int(ts), message_data))  # Guardar con timestamp para ordenar

            # Ordenar las nuevas entradas por timestamp (de más reciente a más antiguo)
            new_entries.sort(key=lambda x: x[0], reverse=True)

            # Enviar las entradas ordenadas
            for _, message_data in new_entries:
                try:
                    await websocket.send_json(message_data)
                except WebSocketDisconnect:
                    print("Cliente desconectado mientras se enviaban mensajes.")
                    return
                except Exception as send_exc:
                    print(f"Error al enviar mensaje por websocket: {send_exc}")

            await asyncio.sleep(5)  # Esperar antes de la siguiente consulta

    except WebSocketDisconnect:
        print("Cliente desconectado.")
    except Exception as e:
        print(f"Error inesperado en el websocket: {str(e)}")
        try:
            await websocket.send_json({"error": f"Error inesperado del servidor: {str(e)}"})
        except Exception as final_send_exc:
            print(f"No se pudo enviar el mensaje de error final: {final_send_exc}")


# Ruta pa obtener las ips baneadas (ejemplo basado en logs, NO en estado real de fail2ban-client)
#@router.get("/fail2ban/banned-ips")
#async def get_banned_ips(
#    page: int = Query(0, ge=0, description="Número de página."),
#    size: int = Query(10, ge=1, le=100, description="Tamaño de página."),
#):
#    # Busca logs que contengan "Ban" en la última hora (ajusta según necesidad)
#    # ¡IMPORTANTE!: Esto NO garantiza que la IP siga baneada. Solo muestra IPs que FUERON baneadas.
#    # Para el estado actual, necesitarías usar `fail2ban-client status <jail>` y parsear la salida.
#    start_time_sec = int(time.time()) - 3600 # Última hora
#    start_ns = start_time_sec * 1_000_000_000 # Convertir a nanosegundos
#
#    params = {
#        "query": '{job="fail2ban"} |= "Ban"', # Busca la palabra "Ban"
#        "start": str(start_ns),
#        "limit": 1000, # Obtener un límite mayor para tener suficientes datos para paginar
#                       # Idealmente, Loki soporta paginación, pero aquí simulamos post-filtrado
#        "direction": "forward", # Obtener logs desde el más antiguo al más reciente
#    }
#
#    async with AsyncClient() as client:
#        try:
#            # --- CAMBIO AQUÍ ---
#            response = await client.get(LOKI_QUERY_URL, params=params, timeout=10.0)
#            # -------------------
#            response.raise_for_status()
#        except (RequestError, HTTPStatusError) as exc:
#            raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {str(exc)}")
#
#    results = response.json().get("data", {}).get("result", [])
#    entries = []
#    banned_ips = set() # Para evitar duplicados si una IP es baneada múltiples veces en el rango
#
#    # Procesar resultados en orden cronológico
#    all_values = []
#    for stream in results:
#        labels = stream.get("stream", {})
#        jail = labels.get("jail", "desconocido") # Asumiendo que promtail añade la etiqueta 'jail'
#        for ts, line in stream.get("values", []):
#             all_values.append({'ts': ts, 'line': line, 'jail': jail})
#
#    # Ordenar todos los logs por timestamp
#    all_values.sort(key=lambda x: int(x['ts']))
#
#    for log_entry in all_values:
#        line = log_entry['line']
#        # Expresión regular más robusta para capturar IP en logs de ban
#        match = re.search(r"(?:Ban|already banned)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
#        if match:
#            ip = match.group(1)
#            # Solo añadir si no se ha añadido ya para este periodo de logs
#            if ip not in banned_ips:
#                jail = log_entry['jail']
#                ban_time_ns = log_entry['ts'] # Timestamp en nanosegundos string
#                # Opcional: buscar intentos fallidos si están en el mensaje (esto es muy dependiente del formato del log)
#                attempts_match = re.search(r"\((\d+)\s+failures\)", line) # Ejemplo: "(3 failures)"
#                failed_attempts = int(attempts_match.group(1)) if attempts_match else None
#
#                entries.append({
#                    "ip": ip,
#                    "jail": jail,
#                    "ban_time": ban_time_ns,
#                    "failed_attempts": failed_attempts, # Puede ser None
#                    "raw_log": line # Incluir el log original puede ser útil
#                })
#                banned_ips.add(ip) # Marcar como añadida
#
#    # Aplicar paginación a la lista recolectada y ordenada
#    start_idx = page * size
#    end_idx = start_idx + size
#    # Devolver solo la página solicitada
#    return entries[start_idx:end_idx]
@router.get("/fail2ban/banned-ips")
async def get_banned_ips(
    page: int = Query(0, ge=0, description="Número de página."),
    size: int = Query(10, ge=1, le=100, description="Tamaño de página."),
):
    start_time_sec = int(time.time()) - 3600  # Última hora
    start_ns = start_time_sec * 1_000_000_000

    params = {
        "query": '{job="fail2ban"} |= "Ban"',
        "start": str(start_ns),
        "limit": 1000,
        "direction": "backward",  # <- más reciente primero
    }

    async with AsyncClient() as client:
        try:
            response = await client.get(LOKI_QUERY_URL, params=params, timeout=10.0)
            response.raise_for_status()
        except (RequestError, HTTPStatusError) as exc:
            raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {str(exc)}")

    results = response.json().get("data", {}).get("result", [])
    entries = []
    banned_ips = set()

    all_values = []
    for stream in results:
        labels = stream.get("stream", {})
        jail = labels.get("jail", "desconocido")
        for ts, line in stream.get("values", []):
            all_values.append({'ts': ts, 'line': line, 'jail': jail})

    # Ordenar del más reciente al más antiguo
    all_values.sort(key=lambda x: int(x['ts']), reverse=True)

    for log_entry in all_values:
        line = log_entry['line']
        match = re.search(r"(?:Ban|already banned)\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
        if match:
            ip = match.group(1)
            if ip not in banned_ips:
                jail = log_entry['jail']
                ban_time_ns = int(log_entry['ts'])
                ban_time_str = datetime.utcfromtimestamp(ban_time_ns / 1_000_000_000).strftime('%Y-%m-%d %H:%M:%S')

                # Capturar intentos fallidos (ej. "after 5 failures")
                attempts_match = re.search(r"after\s+(\d+)\s+failures?", line, re.IGNORECASE)
                failed_attempts = int(attempts_match.group(1)) if attempts_match else None

                entries.append({
                    "ip": ip,
                    "jail": jail,
                    "ban_time": ban_time_str,
                    "failed_attempts": failed_attempts,
                    "raw_log": line
                })
                banned_ips.add(ip)

    # Paginación ya en orden descendente
    start_idx = page * size
    end_idx = start_idx + size
    return entries[start_idx:end_idx]


# Ruta para obtener logs filtrados (similar a la función query_loki pero con más filtros)
@router.get("/fail2ban/logs")
async def get_filtered_logs(
    page: int = Query(0, ge=0),
    size: int = Query(10, ge=1, le=100),
    start: Optional[int] = Query(None, description="Inicio del rango de tiempo (timestamp UNIX en segundos)."),
    end: Optional[int] = Query(None, description="Fin del rango de tiempo (timestamp UNIX en segundos)."),
    # 'service' aquí se refiere a la etiqueta 'job' de Loki/Promtail
    service: Optional[str] = Query(None, description="Filtrar por etiqueta 'job' (e.g., 'fail2ban')."),
    level: Optional[str] = Query(None, description="Filtrar por nivel de log (buscar texto en el mensaje)."),
    filter_text: Optional[str] = Query(None, description="Texto libre a buscar en el mensaje del log."),
):
    # Construir la query de LogQL
    query_parts = ['{job="fail2ban"}'] # Base query obligatoria
    if service:
        # Sobrescribe si se especifica, aunque ya filtramos por job="fail2ban"
        # Podría ser útil si tuvieras logs de diferentes jails bajo el mismo job pero con otra etiqueta
        query_parts[0] = f'{{job="{service}"}}' # O añadir como {job="fail2ban", service_label="algo"} si tienes más etiquetas
    if level:
        # Filtrado de línea por nivel (sensible a mayúsculas/minúsculas por defecto en LogQL)
        query_parts.append(f'|= `{level}`') # Usar backticks para buscar la cadena exacta
    if filter_text:
        # Filtrado de línea por texto libre
        query_parts.append(f'|= `{filter_text}`')

    logql_query = " ".join(query_parts)

    params = {
        "query": logql_query,
        "limit": 1000, # Obtener más para paginar después
        "direction": "backward", # Logs más recientes primero por defecto
    }
    if start:
        # Convertir de segundos UNIX a nanosegundos
        params["start"] = str(start * 1_000_000_000)
    if end:
        # Convertir de segundos UNIX a nanosegundos
        params["end"] = str(end * 1_000_000_000)

    async with AsyncClient() as client:
        try:
             # --- CAMBIO AQUÍ ---
            response = await client.get(LOKI_QUERY_URL, params=params, timeout=10.0)
             # -------------------
            response.raise_for_status()
        except (RequestError, HTTPStatusError) as exc:
            raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {str(exc)}")

    results = response.json().get("data", {}).get("result", [])
    entries = []

    # Recolectar todos los valores de todos los streams
    all_values = []
    for stream in results:
        labels = stream.get("stream", {})
        service_name = labels.get("job", "desconocido")
        # Intentar extraer nivel de log (puede no estar como etiqueta)
        level_value = labels.get("level", "info") # O parsearlo del mensaje si es necesario

        for ts, line in stream.get("values", []):
            all_values.append({
                "timestamp": ts, # Mantener como string de nanosegundos
                "service": service_name,
                "message": line,
                "level": level_value # Puede ser 'info' por defecto si no hay etiqueta 'level'
            })

    # Ordenar por timestamp (descendente, ya que pedimos 'backward')
    # Loki debería devolverlos ordenados, pero re-ordenamos por si acaso
    all_values.sort(key=lambda x: int(x['timestamp']), reverse=True)

    # Aplicar paginación
    start_idx = page * size
    end_idx = start_idx + size
    return all_values[start_idx:end_idx]

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

# Esta ruta es más simple que /fail2ban/logs, decide si mantener ambas
# @router.get("/fail2ban-logs", response_model=List[LogEntry]) # Necesitarías importar List y LogEntry
# async def get_fail2ban_logs_simple(
#     start: Optional[str] = Query(None), # Timestamps como strings (formato RFC3339 o Unix epoch ns)
#     end: Optional[str] = Query(None),
#     limit: int = Query(100, ge=1, le=1000),
# ):
#     # Asumiendo que tienes una función query_loki en services.loki
#     # from services.loki import query_loki
#     try:
#         return await query_loki(start, end, limit) # query_loki debe manejar la llamada a LOKI_QUERY_URL
#     except HTTPException as e:
#         raise e # Re-lanzar excepciones HTTP generadas por query_loki
#     except Exception as e:
#         # Capturar otros posibles errores
#         raise HTTPException(status_code=500, detail=f"Error interno al obtener logs: {str(e)}")