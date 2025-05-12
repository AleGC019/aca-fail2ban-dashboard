# api/controllers/logs.py

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from httpx import AsyncClient, RequestError, HTTPStatusError

# --- CORRECCIÓN DE IMPORTACIÓN ---
# Originalmente tenías:
# from configuration.settings import settings # <<< INCORRECTO, 'settings' no es un objeto exportado
# Lo cambiamos para importar directamente la variable que necesitas:
from configuration.settings import LOKI_QUERY_URL  # <<< CORRECTO
# --- FIN DE CORRECCIÓN DE IMPORTACIÓN ---

from data.models import LogEntry  # Para el endpoint simple /fail2ban-logs
from services.loki import query_loki as service_query_loki  # Para el endpoint simple /fail2ban-logs
from typing import List, Optional
import asyncio
import time
import re

router = APIRouter()


# Endpoint de Health Check (ya estaba bien)
@router.get("/health")
async def health():
    return {"status": "ok", "message": "API de Logs y Gestión de Fail2ban funcionando"}


# Endpoint original para /fail2ban-logs (este usaba un servicio que ya importaba bien LOKI_QUERY_URL)
# Lo renombro ligeramente para evitar confusión si quieres mantener ambos endpoints de logs por ahora.
@router.get("/fail2ban-logs-simple", response_model=List[LogEntry])
async def get_fail2ban_logs_original(
        start: Optional[str] = Query(None,
                                     description="RFC3339 o timestamp UNIX (ns) para el inicio del rango de tiempo."),
        end: Optional[str] = Query(None, description="RFC3339 o timestamp UNIX (ns) para el fin del rango de tiempo."),
        limit: int = Query(100, ge=1, le=1000, description="Número máximo de entradas de log a devolver."),
):
    # El servicio 'service_query_loki' ya maneja la lógica y la importación de LOKI_QUERY_URL correctamente.
    return await service_query_loki(start, end, limit)


# WebSocket para recibir logs de fail2ban en tiempo real
@router.websocket("/ws/fail2ban-logs")
async def websocket_fail2ban_logs(websocket: WebSocket):
    await websocket.accept()
    last_timestamp_ns_str = None  # Guardar el último timestamp como string (como viene de Loki)

    try:
        while True:
            params = {
                "query": '{job="fail2ban"}',
                "limit": 50,  # Traer un lote razonable
                "direction": "forward"  # Traer los más viejos primero para procesar en orden
            }

            if last_timestamp_ns_str:
                # Sumar 1 nanosegundo para evitar traer el mismo log otra vez
                params["start"] = str(int(last_timestamp_ns_str) + 1)
            else:
                # Para la primera carga, traer logs de, por ejemplo, los últimos 5 minutos
                params["start"] = str(int(time.time() - 300) * 1_000_000_000)

            async with AsyncClient() as client:
                try:
                    # --- CORRECCIÓN DE USO ---
                    # Usar la variable LOKI_QUERY_URL importada directamente
                    response = await client.get(LOKI_QUERY_URL, params=params, timeout=10.0)  # <<< USO CORREGIDO
                    # --- FIN DE CORRECCIÓN DE USO ---
                    response.raise_for_status()
                except (RequestError, HTTPStatusError) as exc:
                    await websocket.send_json({"error": f"Error al contactar Loki: {str(exc)}"})
                    await asyncio.sleep(5)
                    continue

            data = response.json().get("data", {})
            results = data.get("result", [])

            new_logs_found_in_batch = False
            if results:
                all_values_from_batch = []
                for stream in results:
                    # Podrías querer enviar las etiquetas del stream también
                    # stream_labels = stream.get("stream", {}) 
                    for ts, line in stream.get("values", []):
                        all_values_from_batch.append({"timestamp": ts, "message": line})  # "labels": stream_labels

                # Ordenar por timestamp (ya que 'direction: forward' los trae ordenados por stream, pero aquí los mezclamos)
                all_values_from_batch.sort(key=lambda x: int(x["timestamp"]))

                for log_data in all_values_from_batch:
                    await websocket.send_json(log_data)
                    last_timestamp_ns_str = log_data["timestamp"]  # Actualizar con el último timestamp enviado
                    new_logs_found_in_batch = True

            # Ajustar el tiempo de espera
            if new_logs_found_in_batch:
                await asyncio.sleep(1)  # Hay actividad, revisa pronto
            else:
                await asyncio.sleep(5)  # No hay nuevos logs, espera un poco más

    except WebSocketDisconnect:
        print(f"Cliente WebSocket {websocket.client} desconectado")
    except Exception as e:
        error_message = f"Error inesperado en WebSocket: {str(e)}"
        print(error_message)
        try:
            await websocket.send_json({"error": error_message})
        except Exception:
            pass  # Si el socket ya está cerrado, no se puede enviar el error
        # Uvicorn suele manejar el cierre del websocket en excepciones no controladas
        # await websocket.close()


# Ruta para obtener las IPs baneadas (ejemplo, podrías necesitar Pydantic models para la respuesta)
@router.get("/fail2ban/banned-ips", response_model=List[dict])  # Usar un Pydantic model aquí es mejor
async def get_banned_ips(
        page: int = Query(0, ge=0, description="Número de página (inicia en 0)."),
        size: int = Query(10, ge=1, le=100, description="Tamaño de página."),
):
    # Consulta por logs que contengan "Ban" en el mensaje en la última hora
    start_time_ns = int(time.time() - 3600) * 1_000_000_000  # Última hora en nanosegundos

    params = {
        "query": '{job="fail2ban"} |= "Ban"',
        "start": str(start_time_ns),
        "limit": 500,  # Trae un buen número para poder parsear y paginar
        "direction": "forward"
    }

    parsed_ban_entries = []

    async with AsyncClient() as client:
        try:
            # --- CORRECCIÓN DE USO ---
            response = await client.get(LOKI_QUERY_URL, params=params, timeout=10.0)  # <<< USO CORREGIDO
            # --- FIN DE CORRECCIÓN DE USO ---
            response.raise_for_status()
        except (RequestError, HTTPStatusError) as exc:
            raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {str(exc)}")

    results = response.json().get("data", {}).get("result", [])

    raw_log_lines_with_ban = []
    for stream in results:
        labels = stream.get("stream", {})
        for ts, line in stream.get("values", []):
            raw_log_lines_with_ban.append({"ts": ts, "line": line, "labels": labels})

    raw_log_lines_with_ban.sort(key=lambda x: int(x["ts"]))  # Ordenar por timestamp

    # Extraer IPs y detalles, evitando duplicados si es necesario (mostrando el ban más reciente por IP)
    # Para esta demo, simplemente listaremos los eventos de ban encontrados.
    for entry in raw_log_lines_with_ban:
        match = re.search(r"Ban\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", entry["line"])
        if match:
            ip = match.group(1)
            # Asumimos que la etiqueta 'component' de Promtail podría ser el jail.
            # Necesitarías verificar si esta etiqueta es la correcta o si necesitas parsear el jail del log.
            jail_from_labels = entry["labels"].get("component", "desconocido")

            parsed_ban_entries.append({
                "ip": ip,
                "jail": jail_from_labels,
                "ban_time": entry["ts"],
                "log_line_preview": entry["line"][:100]  # Muestra un preview del log
            })

    # Aplicar paginación
    start_idx = page * size
    end_idx = start_idx + size
    return parsed_ban_entries[start_idx:end_idx]


# Ruta para obtener logs filtrados con paginación (ejemplo mejorado)
@router.get("/fail2ban/logs", response_model=List[dict])  # Usar un Pydantic model es mejor
async def get_filtered_logs(
        page: int = Query(0, ge=0, description="Número de página (inicia en 0)."),
        size: int = Query(10, ge=1, le=100, description="Número de logs por página."),
        start_time_ns: Optional[int] = Query(None,
                                             description="Inicio del rango de tiempo (timestamp UNIX en nanosegundos)."),
        end_time_ns: Optional[int] = Query(None,
                                           description="Fin del rango de tiempo (timestamp UNIX en nanosegundos)."),
        component: Optional[str] = Query(None,
                                         description="Filtrar por la etiqueta 'component' (ej. 'sshd', 'server')."),
        level: Optional[str] = Query(None,
                                     description="Filtrar por la etiqueta 'level' (ej. 'notice', 'info', 'error')."),
        text_filter: Optional[str] = Query(None,
                                           description="Texto a buscar en el mensaje del log (filtrado de línea)."),
):
    logql_parts = ['{job="fail2ban"}']  # Base de la consulta

    if component:
        logql_parts.append(f', component="{component}"')
    if level:
        logql_parts.append(f', level="{level}"')

    query = "".join(logql_parts)

    if text_filter:  # Filtro de línea se añade después de los selectores de stream
        escaped_text_filter = text_filter.replace('"', '\\"')  # Escapar comillas dobles para LogQL
        query += f' |= "{escaped_text_filter}"'

    params = {
        "query": query,
        "limit": size,  # Traer solo los logs para la página actual
        "direction": "backward"  # Traer los más recientes primero
    }

    # Para paginación con 'start' y 'offset' en Loki, se necesita un enfoque diferente
    # Loki no tiene un 'offset' directo como SQL. La paginación se maneja típicamente
    # trayendo N*page_size logs y luego cortando en el cliente, o usando el timestamp
    # del último log visto en la página anterior como 'end' para la siguiente página (si 'direction' es forward)
    # o como 'start' para la página anterior (si 'direction' es backward).

    # Para esta implementación, si 'page' > 0, ajustaremos 'end' para simular un offset
    # Esto es una simplificación y puede no ser perfectamente preciso o eficiente para grandes datasets.
    # Se requeriría una estrategia más robusta para paginación real en producción.
    # Por ahora, si page > 0, no podemos usar 'limit' y 'start' de forma simple para paginar sin más lógica.

    # Simplificaremos: traeremos una cantidad mayor y paginaremos en Python
    # Traeremos suficientes para cubrir hasta la página actual y un poco más para ver si hay más.
    # OJO: Esto puede ser ineficiente para muchas páginas.
    effective_limit = (page + 1) * size + 1  # Trae un extra para saber si hay más páginas

    if start_time_ns:
        params["start"] = str(start_time_ns)
    if end_time_ns:
        params["end"] = str(end_time_ns)

    params["limit"] = effective_limit  # Sobrescribir el límite para traer suficientes datos

    all_fetched_entries = []
    async with AsyncClient() as client:
        try:
            # --- CORRECCIÓN DE USO ---
            response = await client.get(LOKI_QUERY_URL, params=params, timeout=10.0)  # <<< USO CORREGIDO
            # --- FIN DE CORRECCIÓN DE USO ---
            response.raise_for_status()
        except (RequestError, HTTPStatusError) as exc:
            raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {str(exc)}")

    results = response.json().get("data", {}).get("result", [])

    for stream in results:
        stream_labels = stream.get("stream", {})
        for ts, line_content in stream.get("values", []):
            all_fetched_entries.append({
                "timestamp": ts,
                "message": line_content,
                "labels": stream_labels  # Incluir todas las etiquetas del stream
            })

    # Los logs vienen ordenados por Loki (más recientes primero debido a direction="backward")

    # Aplicar el corte para la paginación
    start_index_for_page = page * size
    end_index_for_page = start_index_for_page + size

    paginated_entries = all_fetched_entries[start_index_for_page:end_index_for_page]

    # Podrías añadir información sobre si hay más páginas
    # has_more_pages = len(all_fetched_entries) > end_index_for_page

    return paginated_entries