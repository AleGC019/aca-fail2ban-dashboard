from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from httpx import AsyncClient, RequestError, HTTPStatusError
from configuration.settings import settings
import asyncio

router = APIRouter()


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
                    response = await client.get(
                        settings.LOKI_QUERY_URL, params=params, timeout=10.0
                    )
                    response.raise_for_status()
                except (RequestError, HTTPStatusError) as exc:
                    await websocket.send_json(
                        {"error": f"Error al contactar Loki: {str(exc)}"}
                    )
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
