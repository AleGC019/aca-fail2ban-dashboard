import httpx
from fastapi import HTTPException
from configuration.settings import LOKI_QUERY_URL
from data.models import LogEntry
from typing import List


async def query_loki(start, end, limit) -> List[LogEntry]:
    params = {"query": '{job="fail2ban"}', "limit": limit}
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(LOKI_QUERY_URL, params=params, timeout=10.0)
            resp.raise_for_status()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail=f"Error al contactar Loki: {exc}")
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=exc.response.status_code, detail=exc.response.text
        )

    raw_data = resp.json().get("data", {})
    result = []
    for stream in raw_data.get("result", []):
        labels = stream.get("stream", {})
        for ts, line in stream.get("values", []):
            result.append(LogEntry(timestamp=ts, line=line, labels=labels))
    return result
