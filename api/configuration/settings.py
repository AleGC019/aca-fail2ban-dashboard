import os
from dotenv import load_dotenv

def load_env_or_fail():
    load_dotenv()
    if not os.getenv("LOKI_QUERY_URL"):
        raise RuntimeError("La variable LOKI_QUERY_URL no está configurada")

LOKI_QUERY_URL = os.getenv("LOKI_QUERY_URL")
FAIL2BAN_SOCKET_PATH = "/var/run/fail2ban/fail2ban.sock"


### controllers/logs.py
from fastapi import APIRouter, HTTPException, Query
from data.models import LogEntry
from configuration.settings import LOKI_QUERY_URL
from services.loki import query_loki
from typing import List, Optional

router = APIRouter()

@router.get("/health")
async def health():
    return {"status": "ok", "message": "API de Logs y Gestión de Fail2ban funcionando"}

@router.get("/fail2ban-logs", response_model=List[LogEntry])
async def get_fail2ban_logs(
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    return await query_loki(start, end, limit)
