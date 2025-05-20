import os
from dotenv import load_dotenv
from fastapi import APIRouter, Query
from pydantic import BaseSettings
from typing import List, Optional
from data.models import LogEntry


# Load environment variables first
def load_env_or_fail():
    load_dotenv()
    if not os.getenv("LOKI_QUERY_URL"):
        raise RuntimeError("La variable LOKI_QUERY_URL no está configurada")


class Settings(BaseSettings):
    LOKI_QUERY_URL: str = os.getenv(
        "LOKI_QUERY_URL", "http://loki:3100/loki/api/v1/query_range"
    )
    FAIL2BAN_SOCKET_PATH: str = "/var/run/fail2ban/fail2ban.sock"


settings = Settings()

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
    # Import here to avoid circular import
    from services.loki import query_loki

    return await query_loki(start, end, limit)
