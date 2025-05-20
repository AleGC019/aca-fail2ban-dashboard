from pydantic import BaseModel, Field
from typing import Optional


class LogEntry(BaseModel):
    timestamp: str
    line: str
    labels: dict


class IPActionRequest(BaseModel):
    ip_address: str = Field(..., example="192.168.1.100")


class ActionResponse(BaseModel):
    status: str
    message: str
    ip_address: Optional[str] = None
    jail: Optional[str] = None
    command_output: Optional[str] = None
