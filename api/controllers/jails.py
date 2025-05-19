from fastapi import APIRouter, HTTPException
from data.models import IPActionRequest, ActionResponse
from services.fail2ban import run_fail2ban_command, is_valid_ip
from typing import List

router = APIRouter()


@router.post("/jails/{jail_name}/ban-ip", response_model=ActionResponse)
async def ban_ip_in_jail(jail_name: str, request_body: IPActionRequest):
    if not is_valid_ip(request_body.ip_address):
        raise HTTPException(status_code=400, detail="Formato de dirección IP inválido.")
    output = run_fail2ban_command(["set", jail_name, "banip", request_body.ip_address])
    return ActionResponse(
        status="success",
        message=f"IP {request_body.ip_address} baneada.",
        ip_address=request_body.ip_address,
        jail=jail_name,
        command_output=output,
    )


@router.post("/jails/{jail_name}/unban-ip", response_model=ActionResponse)
async def unban_ip_in_jail(jail_name: str, request_body: IPActionRequest):
    if not is_valid_ip(request_body.ip_address):
        raise HTTPException(status_code=400, detail="Formato de dirección IP inválido.")
    output = run_fail2ban_command(
        ["set", jail_name, "unbanip", request_body.ip_address]
    )
    return ActionResponse(
        status="success",
        message=f"IP {request_body.ip_address} desbaneada.",
        ip_address=request_body.ip_address,
        jail=jail_name,
        command_output=output,
    )


@router.get("/jails", response_model=List[str])
async def get_jails():
    output = run_fail2ban_command(["status"])
    line = next(
        (
            line_content
            for line_content in output.split("\n")
            if "Jail list:" in line_content
        ),
        None,
    )
    if not line:
        if "no jail" in output.lower():
            return []
        raise HTTPException(
            status_code=500, detail="No se pudo obtener la lista de jails"
        )
    return [j.strip() for j in line.split(":")[1].split(",") if j.strip()]
