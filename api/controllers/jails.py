from fastapi import APIRouter, HTTPException
from data.models import IPActionRequest, ActionResponse
from services.fail2ban import is_ip_banned, jail_exists, run_fail2ban_command, is_valid_ip
from typing import List

router = APIRouter()

async def execute_ip_action(jail_name: str, action: str, ip_address: str) -> ActionResponse:
    """Función común para banear o desbanear una IP."""
    if not is_valid_ip(ip_address):
        raise HTTPException(status_code=400, detail="Formato de dirección IP inválido.")
    
    if not jail_exists(jail_name):
        raise HTTPException(status_code=400, detail=f"El jail {jail_name} no existe.")
    
    is_banned = is_ip_banned(jail_name, ip_address)
    action_type = "banip" if action == "ban" else "unbanip"
    expected_action = "Ban" if action == "ban" else "Unban"
    
    if action == "ban" and is_banned:
        return ActionResponse(
            status="info",
            message=f"La IP {ip_address} ya está baneada en el jail {jail_name}.",
            ip_address=ip_address,
            jail=jail_name,
            command_output=None
        )
    elif action == "unban" and not is_banned:
        return ActionResponse(
            status="info",
            message=f"La IP {ip_address} no está baneada en el jail {jail_name}.",
            ip_address=ip_address,
            jail=jail_name,
            command_output=None
        )
    
    output = run_fail2ban_command(["set", jail_name, action_type, ip_address])
    
    # Verificar la salida para confirmar la acción
    status = "success"
    message = f"La IP {ip_address} ha sido {'baneada' if action == 'ban' else 'desbaneada'} en el jail {jail_name}."
    if "already banned" in output.lower():
        status = "info"
        message = f"La IP {ip_address} ya estaba baneada en el jail {jail_name}."
    elif "is not banned" in output.lower():
        status = "info"
        message = f"La IP {ip_address} no estaba baneada en el jail {jail_name}."
    
    return ActionResponse(
        status=status,
        message=message,
        ip_address=ip_address,
        jail=jail_name,
        command_output=output
    )

#@router.post("/jails/{jail_name}/ban-ip", response_model=ActionResponse)
#async def ban_ip_in_jail(jail_name: str, request_body: IPActionRequest):
#    if not is_valid_ip(request_body.ip_address):
#        raise HTTPException(status_code=400, detail="Formato de dirección IP inválido.")
#    output = run_fail2ban_command(["set", jail_name, "banip", request_body.ip_address])
#    return ActionResponse(
#        status="success",
#        message=f"IP {request_body.ip_address} baneada.",
#        ip_address=request_body.ip_address,
#        jail=jail_name,
#        command_output=output,
#    )
#
#
#@router.post("/jails/{jail_name}/unban-ip", response_model=ActionResponse)
#async def unban_ip_in_jail(jail_name: str, request_body: IPActionRequest):
#    if not is_valid_ip(request_body.ip_address):
#        raise HTTPException(status_code=400, detail="Formato de dirección IP inválido.")
#    output = run_fail2ban_command(
#        ["set", jail_name, "unbanip", request_body.ip_address]
#    )
#    return ActionResponse(
#        status="success",
#        message=f"IP {request_body.ip_address} desbaneada.",
#        ip_address=request_body.ip_address,
#        jail=jail_name,
#        command_output=output,
#    )

@router.post("/jails/{jail_name}/ban-ip", response_model=ActionResponse)
async def ban_ip_in_jail(jail_name: str, request_body: IPActionRequest):
    """Banea una IP en el jail especificado."""
    return await execute_ip_action(jail_name, "ban", request_body.ip_address)

@router.post("/jails/{jail_name}/unban-ip", response_model=ActionResponse)
async def unban_ip_in_jail(jail_name: str, request_body: IPActionRequest):
    """Desbanea una IP en el jail especificado."""
    return await execute_ip_action(jail_name, "unban", request_body.ip_address)

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
