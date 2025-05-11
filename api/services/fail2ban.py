import subprocess, re
from fastapi import HTTPException
from typing import List

def is_valid_ip(ip: str) -> bool:
    return re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip) is not None

def run_fail2ban_command(command_args: List[str]) -> str:
    try:
        process = subprocess.run(["fail2ban-client"] + command_args, capture_output=True, text=True)
        if process.returncode != 0:
            if "is not banned" in process.stdout or "already banned" in process.stdout:
                return process.stdout.strip()
            raise HTTPException(status_code=400, detail=process.stderr.strip() or process.stdout.strip())
        return process.stdout.strip() or "Comando ejecutado sin salida."
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="fail2ban-client no encontrado.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al ejecutar Fail2ban: {str(e)}")
