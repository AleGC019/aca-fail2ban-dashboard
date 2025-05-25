import ipaddress
import subprocess
from fastapi import HTTPException
from typing import List


def is_valid_ip(ip: str) -> bool:
    """Valida si la cadena es una dirección IP válida (IPv4 o IPv6)."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def jail_exists(jail_name: str) -> bool:
    """Verifica si el jail especificado existe en Fail2ban."""
    try:
        process = subprocess.run(
            ["fail2ban-client", "status", jail_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        return process.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        return False

def is_ip_banned(jail_name: str, ip_address: str) -> bool:
    """Verifica si la IP está baneada en el jail especificado."""
    try:
        process = subprocess.run(
            ["fail2ban-client", "get", jail_name, "banned"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if process.returncode != 0:
            return False
        # La salida de 'banned' es una lista de IPs, una por línea
        banned_ips = process.stdout.strip().split("\n")
        return ip_address in banned_ips
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

#def run_fail2ban_command(command_args: List[str]) -> str:
#    try:
#        process = subprocess.run(
#            ["fail2ban-client"] + command_args, capture_output=True, text=True
#        )
#        if process.returncode != 0:
#            if "is not banned" in process.stdout or "already banned" in process.stdout:
#                return process.stdout.strip()
#            raise HTTPException(
#                status_code=400, detail=process.stderr.strip() or process.stdout.strip()
#            )
#        return process.stdout.strip() or "Comando ejecutado sin salida."
#    except FileNotFoundError:
#        raise HTTPException(status_code=500, detail="fail2ban-client no encontrado.")
#    except Exception as e:
#        raise HTTPException(
#            status_code=500, detail=f"Error al ejecutar Fail2ban: {str(e)}"
#        )

def run_fail2ban_command(command_args: List[str]) -> str:
    """Ejecuta un comando de fail2ban-client y maneja errores."""
    try:
        process = subprocess.run(
            ["fail2ban-client"] + command_args,
            capture_output=True,
            text=True,
            timeout=30
        )
        if process.returncode != 0:
            # Manejar casos específicos de Fail2ban
            stdout_lower = process.stdout.lower()
            if "is not banned" in stdout_lower or "already banned" in stdout_lower:
                return process.stdout.strip()
            raise HTTPException(
                status_code=400,
                detail=process.stderr.strip() or process.stdout.strip() or "Error desconocido en Fail2ban."
            )
        return process.stdout.strip() or "Comando ejecutado sin salida."
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="fail2ban-client no encontrado.")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Tiempo de espera agotado al ejecutar el comando Fail2ban.")
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error al ejecutar Fail2ban: {str(e)}"
        )