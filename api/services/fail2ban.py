import ipaddress
import subprocess
from fastapi import HTTPException
from typing import List
import re

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
    try:
        process = subprocess.run(
            ["fail2ban-client", "get", jail_name, "banned"],
            capture_output=True,
            text=True,
            timeout=10
        )
        print(f"Comando: fail2ban-client get {jail_name} banned")
        print(f"Return code: {process.returncode}")
        print(f"Salida: {process.stdout}")
        print(f"Error: {process.stderr}")
        
        if process.returncode != 0:
            print(f"Error al verificar IPs baneadas: {process.stderr}")
            return False
        
        output = process.stdout.strip()
        if not output:
            print("No hay IPs baneadas")
            return False
        
        # Parsear el formato ['IP1', 'IP2', ...]
        ip_pattern = re.compile(r"'(\d{1,3}(?:\.\d{1,3}){3})'")
        banned_ips = ip_pattern.findall(output)
        
        print(f"IPs baneadas parseadas: {banned_ips}")
        return ip_address in banned_ips
    except subprocess.TimeoutExpired:
        print("Timeout al ejecutar fail2ban-client get banned")
        return False
    except FileNotFoundError:
        print("fail2ban-client no encontrado")
        return False
    except Exception as e:
        print(f"Excepción en is_ip_banned: {str(e)}")
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
def get_currently_banned_ips(jail_name: str) -> List[str]:
    try:
        process = subprocess.run(
            ["fail2ban-client", "get", jail_name, "banned"],
            capture_output=True,
            text=True,
            timeout=10
        )
        print(f"Comando: fail2ban-client get {jail_name} banned")
        print(f"Salida: {process.stdout}")
        print(f"Error: {process.stderr}")
        
        if process.returncode != 0:
            print(f"Error al obtener IPs baneadas: {process.stderr}")
            return []
        
        output = process.stdout.strip()
        if not output:
            print("No hay IPs baneadas")
            return []
        
        ip_pattern = re.compile(r"'(\d{1,3}(?:\.\d{1,3}){3})'")
        banned_ips = ip_pattern.findall(output)
        
        print(f"IPs baneadas en {jail_name}: {banned_ips}")
        return banned_ips
    except Exception as e:
        print(f"Error al obtener IPs baneadas para {jail_name}: {str(e)}")
        return []

def run_fail2ban_command(command_args: List[str]) -> str:
    try:
        process = subprocess.run(
            ["fail2ban-client"] + command_args,
            capture_output=True,
            text=True,
            timeout=30
        )
        print(f"Ejecutando comando: {' '.join(command_args)}, Salida: {process.stdout}, Error: {process.stderr}")
        if process.returncode != 0:
            stdout_lower = process.stdout.lower()
            if "is not banned" in stdout_lower or "already banned" in stdout_lower:
                return process.stdout.strip()
            raise ValueError(process.stderr.strip() or process.stdout.strip() or "Error desconocido en Fail2ban.")
        return process.stdout.strip() or "Comando ejecutado sin salida."
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="fail2ban-client no encontrado.")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Tiempo de espera agotado al ejecutar el comando Fail2ban.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al ejecutar Fail2ban: {str(e)}")