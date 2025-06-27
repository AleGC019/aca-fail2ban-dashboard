import ipaddress
import subprocess
from fastapi import HTTPException
from typing import List
import re
from fastapi import HTTPException
import subprocess
import re
from datetime import datetime, timedelta
from dateutil import parser as date_parser

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
    
def get_banned_ips_with_details(jail: str, log_file: str = "/var/log/fail2ban.log", hours: int = 24) -> list:
    """
    Obtiene las IPs baneadas en una jail específica junto con detalles como la hora del ban,
    el mensaje del log y el número de intentos fallidos.

    Args:
        jail (str): Nombre del jail de Fail2ban (e.g., "sshd").
        log_file (str): Ruta al archivo de log de Fail2ban (default: "/var/log/fail2ban.log").
        hours (int): Rango de tiempo en horas hacia atrás para buscar logs (default: 24).

    Returns:
        list: Lista de diccionarios con la información de cada IP baneada.
    """
    # Verificar si el jail existe
    try:
        subprocess.run(["fail2ban-client", "status", jail], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        raise HTTPException(status_code=400, detail=f"El jail {jail} no existe.")

    # Obtener las IPs baneadas
    try:
        banned_ips_output = subprocess.run(["fail2ban-client", "get", jail, "banned"], check=True, capture_output=True).stdout.decode()
        banned_ips = banned_ips_output.strip().split()
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener IPs baneadas: {str(e)}")

    if not banned_ips:
        return []

    # Obtener findtime del jail
    try:
        findtime_output = subprocess.run(["fail2ban-client", "get", jail, "findtime"], check=True, capture_output=True).stdout.decode()
        findtime = int(findtime_output.strip())
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener findtime: {str(e)}")

    # Obtener la ruta del archivo de log del jail (e.g., /var/log/auth.log para SSH)
    try:
        logpath_output = subprocess.run(["fail2ban-client", "get", jail, "logpath"], check=True, capture_output=True).stdout.decode()
        jail_log_file = logpath_output.strip()
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener logpath: {str(e)}")

    # Regex para el log de baneo en /var/log/fail2ban.log
    ban_pattern = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+'
        r'fail2ban\.actions\s*\[\d+\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+'
        r'Ban\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})$'
    )

    # Regex para intentos fallidos en /var/log/auth.log (para SSH)
    failure_pattern = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+.*Failed password for .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*$'
    )

    ban_entries = []
    time_limit = datetime.utcnow() - timedelta(hours=hours)

    for ip in banned_ips:
        latest_log = None
        latest_time = None

        # Buscar el log de baneo más reciente en /var/log/fail2ban.log
        try:
            with open(log_file, 'r') as f:
                for line in reversed(list(f)):  # Leer desde el final para encontrar el más reciente primero
                    match = ban_pattern.match(line.strip())
                    if match and match.group('ip') == ip and match.group('jail') == jail:
                        timestamp_str = match.group('timestamp')
                        ban_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                        if ban_time >= time_limit:
                            if not latest_time or ban_time > latest_time:
                                latest_time = ban_time
                                latest_log = {
                                    "ip": ip,
                                    "jail": jail,
                                    "ban_time": ban_time.strftime('%Y-%m-%d %H:%M:%S'),
                                    "raw_log": line.strip()
                                }
                        break
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al leer el log de Fail2ban: {str(e)}")

        if latest_log:
            # Calcular el período de findtime para contar intentos fallidos
            start_time = latest_time - timedelta(seconds=findtime)
            failed_attempts = 0

            # Contar intentos fallidos en el log del jail
            try:
                with open(jail_log_file, 'r') as f:
                    for line in f:
                        match = failure_pattern.match(line.strip())
                        if match and match.group('ip') == ip:
                            log_time = date_parser.parse(match.group('timestamp') + f" {latest_time.year}")
                            if start_time <= log_time <= latest_time:
                                failed_attempts += 1
            except Exception as e:
                print(f"Error al leer el log del jail: {str(e)}")
                failed_attempts = -1  # Indicador de error

            latest_log["failed_attempts"] = failed_attempts
            ban_entries.append(latest_log)
        else:
            ban_entries.append({
                "ip": ip,
                "jail": jail,
                "ban_time": "No disponible",
                "failed_attempts": -1,
                "raw_log": "No disponible"
            })

    return ban_entries