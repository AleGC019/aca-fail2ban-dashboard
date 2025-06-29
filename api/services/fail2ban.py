import ipaddress
import subprocess
import os
from fastapi import HTTPException
from typing import Dict, List
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
    
def get_fail2ban_log_path() -> str:
    """
    Obtiene la ruta del archivo de log de Fail2ban usando fail2ban-client.
    """
    try:
        result = subprocess.run(
            ["fail2ban-client", "get", "logtarget"],
            check=True,
            capture_output=True,
            text=True
        )
        log_path = result.stdout.strip()
        if log_path.startswith("FILE:"):
            log_path = log_path.replace("FILE:", "").strip()
        return log_path
    except subprocess.CalledProcessError:
        # Ruta por defecto si el comando falla
        return "/var/log/fail2ban.log"

def get_banned_ips_with_details(jail: str, hours: int = 24) -> List[Dict]:
    """
    Obtiene las IPs baneadas para una jail específica, junto con la hora del ban y el mensaje del log.

    Args:
        jail (str): Nombre del jail (e.g., "sshd").
        hours (int): Rango de tiempo en horas hacia atrás para buscar logs.

    Returns:
        List[Dict]: Lista de diccionarios con ip, jail, ban_time, raw_log.
    """
    # Verificar si el jail existe
    try:
        subprocess.run(
            ["fail2ban-client", "status", jail],
            check=True,
            capture_output=True
        )
    except subprocess.CalledProcessError:
        raise HTTPException(status_code=400, detail=f"El jail {jail} no existe.")

    # Obtener IPs baneadas
    try:
        banned_ips_output = subprocess.run(
            ["fail2ban-client", "get", jail, "banned"],
            check=True,
            capture_output=True,
            text=True
        ).stdout
        
        # Parsear el formato ['IP1', 'IP2', ...] o similar
        # Usar regex para extraer IPs entre comillas simples
        ip_pattern = re.compile(r"'(\d{1,3}(?:\.\d{1,3}){3})'")
        banned_ips = ip_pattern.findall(banned_ips_output.strip())
        
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener IPs baneadas: {str(e)}")

    if not banned_ips:
        return []

    # Obtener la ruta del archivo de log
    #log_file = get_fail2ban_log_path()
    log_file = "/var/log/fail2ban.log"
    if not os.path.exists(log_file):
        raise HTTPException(status_code=500, detail=f"Archivo de log {log_file} no encontrado")

    # Regex para el log de baneo
    ban_pattern = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+'
        r'fail2ban\.actions\s*\[\d+\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+'
        r'Ban\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})$'
    )

    ban_entries = []
    time_limit = datetime.utcnow() - timedelta(hours=hours)

    for ip in banned_ips:
        latest_log = None
        latest_time = None

        try:
            with open(log_file, 'r') as f:
                for line in reversed(list(f)):
                    match = ban_pattern.match(line.strip())
                    if match and match.group('ip') == ip and match.group('jail') == jail:
                        timestamp_str = match.group('timestamp')
                        try:
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
                        except ValueError:
                        # Handle invalid timestamp format gracefully
                            continue
                        break
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail=f"Archivo de log {log_file} no encontrado")
        except PermissionError:
            raise HTTPException(status_code=500, detail=f"Permisos insuficientes para leer {log_file}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al leer el log: {str(e)}")

        if latest_log:
            ban_entries.append(latest_log)
        else:
            ban_entries.append({
                "ip": ip,
                "jail": jail,
                "ban_time": "No disponible",
                "raw_log": "No disponible"
            })

    return ban_entries

def get_banned_ips_with_details_improved(jail: str) -> list:
    """
    Obtiene las IPs baneadas con información detallada usando comandos de fail2ban-client.
    
    Args:
        jail (str): Nombre del jail de Fail2ban (e.g., "sshd").
    
    Returns:
        list: Lista de diccionarios con información de cada IP baneada.
    """
    # Verificar si el jail existe
    if not jail_exists(jail):
        raise HTTPException(status_code=400, detail=f"El jail {jail} no existe.")
    
    # Obtener las IPs actualmente baneadas
    banned_ips = get_currently_banned_ips(jail)
    
    if not banned_ips:
        return []
    
    ban_entries = []
    
    for ip in banned_ips:
        try:
            # Obtener información detallada de la IP baneada
            ban_info = {
                "ip": ip,
                "jail": jail,
                "ban_time": "No disponible",
                "failed_attempts": 0,
                "raw_log": "Obtenido directamente de Fail2ban"
            }
            
            # Intentar obtener el tiempo de ban usando fail2ban-client
            try:
                # Comando para obtener el tiempo de ban (si está disponible)
                process = subprocess.run(
                    ["fail2ban-client", "get", jail, "bantime"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if process.returncode == 0:
                    bantime = int(process.stdout.strip())
                    # Estimar el tiempo de ban (no es exacto, pero es una aproximación)
                    estimated_ban_time = datetime.now() - timedelta(seconds=bantime//2)
                    ban_info["ban_time"] = estimated_ban_time.strftime('%Y-%m-%d %H:%M:%S')
            except Exception as e:
                print(f"No se pudo obtener bantime para {ip}: {str(e)}")
            
            # Intentar obtener el número de fallas usando el historial
            try:
                # Buscar en los logs de fail2ban recientes para obtener más información
                log_info = get_ban_info_from_logs(jail, ip)
                if log_info:
                    ban_info.update(log_info)
            except Exception as e:
                print(f"No se pudo obtener información del log para {ip}: {str(e)}")
            
            ban_entries.append(ban_info)
            
        except Exception as e:
            print(f"Error procesando IP {ip}: {str(e)}")
            ban_entries.append({
                "ip": ip,
                "jail": jail,
                "ban_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "failed_attempts": 1,
                "raw_log": f"Error al obtener detalles: {str(e)}"
            })
    
    return ban_entries

def get_ban_info_from_logs(jail: str, ip: str, hours: int = 24) -> dict:
    """
    Busca información específica de ban en los logs de fail2ban.
    
    Args:
        jail (str): Nombre del jail
        ip (str): Dirección IP a buscar
        hours (int): Horas hacia atrás para buscar
    
    Returns:
        dict: Información del ban encontrada en los logs
    """
    log_files = [
        "/var/log/fail2ban.log",
        "/var/log/syslog",
        "/var/log/messages"
    ]
    
    # Regex para diferentes formatos de log de fail2ban
    ban_patterns = [
        # Formato estándar de fail2ban.log
        re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+'
            r'fail2ban\.actions\s*\[\d+\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+'
            r'Ban\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
        ),
        # Formato de syslog
        re.compile(
            r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+'
            r'fail2ban\.actions\[\d+\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+'
            r'Ban\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
        )
    ]
    
    time_limit = datetime.now() - timedelta(hours=hours)
    
    for log_file in log_files:
        try:
            if not os.path.exists(log_file):
                continue
                
            with open(log_file, 'r') as f:
                lines = f.readlines()
                
                # Leer desde el final para encontrar el más reciente
                for line in reversed(lines):
                    line = line.strip()
                    
                    for pattern in ban_patterns:
                        match = pattern.search(line)
                        if match and match.group('ip') == ip and match.group('jail') == jail:
                            timestamp_str = match.group('timestamp')
                            
                            try:
                                # Intentar parsear diferentes formatos de timestamp
                                if ',' in timestamp_str:  # Formato con microsegundos
                                    ban_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                                else:  # Formato syslog
                                    current_year = datetime.now().year
                                    ban_time = datetime.strptime(f"{current_year} {timestamp_str}", '%Y %b %d %H:%M:%S')
                                
                                if ban_time >= time_limit:
                                    return {
                                        "ban_time": ban_time.strftime('%Y-%m-%d %H:%M:%S'),
                                        "failed_attempts": get_failed_attempts_count(jail, ip, ban_time),
                                        "raw_log": line
                                    }
                            except ValueError as e:
                                print(f"Error parseando timestamp {timestamp_str}: {str(e)}")
                                continue
                                
        except Exception as e:
            print(f"Error leyendo {log_file}: {str(e)}")
            continue
    
    return None

def get_failed_attempts_count(jail: str, ip: str, ban_time: datetime, window_minutes: int = 60) -> int:
    """
    Cuenta los intentos fallidos que llevaron al ban de una IP.
    
    Args:
        jail (str): Nombre del jail
        ip (str): Dirección IP
        ban_time (datetime): Tiempo del ban
        window_minutes (int): Ventana de tiempo en minutos para contar intentos
    
    Returns:
        int: Número de intentos fallidos encontrados
    """
    log_files = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog"
    ]
    
    # Patrones para diferentes tipos de fallos según el jail
    failure_patterns = {
        'sshd': [
            re.compile(r'Failed password for .* from ' + re.escape(ip)),
            re.compile(r'Invalid user .* from ' + re.escape(ip)),
            re.compile(r'authentication failure.*rhost=' + re.escape(ip))
        ],
        'apache': [
            re.compile(r'client ' + re.escape(ip) + '.*File does not exist'),
            re.compile(r'client ' + re.escape(ip) + '.*not found')
        ]
    }
    
    patterns = failure_patterns.get(jail, failure_patterns['sshd'])
    start_time = ban_time - timedelta(minutes=window_minutes)
    failed_count = 0
    
    for log_file in log_files:
        try:
            if not os.path.exists(log_file):
                continue
                
            with open(log_file, 'r') as f:
                for line in f:
                    # Buscar patrones de fallo para esta IP
                    for pattern in patterns:
                        if pattern.search(line):
                            # Intentar extraer timestamp de la línea
                            timestamp_match = re.search(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
                            if timestamp_match:
                                try:
                                    timestamp_str = timestamp_match.group(1)
                                    log_time = datetime.strptime(f"{ban_time.year} {timestamp_str}", '%Y %b %d %H:%M:%S')
                                    
                                    if start_time <= log_time <= ban_time:
                                        failed_count += 1
                                except ValueError:
                                    continue
                            break
                            
        except Exception as e:
            print(f"Error contando fallos en {log_file}: {str(e)}")
            continue
    
    return failed_count if failed_count > 0 else 1  # Mínimo 1 intento para causar el ban