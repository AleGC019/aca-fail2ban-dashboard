import ipaddress
import subprocess
import os
from fastapi import HTTPException
from typing import Dict, List
import re
from datetime import datetime, timedelta

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
    Cuenta el número de intentos fallidos para una IP específica antes del ban.
    
    Args:
        jail (str): Nombre del jail
        ip (str): Dirección IP
        ban_time (datetime): Tiempo del ban
        window_minutes (int): Ventana de tiempo en minutos antes del ban para buscar
    
    Returns:
        int: Número de intentos fallidos encontrados
    """
    log_files = [
        "/var/log/fail2ban.log",
        "/var/log/syslog",
        "/var/log/messages"
    ]
    
    # Regex para detectar intentos fallidos
    found_patterns = [
        re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+'
            r'fail2ban\.filter\s*\[\d+\]:\s+INFO\s+\[(?P<jail>[^\]]+)\]\s+'
            r'Found\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
        ),
        re.compile(
            r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+'
            r'fail2ban\.filter\[\d+\]:\s+INFO\s+\[(?P<jail>[^\]]+)\]\s+'
            r'Found\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
        )
    ]
    
    failed_attempts = 0
    search_start_time = ban_time - timedelta(minutes=window_minutes)
    
    for log_file in log_files:
        if not os.path.exists(log_file):
            continue
            
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    for pattern in found_patterns:
                        match = pattern.match(line.strip())
                        if match and match.group('ip') == ip and match.group('jail') == jail:
                            timestamp_str = match.group('timestamp')
                            try:
                                if len(timestamp_str.split('-')) == 3:  # Formato YYYY-MM-DD
                                    log_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                                else:  # Formato syslog
                                    current_year = datetime.now().year
                                    log_time = datetime.strptime(f"{current_year} {timestamp_str}", '%Y %b %d %H:%M:%S')
                                
                                if search_start_time <= log_time <= ban_time:
                                    failed_attempts += 1
                            except ValueError:
                                continue
                            break
        except (PermissionError, FileNotFoundError):
            continue
    
    return failed_attempts

def get_jail_ban_duration(jail: str) -> int:
    """
    Obtiene la duración de ban configurada para un jail específico.
    
    Args:
        jail (str): Nombre del jail de Fail2ban
    
    Returns:
        int: Duración del ban en segundos (por defecto 600 = 10 minutos)
    """
    try:
        # TODO: Eliminar print de debug después de las pruebas
        print(f"🔍 [DEBUG] Obteniendo duración de ban para jail {jail}")
        
        # Intentar obtener bantime del jail específico
        process = subprocess.run(
            ["fail2ban-client", "get", jail, "bantime"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        print(f"📊 [DEBUG] Comando: fail2ban-client get {jail} bantime")
        print(f"📊 [DEBUG] Return code: {process.returncode}")
        print(f"📊 [DEBUG] Salida: {process.stdout.strip()}")
        
        if process.returncode == 0:
            bantime_str = process.stdout.strip()
            try:
                bantime_seconds = int(bantime_str)
                print(f"✅ [DEBUG] Ban duration obtenida: {bantime_seconds} segundos")
                return bantime_seconds
            except ValueError:
                print(f"⚠️ [DEBUG] No se pudo parsear bantime: {bantime_str}")
        else:
            print(f"⚠️ [DEBUG] Error al obtener bantime: {process.stderr}")
            
    except subprocess.TimeoutExpired:
        print("⚠️ [DEBUG] Timeout al obtener bantime")
    except FileNotFoundError:
        print("⚠️ [DEBUG] fail2ban-client no encontrado")
    except Exception as e:
        print(f"⚠️ [DEBUG] Excepción al obtener bantime: {str(e)}")
    
    # Valor por defecto: 10 minutos (600 segundos)
    default_bantime = 600
    print(f"🔄 [DEBUG] Usando bantime por defecto: {default_bantime} segundos")
    return default_bantime

def get_ban_temporal_info(jail: str, ip: str, ban_duration_seconds: int) -> dict:
    """
    Calcula información temporal del ban para una IP.
    
    Args:
        jail (str): Nombre del jail
        ip (str): IP baneada
        ban_duration_seconds (int): Duración del ban en segundos
    
    Returns:
        dict: Información temporal del ban
    """
    try:
        # TODO: Eliminar prints de debug después de las pruebas
        print(f"🕒 [DEBUG] Calculando info temporal para {ip} en jail {jail}")
        
        # Obtener cuándo fue baneada la IP usando fail2ban-client
        process = subprocess.run(
            ["fail2ban-client", "get", jail, "banip", "--with-time"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if process.returncode == 0:
            # Parsear salida para encontrar nuestra IP
            ban_start_time = None
            for line in process.stdout.split('\n'):
                if ip in line:
                    # Formato típico: "2025-06-29 06:30:00 + 600 = 2025-06-29 06:40:00"
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            ban_start_time = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S")
                            break
                        except ValueError:
                            continue
            
            if not ban_start_time:
                # Fallback: usar tiempo actual menos una estimación
                ban_start_time = datetime.now() - timedelta(minutes=2)
        else:
            # Fallback si el comando falla
            ban_start_time = datetime.now() - timedelta(minutes=2)
        
        # Calcular tiempos
        now = datetime.now()
        ban_end_time = ban_start_time + timedelta(seconds=ban_duration_seconds)
        
        # Tiempo transcurrido desde el ban
        time_since_ban = now - ban_start_time
        ban_started_ago_seconds = int(time_since_ban.total_seconds())
        
        # Tiempo restante
        time_remaining = ban_end_time - now
        ban_remaining_seconds = max(0, int(time_remaining.total_seconds()))
        
        # Verificar si es ban permanente (valores muy altos)
        is_permanent = ban_duration_seconds > 86400 * 365  # Más de 1 año
        
        temporal_info = {
            "ban_started_ago": format_duration(ban_started_ago_seconds),
            "ban_time_remaining": format_duration(ban_remaining_seconds) if not is_permanent else "Permanente",
            "estimated_unban_time": ban_end_time.strftime('%Y-%m-%d %H:%M:%S') if not is_permanent else "Nunca",
            "is_permanent_ban": is_permanent,
            "ban_start_timestamp": ban_start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "ban_progress_percent": min(100, (ban_started_ago_seconds / ban_duration_seconds) * 100) if ban_duration_seconds > 0 else 0
        }
        
        print(f"✅ [DEBUG] Info temporal para {ip}: {temporal_info}")
        return temporal_info
        
    except Exception as e:
        print(f"❌ [DEBUG] Error calculando info temporal para {ip}: {str(e)}")
        return {
            "ban_started_ago": "Desconocido",
            "ban_time_remaining": "Desconocido", 
            "estimated_unban_time": "Desconocido",
            "is_permanent_ban": False,
            "ban_start_timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "ban_progress_percent": 0
        }

def get_ip_ban_history(ip: str, jail: str = None, days_back: int = 30) -> dict:
    """
    Obtiene el historial de bans de una IP específica.
    
    Args:
        ip (str): IP a consultar
        jail (str): Jail específico o None para todos
        days_back (int): Días hacia atrás para buscar
    
    Returns:
        dict: Historial de bans de la IP
    """
    try:
        # TODO: Eliminar prints de debug después de las pruebas
        print(f"📜 [DEBUG] Obteniendo historial para IP {ip} en jail {jail or 'todos'}")
        
        log_files = ["/var/log/fail2ban.log"]
        
        # Patrones para encontrar bans y unbans
        ban_pattern = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+'
            r'fail2ban\.actions\s*\[\d+\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+'
            r'Ban\s+' + re.escape(ip)
        )
        
        unban_pattern = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+'
            r'fail2ban\.actions\s*\[\d+\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+'
            r'Unban\s+' + re.escape(ip)
        )
        
        ban_events = []
        unban_events = []
        time_limit = datetime.now() - timedelta(days=days_back)
        
        for log_file in log_files:
            if not os.path.exists(log_file):
                continue
                
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        # Buscar bans
                        ban_match = ban_pattern.match(line.strip())
                        if ban_match:
                            jail_match = ban_match.group('jail')
                            if jail is None or jail_match == jail:
                                try:
                                    event_time = datetime.strptime(ban_match.group('timestamp'), '%Y-%m-%d %H:%M:%S,%f')
                                    if event_time >= time_limit:
                                        ban_events.append({
                                            "timestamp": event_time,
                                            "jail": jail_match,
                                            "type": "ban"
                                        })
                                except ValueError:
                                    continue
                        
                        # Buscar unbans
                        unban_match = unban_pattern.match(line.strip())
                        if unban_match:
                            jail_match = unban_match.group('jail')
                            if jail is None or jail_match == jail:
                                try:
                                    event_time = datetime.strptime(unban_match.group('timestamp'), '%Y-%m-%d %H:%M:%S,%f')
                                    if event_time >= time_limit:
                                        unban_events.append({
                                            "timestamp": event_time,
                                            "jail": jail_match,
                                            "type": "unban"
                                        })
                                except ValueError:
                                    continue
                                    
            except (PermissionError, FileNotFoundError):
                continue
        
        # Determinar si es reincidente
        total_bans = len(ban_events)
        is_repeat_offender = total_bans > 1
        
        # Encontrar primer y último ban
        first_seen = min([event["timestamp"] for event in ban_events]) if ban_events else None
        last_ban = max([event["timestamp"] for event in ban_events]) if ban_events else None
        
        # Calcular frecuencia
        if total_bans > 0 and first_seen:
            days_span = max(1, (datetime.now() - first_seen).days)
            bans_per_day = total_bans / days_span
            if bans_per_day > 1:
                frequency = "alta"
            elif bans_per_day > 0.3:
                frequency = "media"
            else:
                frequency = "baja"
        else:
            frequency = "desconocida"
        
        history_info = {
            "previous_bans_count": max(0, total_bans - 1),  # Excluyendo el ban actual
            "total_bans_ever": total_bans,
            "total_unbans": len(unban_events),
            "first_seen": first_seen.strftime('%Y-%m-%d %H:%M:%S') if first_seen else "Desconocido",
            "last_ban_before": last_ban.strftime('%Y-%m-%d %H:%M:%S') if last_ban else "Primer ban",
            "is_repeat_offender": is_repeat_offender,
            "attack_frequency": frequency,
            "days_since_first_seen": (datetime.now() - first_seen).days if first_seen else 0
        }
        
        print(f"✅ [DEBUG] Historial para {ip}: {history_info}")
        return history_info
        
    except Exception as e:
        print(f"❌ [DEBUG] Error obteniendo historial para {ip}: {str(e)}")
        return {
            "previous_bans_count": 0,
            "total_bans_ever": 1,
            "total_unbans": 0,
            "first_seen": "Desconocido",
            "last_ban_before": "Primer ban",
            "is_repeat_offender": False,
            "attack_frequency": "desconocida",
            "days_since_first_seen": 0
        }

def get_jail_context_info(jail: str) -> dict:
    """
    Obtiene información de contexto y configuración del jail.
    
    Args:
        jail (str): Nombre del jail
    
    Returns:
        dict: Información del contexto del jail
    """
    try:
        # TODO: Eliminar prints de debug después de las pruebas
        print(f"🏢 [DEBUG] Obteniendo contexto del jail {jail}")
        
        jail_info = {}
        
        # Obtener configuración básica del jail
        config_commands = {
            "maxretry": ["fail2ban-client", "get", jail, "maxretry"],
            "findtime": ["fail2ban-client", "get", jail, "findtime"],
            "bantime": ["fail2ban-client", "get", jail, "bantime"]
        }
        
        for config_name, command in config_commands.items():
            try:
                process = subprocess.run(command, capture_output=True, text=True, timeout=5)
                if process.returncode == 0:
                    value = process.stdout.strip()
                    jail_info[config_name] = int(value) if value.isdigit() else value
                else:
                    jail_info[config_name] = "N/A"
            except Exception:
                jail_info[config_name] = "N/A"
        
        # Obtener estadísticas actuales
        try:
            # Total de IPs baneadas actualmente
            current_banned = get_currently_banned_ips(jail)
            jail_info["current_banned_total"] = len(current_banned)
        except Exception:
            jail_info["current_banned_total"] = 0
        
        # Estimar eficiencia y estadísticas del día (simplificado)
        try:
            # Contar bans de hoy en los logs
            today_bans = count_todays_bans(jail)
            jail_info["bans_today"] = today_bans
            
            # Calcular una eficiencia estimada (simplificada)
            if jail_info.get("maxretry", 0) > 0:
                efficiency = min(100, (today_bans / max(1, jail_info["maxretry"])) * 20)  # Fórmula simplificada
                jail_info["jail_efficiency"] = round(efficiency, 1)
            else:
                jail_info["jail_efficiency"] = 0.0
                
        except Exception:
            jail_info["bans_today"] = 0
            jail_info["jail_efficiency"] = 0.0
        
        # Hora pico de ataques (simplificado - podría ser más sofisticado)
        jail_info["top_attack_hour"] = get_peak_attack_hour(jail)
        
        print(f"✅ [DEBUG] Contexto del jail {jail}: {jail_info}")
        return jail_info
        
    except Exception as e:
        print(f"❌ [DEBUG] Error obteniendo contexto del jail {jail}: {str(e)}")
        return {
            "maxretry": "N/A",
            "findtime": "N/A", 
            "bantime": "N/A",
            "current_banned_total": 0,
            "bans_today": 0,
            "jail_efficiency": 0.0,
            "top_attack_hour": "N/A"
        }

def calculate_threat_level(ban_history: dict, failed_attempts: int, jail_context: dict, temporal_info: dict) -> dict:
    """
    Calcula el nivel de amenaza basado en múltiples factores.
    
    Args:
        ban_history (dict): Historial de bans de la IP
        failed_attempts (int): Número de intentos fallidos
        jail_context (dict): Contexto del jail
        temporal_info (dict): Información temporal
    
    Returns:
        dict: Nivel de amenaza y recomendaciones
    """
    try:
        
        score = 0
        reasons = []
        
        # Factor 1: Historial de reincidencia (0-3 puntos)
        if ban_history.get("is_repeat_offender", False):
            repeat_score = min(3, ban_history.get("previous_bans_count", 0))
            score += repeat_score
            if repeat_score > 0:
                reasons.append(f"Reincidente ({ban_history.get('previous_bans_count', 0)} bans previos)")
        
        # Factor 2: Frecuencia de ataques (0-2 puntos)
        frequency = ban_history.get("attack_frequency", "baja")
        if frequency == "alta":
            score += 2
            reasons.append("Frecuencia de ataques alta")
        elif frequency == "media":
            score += 1
            reasons.append("Frecuencia de ataques media")
        
        # Factor 3: Número de intentos fallidos (0-2 puntos)
        maxretry = jail_context.get("maxretry", 5)
        if isinstance(maxretry, int) and failed_attempts > maxretry * 2:
            score += 2
            reasons.append(f"Muchos intentos fallidos ({failed_attempts})")
        elif isinstance(maxretry, int) and failed_attempts > maxretry:
            score += 1
            reasons.append(f"Intentos por encima del límite ({failed_attempts})")
        
        # Factor 4: Persistencia (0-2 puntos)
        days_active = ban_history.get("days_since_first_seen", 0)
        if days_active > 7:
            score += 2
            reasons.append(f"Activa por {days_active} días")
        elif days_active > 1:
            score += 1
            reasons.append(f"Activa por {days_active} días")
        
        # Factor 5: Ban de larga duración (0-1 punto)
        ban_duration = jail_context.get("ban_duration_seconds", 0)
        if ban_duration >= 86400:  # >= 1 día
            score += 1
            reasons.append("Ban de larga duración")
        
        # Determinar nivel basado en score
        if score >= 7:
            level = "CRITICAL"
            recommended_action = "Extender ban permanentemente"
        elif score >= 5:
            level = "HIGH"
            recommended_action = "Extender tiempo de ban"
        elif score >= 3:
            level = "MEDIUM"
            recommended_action = "Monitorear de cerca"
        else:
            level = "LOW"
            recommended_action = "Continuar monitoreo normal"
        
        threat_info = {
            "score": score,
            "max_score": 10,
            "level": level,
            "reasons": reasons,
            "recommended_action": recommended_action,
            "risk_factors": {
                "repeat_offender": ban_history.get("is_repeat_offender", False),
                "high_frequency": frequency == "alta",
                "excessive_attempts": failed_attempts > maxretry if isinstance(maxretry, int) else False,
                "persistent": days_active > 7
            }
        }
        
        print(f"✅ [DEBUG] Nivel de amenaza calculado: {threat_info}")
        return threat_info
        
    except Exception as e:
        print(f"❌ [DEBUG] Error calculando nivel de amenaza: {str(e)}")
        return {
            "score": 1,
            "max_score": 10,
            "level": "LOW",
            "reasons": ["Error en cálculo"],
            "recommended_action": "Revisar manualmente",
            "risk_factors": {
                "repeat_offender": False,
                "high_frequency": False,
                "excessive_attempts": False,
                "persistent": False
            }
        }

def format_duration(seconds: int) -> str:
    """
    Formatea una duración en segundos a formato legible.
    
    Args:
        seconds (int): Duración en segundos
    
    Returns:
        str: Duración formateada
    """
    if seconds < 60:
        return f"{seconds} segundos"
    elif seconds < 3600:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        if remaining_seconds > 0:
            return f"{minutes} minutos {remaining_seconds} segundos"
        return f"{minutes} minutos"
    else:
        hours = seconds // 3600
        remaining_minutes = (seconds % 3600) // 60
        if remaining_minutes > 0:
            return f"{hours}h {remaining_minutes}m"
        return f"{hours} horas"

def count_todays_bans(jail: str) -> int:
    """
    Cuenta los bans de hoy para un jail específico.
    
    Args:
        jail (str): Nombre del jail
    
    Returns:
        int: Número de bans hoy
    """
    try:
        today = datetime.now().date()
        ban_count = 0
        
        log_file = "/var/log/fail2ban.log"
        if not os.path.exists(log_file):
            return 0
        
        ban_pattern = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+'
            r'fail2ban\.actions\s*\[\d+\]:\s+NOTICE\s+\[' + re.escape(jail) + r'\]\s+'
            r'Ban\s+'
        )
        
        with open(log_file, 'r') as f:
            for line in f:
                match = ban_pattern.match(line.strip())
                if match:
                    try:
                        log_date = datetime.strptime(match.group('timestamp'), '%Y-%m-%d %H:%M:%S,%f').date()
                        if log_date == today:
                            ban_count += 1
                    except ValueError:
                        continue
        
        return ban_count
        
    except Exception:
        return 0

def get_peak_attack_hour(jail: str) -> str:
    """
    Obtiene la hora pico de ataques para un jail.
    
    Args:
        jail (str): Nombre del jail
    
    Returns:
        str: Hora pico en formato "HH:00-HH:59"
    """
    try:
        from collections import Counter
        
        hour_counts = Counter()
        today = datetime.now().date()
        
        log_file = "/var/log/fail2ban.log"
        if not os.path.exists(log_file):
            return "N/A"
        
        ban_pattern = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+'
            r'fail2ban\.actions\s*\[\d+\]:\s+NOTICE\s+\[' + re.escape(jail) + r'\]\s+'
            r'Ban\s+'
        )
        
        with open(log_file, 'r') as f:
            for line in f:
                match = ban_pattern.match(line.strip())
                if match:
                    try:
                        log_datetime = datetime.strptime(match.group('timestamp'), '%Y-%m-%d %H:%M:%S,%f')
                        if log_datetime.date() >= today - timedelta(days=7):  # Última semana
                            hour_counts[log_datetime.hour] += 1
                    except ValueError:
                        continue
        
        if hour_counts:
            peak_hour = hour_counts.most_common(1)[0][0]
            return f"{peak_hour:02d}:00-{peak_hour:02d}:59"
        else:
            return "N/A"
            
    except Exception:
        return "N/A"