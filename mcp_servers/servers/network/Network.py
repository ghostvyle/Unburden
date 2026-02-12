#!/usr/bin/env python3
"""
Servidor MCP (Model Context Protocol) para herramientas de red
Proporciona las siguientes herramientas:
- ping: Comprobar conectividad con hosts
- ifconfig: Mostrar información de interfaces de red
- arp: Descubrir equipos alcanzables en la red
"""

import asyncio
import re
import platform
import json
import logging
from typing import List, Optional

# Suprimir logs verbosos de la librería MCP
logging.getLogger('mcp.server.lowlevel.server').setLevel(logging.WARNING)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    import sys
    sys.stderr.write("ERROR: FastMCP no está instalado. Ejecuta: pip install mcp\n")
    sys.exit(1)

# Inicializar servidor MCP
mcp = FastMCP("network-tools")


# === UTILITY FUNCTIONS ===

async def run_command(cmd_args: list, timeout=60):
    """
    Ejecuta comandos de forma asíncrona y segura usando subprocess_exec

    Args:
        cmd_args: Lista de argumentos del comando ["comando", "arg1", "arg2"]
        timeout: Timeout en segundos

    Returns:
        Tupla (stdout, stderr, returncode)
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore'), process.returncode
    except asyncio.TimeoutError:
        # Intentar matar el proceso si existe
        try:
            if process and process.returncode is None:
                process.kill()
                await process.wait()
        except:
            pass
        return "", "Command timed out", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd_args[0]}", -1
    except Exception as e:
        return "", f"Error executing command: {str(e)}", -1


@mcp.tool()
async def ping(hosts: List[str], count: int = 4) -> str:
    """
    Envía pings a una o varias máquinas para comprobar conectividad

    Args:
        hosts: Lista de IPs o hostnames a verificar
        count: Número de pings a enviar (por defecto 4)

    Returns:
        Resultados de los pings en formato JSON
    """
    try:
        results = {}
        ping_cmd = "ping"
        count_flag = "-n" if platform.system().lower() == "windows" else "-c"

        for host in hosts:
            try:
                # Ejecutar ping usando run_command con lista de argumentos
                cmd_args = [ping_cmd, count_flag, str(count), host]
                stdout, stderr, returncode = await run_command(cmd_args, timeout=10)

                # Verificar timeout
                if returncode == -1 and "timeout" in stderr.lower():
                    results[host] = {
                        "status": "timeout",
                        "message": f"Timeout al intentar alcanzar {host}"
                    }
                    continue

                # Analizar resultado
                if returncode == 0:
                    # Buscar tiempo de respuesta promedio
                    if platform.system().lower() == "windows":
                        avg_pattern = r"Average = (\d+)ms"
                    else:
                        avg_pattern = r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/"

                    avg_match = re.search(avg_pattern, stdout)
                    avg_time = avg_match.group(1) if avg_match else "N/A"

                    # Buscar paquetes perdidos
                    if platform.system().lower() == "windows":
                        loss_pattern = r"\((\d+)% loss\)"
                    else:
                        loss_pattern = r"(\d+)% packet loss"

                    loss_match = re.search(loss_pattern, stdout)
                    packet_loss = loss_match.group(1) if loss_match else "0"

                    results[host] = {
                        "status": "online",
                        "avg_time_ms": avg_time,
                        "packet_loss": f"{packet_loss}%",
                        "message": f"Host {host} está activo"
                    }
                else:
                    results[host] = {
                        "status": "offline",
                        "message": f"Host {host} no responde a ping"
                    }
            except Exception as e:
                results[host] = {
                    "status": "error",
                    "message": f"Error al hacer ping: {str(e)}"
                }

        return json.dumps(results, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error crítico en ping: {str(e)}"}, indent=2)


@mcp.tool()
async def ifconfig() -> str:
    """
    Muestra información de las interfaces de red del sistema

    Returns:
        Información de las interfaces en formato JSON
    """
    try:
        interfaces = {}
        # Intentar con ip addr primero (más moderno en Linux)
        stdout, stderr, returncode = await run_command(["ip", "addr", "show"], timeout=5)

        if returncode == 0:
            # Parsear salida de ip addr
            current_interface = None
            for line in stdout.split('\n'):
                # Nueva interfaz
                match = re.match(r'^\d+:\s+(\S+):', line)
                if match:
                    current_interface = match.group(1).replace('@NONE', '')
                    interfaces[current_interface] = {
                        "status": "UNKNOWN",
                        "ipv4": [],
                        "ipv6": [],
                        "mac": None
                    }

                # Estado de la interfaz
                if current_interface and "state" in line:
                    if "UP" in line:
                        interfaces[current_interface]["status"] = "UP"
                    elif "DOWN" in line:
                        interfaces[current_interface]["status"] = "DOWN"

                # Dirección MAC
                if current_interface and "link/ether" in line:
                    mac_match = re.search(r'link/ether\s+([0-9a-f:]+)', line)
                    if mac_match:
                        interfaces[current_interface]["mac"] = mac_match.group(1)

                # IPv4
                if current_interface and "inet " in line and "inet6" not in line:
                    ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', line)
                    if ip_match:
                        interfaces[current_interface]["ipv4"].append(ip_match.group(1))

                # IPv6
                if current_interface and "inet6" in line:
                    ip6_match = re.search(r'inet6\s+([0-9a-f:]+/\d+)', line)
                    if ip6_match:
                        interfaces[current_interface]["ipv6"].append(ip6_match.group(1))
        else:
            # Si ip no está disponible, intentar con ifconfig
            stdout, stderr, returncode = await run_command(["ifconfig"], timeout=5)

            if returncode == 0:
                # Parsear salida de ifconfig
                current_interface = None
                for line in stdout.split('\n'):
                    if line and not line.startswith(' '):
                        match = re.match(r'^(\S+)', line)
                        if match:
                            current_interface = match.group(1).rstrip(':')
                            interfaces[current_interface] = {
                                "status": "UP" if "UP" in line else "DOWN",
                                "ipv4": [],
                                "ipv6": [],
                                "mac": None
                            }

                    if current_interface:
                        # MAC address
                        mac_match = re.search(r'ether\s+([0-9a-f:]+)', line)
                        if mac_match:
                            interfaces[current_interface]["mac"] = mac_match.group(1)

                        # IPv4
                        ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            interfaces[current_interface]["ipv4"].append(ip_match.group(1))

                        # IPv6
                        ip6_match = re.search(r'inet6\s+([0-9a-f:]+)', line)
                        if ip6_match:
                            interfaces[current_interface]["ipv6"].append(ip6_match.group(1))

        return json.dumps({
            "interfaces": interfaces,
            "summary": f"Se encontraron {len(interfaces)} interfaces de red"
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "error": f"Error crítico en ifconfig: {str(e)}"
        }, indent=2)


@mcp.tool()
async def arp(interface: Optional[str] = None, scan_local: bool = False) -> str:
    """
    Descubre equipos alcanzables usando ARP

    Args:
        interface: Interfaz específica a usar (opcional)
        scan_local: Si True, hace escaneo activo completo de la red (requiere arp-scan con sudo)

    Returns:
        Lista de dispositivos descubiertos en formato JSON
    """
    try:
        devices = []
        # Si scan_local=True, usar arp-scan con sudo para escaneo activo completo
        if scan_local:
            # Construir comando arp-scan
            cmd_args = ["sudo", "-n", "arp-scan", "--localnet"]
            if interface:
                cmd_args.extend(["-I", interface])

            stdout, stderr, returncode = await run_command(cmd_args, timeout=30)

            if returncode == 0:
                # Parsear salida de arp-scan
                for line in stdout.split('\n'):
                    # Formato: IP    MAC    Vendor
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)\s+(.*)', line, re.IGNORECASE)
                    if match:
                        devices.append({
                            "ip": match.group(1),
                            "mac": match.group(2),
                            "vendor": match.group(3).strip() if match.group(3) else "Unknown"
                        })

                return json.dumps({
                    "method": f"arp-scan --localnet{' -I ' + interface if interface else ''}",
                    "devices": devices,
                    "count": len(devices),
                    "message": f"Escaneo activo completado: {len(devices)} hosts activos encontrados"
                }, indent=2)
            else:
                # Si falla arp-scan
                return json.dumps({
                    "error": "arp-scan falló. Verifica que: 1) arp-scan esté instalado (apt install arp-scan), 2) Unburden se ejecute con sudo, 3) sudoers permita arp-scan sin contraseña",
                    "stderr": stderr,
                    "fallback": "Usa scan_local=False para ver tabla ARP actual sin escaneo activo"
                }, indent=2)

        # Método básico: usar arp -a (tabla ARP actual, no requiere sudo)
        stdout, stderr, returncode = await run_command(["arp", "-a"], timeout=10)

        if returncode == 0:
            # Parsear salida de arp -a
            for line in stdout.split('\n'):
                if platform.system().lower() == "windows":
                    # Formato Windows
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)', line, re.IGNORECASE)
                    if match:
                        devices.append({
                            "ip": match.group(1),
                            "mac": match.group(2).replace('-', ':'),
                            "vendor": "Unknown"
                        })
                else:
                    # Formato Linux/Mac
                    match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)', line, re.IGNORECASE)
                    if match:
                        devices.append({
                            "ip": match.group(1),
                            "mac": match.group(2),
                            "vendor": "Unknown"
                        })

            return json.dumps({
                "method": "arp -a (tabla ARP pasiva)",
                "devices": devices,
                "count": len(devices),
                "message": f"Se encontraron {len(devices)} dispositivos en la tabla ARP actual",
                "note": "Para escaneo activo completo de la red, usa scan_local=True (requiere ejecutar Unburden con sudo)"
            }, indent=2)

        return json.dumps({
            "error": "No se pudo obtener información ARP"
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "error": f"Error crítico en arp: {str(e)}",
            "suggestion": "Para escaneo activo (scan_local=True): ejecuta Unburden con sudo y configura sudoers para arp-scan"
        }, indent=2)


if __name__ == "__main__":
    # Iniciar servidor MCP con transporte stdio
    mcp.run(transport="stdio")
