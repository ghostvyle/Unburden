"""
Gestor de clientes MCP (Model Context Protocol)
Maneja la conexión y comunicación con servidores MCP via SSE y STDIO
"""
import os
import json
import asyncio
import socket
import shutil
import subprocess
import time
import logging
from typing import Dict, List, Tuple, Optional, Any, TYPE_CHECKING

from llama_index.tools.mcp import BasicMCPClient, McpToolSpec
from src.backend.mcp.mcp_manager import MCPManager

if TYPE_CHECKING:
    from llama_index.core.agent.workflow import FunctionAgent

logger = logging.getLogger(__name__)

# === Registry de clientes MCP activos ===
active_mcp_clients = {}  # {server_name: {"client": client, "status": "connected", "transport": "stdio", "tools": 0, "tool_names": []}}
connected_mcps = {}  # Backward compatibility

# === Inicializar MCP Manager ===
mcp_manager = MCPManager()


def _extract_host_port(args: List[str]) -> Optional[Tuple[str, int]]:
    """
    Extrae host y puerto de argumentos MCP.
    
    Args:
        args: Lista de argumentos que debe contener --host y --port
        
    Returns:
        Optional[Tuple[str, int]]: Tupla (host, port) o None si no se encuentran
    """
    try:
        host_index = args.index("--host") + 1
        port_index = args.index("--port") + 1
        host = args[host_index]
        port = int(args[port_index])
        return host, port
    except (ValueError, IndexError):
        return None


def build_mcp_clients_from_config(json_path: str = "mcp_servers.json") -> Tuple[List, List]:
    """
    Construye clientes MCP tanto SSE como STDIO desde configuración.
    
    Lee el archivo JSON de configuración y crea clientes MCP según el tipo
    de transporte especificado (SSE o STDIO).
    
    Args:
        json_path: Ruta al archivo JSON de configuración
        
    Returns:
        Tuple[List, List]: Tupla con (lista de clientes, lista de nombres de servidores)
    """
    try:
        with open(json_path, "r") as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f"Error loading MCP config: {e}")
        return [], []

    clients = []
    server_names = []
    global connected_mcps, active_mcp_clients
    connected_mcps.clear()
    active_mcp_clients.clear()

    for name, server in config.get("mcpServers", {}).items():
        url = server.get("url")
        cmd = server.get("command")
        args = server.get("args", []) or []
        env = server.get("env") or {}
        transport = (server.get("transport") or "").lower()

        try:
            # 1) URL directa (SSE/HTTP)
            if url:
                client = BasicMCPClient(url, timeout=999999)
                clients.append(client)
                server_names.append(name)
                active_mcp_clients[name] = {
                    "client": client,
                    "status": "connected",
                    "transport": "sse",
                    "endpoint": url,
                    "tools": 0,
                    "tool_names": []
                }
                connected_mcps[name] = {"status": "connected", "transport": "sse", "endpoint": url}
                logger.info(f"[MCP] {name}: conectado por URL {url}")
                continue

            # 2) Si está configurado como SSE o tiene --host/--port, intentar SSE
            should_be_sse = (transport == "sse" or server.get("host") or server.get("port") or
                           ("--host" in args and "--port" in args))

            if should_be_sse:
                # Obtener host y port de la configuración o argumentos
                host = server.get("host", "localhost")
                port = server.get("port")

                if not port:
                    hp = _extract_host_port(args) if args else None
                    if hp:
                        host, port = hp

                if port:
                    sse_url = f"http://{host}:{port}/sse"
                    try:
                        # Probar conexión rápida al puerto
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(0.5)
                            if sock.connect_ex((host, port)) == 0:
                                client = BasicMCPClient(sse_url, timeout=999999)
                                clients.append(client)
                                server_names.append(name)
                                active_mcp_clients[name] = {
                                    "client": client,
                                    "status": "connected",
                                    "transport": "sse",
                                    "endpoint": sse_url,
                                    "tools": 0,
                                    "tool_names": []
                                }
                                connected_mcps[name] = {
                                    "status": "connected",
                                    "transport": "sse",
                                    "endpoint": sse_url
                                }
                                logger.info(f"[MCP] {name}: conectado por red {sse_url}")
                                continue
                    except Exception:
                        pass

                    # Si no está corriendo pero tenemos comando, lanzarlo como servidor SSE
                    if cmd:
                        if shutil.which(cmd):

                            # Lanzar el servidor SSE en background
                            try:
                                logger.info(f"[MCP] {name}: lanzando servidor SSE -> {cmd} {' '.join(args)}")
                                process = subprocess.Popen(
                                    [cmd] + args,
                                    env={**os.environ, **env},
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                    start_new_session=True
                                )

                                # Esperar un poco para que el servidor arranque
                                time.sleep(3)

                                # Intentar conectar de nuevo
                                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                                    sock.settimeout(3)
                                    if sock.connect_ex((host, port)) == 0:
                                        client = BasicMCPClient(sse_url, timeout=999999)
                                        clients.append(client)
                                        server_names.append(name)
                                        active_mcp_clients[name] = {
                                            "client": client,
                                            "status": "connected",
                                            "transport": "sse",
                                            "endpoint": sse_url,
                                            "tools": 0,
                                            "tool_names": []
                                        }
                                        connected_mcps[name] = {
                                            "status": "connected",
                                            "transport": "sse",
                                            "endpoint": sse_url
                                        }
                                        logger.info(f"[MCP] {name}: servidor SSE lanzado exitosamente en {sse_url}")
                                        continue
                                    else:
                                        process.terminate()
                                        connected_mcps[name] = {
                                            "status": "failed",
                                            "error": f"Servidor no responde después de lanzar"
                                        }
                                        logger.warning(f"[MCP] {name}: servidor lanzado pero no responde en {sse_url}")
                            except Exception as launch_error:
                                connected_mcps[name] = {
                                    "status": "failed",
                                    "error": f"Error lanzando servidor: {str(launch_error)}"
                                }
                                logger.error(f"[MCP] {name}: error lanzando servidor SSE: {launch_error}")
                        else:
                            connected_mcps[name] = {"status": "failed", "error": f"comando '{cmd}' no encontrado"}
                            logger.warning(f"[MCP] {name}: comando '{cmd}' no encontrado")
                else:
                    connected_mcps[name] = {"status": "failed", "error": "Puerto no especificado para servidor SSE"}
                    logger.warning(f"[MCP] {name}: puerto no especificado para servidor SSE")

            # 3) Si transport es stdio explícitamente y hay command, STDIO
            elif transport == "stdio" and cmd:
                if shutil.which(cmd):
                    client = BasicMCPClient(cmd, args=args, env=env, timeout=999999)
                    clients.append(client)
                    server_names.append(name)
                    active_mcp_clients[name] = {
                        "client": client,
                        "status": "connected",
                        "transport": "stdio",
                        "command": f"{cmd} {' '.join(args)}",
                        "tools": 0,
                        "tool_names": []
                    }

                    # Registrar proceso STDIO para health checking
                    process = None
                    if hasattr(client, '_process'):
                        process = client._process
                    elif hasattr(client, 'process'):
                        process = client.process
                    elif hasattr(client, '_transport') and hasattr(client._transport, 'process'):
                        process = client._transport.process

                    if process:
                        mcp_manager.register_stdio_process(name, process)
                        logger.info(f"Registered STDIO process for {name}: PID {process.pid}")
                    else:
                        logger.debug(f"Could not find process reference for STDIO server {name}")

                    connected_mcps[name] = {
                        "status": "connected",
                        "transport": "stdio",
                        "command": f"{cmd} {' '.join(args)}"
                    }
                    logger.info(f"[MCP] {name}: connected")
                    logger.debug(f"[MCP] {name}: {cmd} {' '.join(args)}")
                    continue
                else:
                    connected_mcps[name] = {"status": "failed", "error": f"comando '{cmd}' no encontrado"}
                    logger.warning(f"[MCP] {name}: comando '{cmd}' no encontrado para STDIO")

            # 4) No se pudo crear cliente
            connected_mcps[name] = {"status": "failed", "error": "configuración inválida"}
            logger.warning(f"[MCP] {name}: no se pudo crear cliente (revisa config)")

        except Exception as server_error:
            connected_mcps[name] = {"status": "failed", "error": str(server_error)}
            logger.error(f"[MCP] {name}: error creando cliente: {server_error}")

    return clients, server_names


async def get_combined_agent_from_clients(clients: List, server_names: List = None) -> 'FunctionAgent':
    """
    Crea agente con herramientas desde clientes MCP (SSE + STDIO).
    
    IMPORTANTE: Esta función solo crea las herramientas del agente,
    NO crea el agente en sí (eso lo hace agent_manager).
    
    Args:
        clients: Lista de clientes MCP conectados
        server_names: Lista de nombres de servidores (opcional)
        
    Returns:
        FunctionAgent: Agente configurado con todas las herramientas disponibles
        
    Raises:
        Exception: Si ocurre un error al cargar las herramientas
    """
    from llama_index.core.agent.workflow import FunctionAgent
    from src.backend.mcp.llm import get_llm
    from src.backend.config.config import SYSTEM_PROMPT

    all_tools = []

    logger.debug(f"Creating agent tools from {len(clients)} MCP clients...")

    if server_names is None:
        server_names = [f"client_{i}" for i in range(len(clients))]

    async def _load_tools_for_client(i: int, client) -> Tuple[int, List, List, Optional[Exception]]:
        """
        Carga herramientas desde un único cliente MCP.
        
        Args:
            i: Índice del cliente
            client: Cliente MCP del cual cargar herramientas
            
        Returns:
            Tuple[int, List, List, Optional[Exception]]: (índice, herramientas, nombres, error)
        """
        server_name = server_names[i] if i < len(server_names) else f"client_{i}"
        try:
            spec = McpToolSpec(client=client)
            tools = await spec.to_tool_list_async()
            tool_names = [tool.metadata.name for tool in tools]
            return i, tools, tool_names, None
        except Exception as e:
            return i, [], [], e

    # Load tools from all clients concurrently
    results = await asyncio.gather(
        *[_load_tools_for_client(i, client) for i, client in enumerate(clients)],
        return_exceptions=False
    )

    for i, tools, tool_names, error in results:
        server_name = server_names[i] if i < len(server_names) else f"client_{i}"
        server_label = f" ({server_name})"

        if error is None:
            all_tools.extend(tools)

            # Registrar el número de herramientas en el MCP Manager y active registry
            if i < len(server_names):
                mcp_manager.register_server_tools(server_name, len(tools))
                if server_name in active_mcp_clients:
                    active_mcp_clients[server_name]["tools"] = len(tools)
                    active_mcp_clients[server_name]["tool_names"] = tool_names

            logger.info(f"[MCP Client {i+1}{server_label}] Loaded {len(tools)} tools")
            logger.debug(f"[MCP Client {i+1}{server_label}] Tools: {', '.join(tool_names)}")
        else:
            logger.warning(f"[MCP Client {i+1}{server_label}] Error loading tools: {error}")

            if i < len(server_names):
                mcp_manager.register_server_tools(server_name, 0)
                if server_name in active_mcp_clients:
                    active_mcp_clients[server_name]["tools"] = 0
                    active_mcp_clients[server_name]["tool_names"] = []
                    active_mcp_clients[server_name]["status"] = "failed"
                    active_mcp_clients[server_name]["error"] = str(error)

    # Crear agente con todas las herramientas disponibles
    agent = FunctionAgent(
        name="Unburden",
        description="Enhanced Cybersecurity Assistant with Pentesting Mode.",
        tools=all_tools,
        llm=get_llm(),
        system_prompt=SYSTEM_PROMPT,
        verbose=True  # Habilitar modo verbose para debugging
    )

    logger.info(f"Agent created with {len(all_tools)} total tools from {len(clients)} clients")
    return agent


def get_mcp_manager() -> MCPManager:
    """
    Obtiene la instancia del MCP Manager.
    
    Returns:
        MCPManager: Instancia singleton del MCP Manager
    """
    return mcp_manager


def get_active_mcp_clients() -> Dict[str, Dict[str, Any]]:
    """
    Obtiene el diccionario de clientes MCP activos.
    
    Returns:
        Dict[str, Dict[str, Any]]: Diccionario con información de clientes activos
    """
    return active_mcp_clients


def get_connected_mcps() -> Dict[str, Dict[str, Any]]:
    """
    Obtiene el diccionario de MCPs conectados (compatibilidad hacia atrás).
    
    Returns:
        Dict[str, Dict[str, Any]]: Diccionario con información de MCPs conectados
    """
    return connected_mcps
