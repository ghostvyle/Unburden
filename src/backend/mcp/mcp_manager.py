"""
MCP Manager - Gestiona la configuración dual de servidores MCP
Separa servidores del sistema (inmutables) de los del usuario (modificables)
"""

import os
import sys
import json
import shutil
import logging
import subprocess
import time
import httpx
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)

class MCPManager:
    def __init__(self, base_dir: str = "mcp_servers"):
        self.base_dir = Path(base_dir)
        self.config_dir = self.base_dir / "config"
        self.system_mcps_path = self.config_dir / "system_mcp_servers.json"
        self.user_mcps_path = self.config_dir / "user_mcp_servers.json"
        self.merged_mcps_path = self.base_dir / "mcp_servers.json"
        
        # Track STDIO processes for health checks
        self.stdio_processes: Dict[str, subprocess.Popen] = {}
        
        # Track tool counts for each server
        self.server_tools: Dict[str, int] = {}
        
        # Asegurar que el directorio config existe
        self.config_dir.mkdir(exist_ok=True)
        
        # Inicializar archivos si no existen
        self._initialize_config_files()
    
    def _initialize_config_files(self):
        """Inicializa archivos de configuración si no existen"""
        
        # Si system-mcps.json no existe, crear uno vacío
        if not self.system_mcps_path.exists():
            default_system = {"mcpServers": {}}
            with open(self.system_mcps_path, 'w') as f:
                json.dump(default_system, f, indent=2)
            logger.info("Created default system-mcps.json")
        
        # Si user-mcps.json no existe, crear uno vacío  
        if not self.user_mcps_path.exists():
            default_user = {"mcpServers": {}}
            with open(self.user_mcps_path, 'w') as f:
                json.dump(default_user, f, indent=2)
            logger.info("Created default user-mcps.json")
    
    def _resolve_paths(self, servers: Dict[str, Any]) -> Dict[str, Any]:
        """Resuelve placeholders ${PROJECT_ROOT} y ${VENV_PYTHON} en la config."""
        project_root = str(Path(__file__).resolve().parents[3])
        venv_python = sys.executable

        resolved = {}
        for name, server in servers.items():
            server = dict(server)
            if "command" in server:
                server["command"] = server["command"].replace(
                    "${VENV_PYTHON}", venv_python
                ).replace("${PROJECT_ROOT}", project_root)
            if "args" in server:
                server["args"] = [
                    arg.replace("${PROJECT_ROOT}", project_root).replace(
                        "${VENV_PYTHON}", venv_python
                    )
                    for arg in server["args"]
                ]
            resolved[name] = server
        return resolved

    def load_system_mcps(self) -> Dict[str, Any]:
        """Carga los MCPs del sistema (inmutables) con rutas resueltas"""
        try:
            with open(self.system_mcps_path, 'r') as f:
                config = json.load(f)
                servers = config.get("mcpServers", {})
                return self._resolve_paths(servers)
        except Exception as e:
            logger.error(f"Error loading system MCPs: {e}")
            return {}
    
    def load_user_mcps(self) -> Dict[str, Any]:
        """Carga los MCPs del usuario (modificables)"""
        try:
            with open(self.user_mcps_path, 'r') as f:
                config = json.load(f)
                return config.get("mcpServers", {})
        except Exception as e:
            logger.error(f"Error loading user MCPs: {e}")
            return {}
    
    def save_user_mcps(self, user_servers: Dict[str, Any]) -> bool:
        """Guarda los MCPs del usuario"""
        try:
            config = {"mcpServers": user_servers}
            with open(self.user_mcps_path, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"Saved {len(user_servers)} user MCP servers")
            return True
        except Exception as e:
            logger.error(f"Error saving user MCPs: {e}")
            return False
    
    def merge_configurations(self) -> Dict[str, Any]:
        """
        Fusiona configuraciones del sistema y usuario.
        Los servidores del usuario tienen prioridad sobre los del sistema.
        """
        system_servers = self.load_system_mcps()
        user_servers = self.load_user_mcps()
        
        # Fusionar: user MCPs sobrescriben system MCPs con el mismo nombre
        merged_servers = system_servers.copy()
        merged_servers.update(user_servers)
        
        merged_config = {"mcpServers": merged_servers}
        
        # Guardar configuración fusionada
        try:
            with open(self.merged_mcps_path, 'w') as f:
                json.dump(merged_config, f, indent=2)
            logger.info(f"MCP: {len(merged_servers)} servers configured")
        except Exception as e:
            logger.error(f"Error saving merged configuration: {e}")
        
        return merged_config
    
    def add_user_servers(self, new_servers: Dict[str, Any], flexible_format: bool = True) -> Tuple[bool, str]:
        """
        Añade nuevos servidores a la configuración del usuario.
        
        Args:
            new_servers: Configuración de nuevos servidores
            flexible_format: Si True, acepta formatos flexibles
        
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            # Procesar formato flexible
            if flexible_format:
                new_servers = self._normalize_server_config(new_servers)
            
            # Cargar configuración actual del usuario
            current_user_servers = self.load_user_mcps()
            
            # Hacer backup
            self._backup_user_config()
            
            # Fusionar nuevos servidores
            current_user_servers.update(new_servers)
            
            # Guardar configuración actualizada del usuario
            if self.save_user_mcps(current_user_servers):
                # Regenerar configuración fusionada
                merged_config = self.merge_configurations()
                merged_count = len(merged_config.get("mcpServers", {}))
                added_count = len(new_servers)
                total_count = len(current_user_servers)
                logger.info(f"User servers updated: {added_count} added, {total_count} total user servers, {merged_count} total merged servers")
                return True, f"Successfully added {added_count} servers. Total user servers: {total_count}"
            else:
                return False, "Failed to save user MCP configuration"
                
        except Exception as e:
            logger.error(f"Error adding user servers: {e}")
            return False, f"Error adding servers: {str(e)}"
    
    def _normalize_server_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normaliza configuración de servidores para aceptar formatos flexibles.
        
        Acepta:
        1. {"server_name": {...}} - formato directo
        2. {"mcpServers": {"server_name": {...}}} - formato estándar MCP
        """
        # Si ya tiene estructura mcpServers, extraer servidores
        if "mcpServers" in config:
            return config["mcpServers"]
        
        # Si no, asumir que es formato directo
        normalized = {}
        for name, server_config in config.items():
            if isinstance(server_config, dict):
                # Validar que tenga al menos 'command'
                if "command" not in server_config:
                    logger.warning(f"Server {name} missing 'command' field")
                    continue
                
                # Autodetectar transport si no está especificado
                if "transport" not in server_config:
                    # Buscar en args para determinar transport
                    args = server_config.get("args", [])
                    if "--transport" in args:
                        transport_idx = args.index("--transport")
                        if transport_idx + 1 < len(args):
                            server_config["transport"] = args[transport_idx + 1]
                    else:
                        # Default a stdio si no se especifica
                        server_config["transport"] = "stdio"
                
                # Autodetectar host y port para SSE
                if server_config.get("transport") == "sse":
                    args = server_config.get("args", [])
                    if "--host" in args:
                        host_idx = args.index("--host")
                        if host_idx + 1 < len(args):
                            server_config["host"] = args[host_idx + 1]
                    if "--port" in args:
                        port_idx = args.index("--port")
                        if port_idx + 1 < len(args):
                            try:
                                server_config["port"] = int(args[port_idx + 1])
                            except ValueError:
                                logger.warning(f"Invalid port for server {name}")
                
                normalized[name] = server_config
            else:
                logger.warning(f"Invalid server configuration for {name}")
        
        return normalized
    
    def _backup_user_config(self):
        """Crea backup de la configuración del usuario"""
        if self.user_mcps_path.exists():
            backup_path = self.user_mcps_path.with_suffix(".json.backup")
            shutil.copy2(self.user_mcps_path, backup_path)
            logger.debug("Created user MCP config backup")
    
    def restore_user_config(self) -> bool:
        """Restaura configuración del usuario desde backup"""
        backup_path = self.user_mcps_path.with_suffix(".json.backup")
        try:
            if backup_path.exists():
                shutil.copy2(backup_path, self.user_mcps_path)
                self.merge_configurations()
                logger.info("Restored user MCP config from backup")
                return True
        except Exception as e:
            logger.error(f"Error restoring backup: {e}")
        return False
    
    def clear_user_mcps(self) -> bool:
        """Limpia todos los MCPs del usuario"""
        try:
            self._backup_user_config()
            empty_config = {"mcpServers": {}}
            with open(self.user_mcps_path, 'w') as f:
                json.dump(empty_config, f, indent=2)
            merged_config = self.merge_configurations()
            merged_count = len(merged_config.get("mcpServers", {}))
            logger.info(f"Cleared all user MCP servers, {merged_count} total merged servers remaining")
            return True
        except Exception as e:
            logger.error(f"Error clearing user MCPs: {e}")
            return False
    
    def get_server_status_info(self) -> Dict[str, Any]:
        """
        Retorna información sobre el estado de los servidores,
        clasificados por tipo (system/user)
        """
        system_servers = self.load_system_mcps()
        user_servers = self.load_user_mcps()
        
        return {
            "system_servers": {name: {"type": "system", **config} for name, config in system_servers.items()},
            "user_servers": {name: {"type": "user", **config} for name, config in user_servers.items()},
            "total_servers": len(system_servers) + len(user_servers),
            "system_count": len(system_servers),
            "user_count": len(user_servers)
        }

    def register_stdio_process(self, server_name: str, process):
        """Registra un proceso STDIO para verificación de salud"""
        self.stdio_processes[server_name] = process
        logger.debug(f"Registered STDIO process for {server_name}: PID {process.pid}")

    def register_server_tools(self, server_name: str, tool_count: int):
        """Registra el número de herramientas disponibles para un servidor"""
        self.server_tools[server_name] = tool_count
        logger.debug(f"Registered {tool_count} tools for server {server_name}")

    def get_server_tool_count(self, server_name: str) -> int:
        """Obtiene el número de herramientas registradas para un servidor"""
        return self.server_tools.get(server_name, 0)

    async def check_server_health(self, server_name: str, server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Verifica el estado real de un servidor MCP"""
        transport = self._detect_transport(server_config)
        logger.debug(f"Checking health for {server_name} with transport {transport}")
        
        if transport == "stdio":
            result = self._check_stdio_health(server_name)
            logger.debug(f"STDIO health check for {server_name}: {result}")
        elif transport in ["sse", "http"]:
            result = await self._check_sse_health(server_name, server_config)
            logger.debug(f"SSE health check for {server_name}: {result}")
        else:
            result = {"status": "failed", "error": f"Unknown transport: {transport}"}
        
        # Agregar número de herramientas si el servidor está conectado
        if result["status"] == "connected":
            result["tools_count"] = self.get_server_tool_count(server_name)
        else:
            result["tools_count"] = 0
            
        return result

    def _detect_transport(self, config: Dict[str, Any]) -> str:
        """Detecta el tipo de transporte de un servidor"""
        if config.get("url"):
            return "sse"
        
        transport = config.get("transport", "").lower()
        if transport in ["sse", "http", "stdio"]:
            return transport
            
        # Buscar en args
        args = config.get("args", [])
        if "--transport" in args:
            try:
                transport_idx = args.index("--transport") + 1
                if transport_idx < len(args):
                    detected = args[transport_idx].lower()
                    if detected in ["sse", "http", "stdio"]:
                        return detected
            except (IndexError, ValueError):
                pass
        
        # Si hay puerto, probablemente sea SSE
        if "--port" in args or config.get("port"):
            return "sse"
        return "stdio"

    def _check_stdio_health(self, server_name: str) -> Dict[str, Any]:
        """Verifica salud de servidor STDIO usando process.poll()"""
        if server_name not in self.stdio_processes:
            # Si no está registrado, intentamos encontrar el proceso por comando
            logger.debug(f"STDIO server {server_name} not registered, attempting to find process")
            return self._find_stdio_process_by_command(server_name)
        
        process = self.stdio_processes[server_name]
        if process.poll() is None:
            return {"status": "connected", "pid": process.pid}
        else:
            # Proceso terminado
            exit_code = process.poll()
            del self.stdio_processes[server_name]
            return {"status": "failed", "error": f"Process died (exit code {exit_code})"}

    def _find_stdio_process_by_command(self, server_name: str) -> Dict[str, Any]:
        """Busca procesos STDIO que estén ejecutándose basado en el comando"""
        try:
            import psutil
            
            # Obtener la configuración del servidor para el comando
            config_path = self.merged_mcps_path
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    server_config = config.get("mcpServers", {}).get(server_name, {})
                    command = server_config.get("command", "")
                    
                    if not command:
                        return {"status": "failed", "error": "No command configured"}
                    
                    # Buscar procesos que coincidan
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        try:
                            cmdline = proc.info['cmdline'] or []
                            if len(cmdline) > 0:
                                # Verificar si el comando coincide
                                if command in cmdline[0] or any(command in arg for arg in cmdline):
                                    # Verificar si contiene argumentos específicos del servidor
                                    args = server_config.get("args", [])
                                    if args and any(arg in ' '.join(cmdline) for arg in args):
                                        return {"status": "connected", "pid": proc.info['pid'], "found_by_search": True}
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            continue
                    
                    return {"status": "failed", "error": "Process not found"}
            else:
                return {"status": "failed", "error": "Configuration file not found"}
                
        except ImportError:
            logger.warning("psutil not available, cannot search for STDIO processes")
            return {"status": "connected", "error": "Process not monitored (psutil unavailable)"}
        except Exception as e:
            logger.error(f"Error searching for STDIO process {server_name}: {e}")
            return {"status": "failed", "error": f"Process search failed: {str(e)}"}

    async def _check_sse_health(self, server_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Verifica salud de servidor SSE/HTTP con GET request"""
        host, port = self._extract_host_port(config)
        
        if not port:
            logger.warning(f"No port specified for SSE server {server_name}")
            return {"status": "failed", "error": "No port specified"}
        
        endpoint = config.get("url", f"http://{host}:{port}/sse")
        logger.debug(f"Testing SSE endpoint for {server_name}: {endpoint}")
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(endpoint)
                logger.debug(f"SSE health check for {server_name}: HTTP {response.status_code}")
                
                # Accept any 2xx or 3xx status as healthy, and specific 4xx that are OK for SSE
                if response.status_code < 400 or response.status_code in [404, 405]:
                    return {"status": "connected", "endpoint": endpoint, "http_status": response.status_code}
                else:
                    return {"status": "failed", "error": f"HTTP {response.status_code}", "endpoint": endpoint, "http_status": response.status_code}
        except httpx.ConnectError as e:
            logger.debug(f"SSE connection error for {server_name}: {e}")
            return {"status": "failed", "error": f"Connection refused", "endpoint": endpoint}
        except httpx.TimeoutException as e:
            logger.debug(f"SSE timeout for {server_name}: {e}")
            return {"status": "failed", "error": f"Request timeout", "endpoint": endpoint}
        except Exception as e:
            logger.debug(f"SSE health check exception for {server_name}: {e}")
            return {"status": "failed", "error": f"HTTP request failed: {str(e)}", "endpoint": endpoint}

    def _extract_host_port(self, config: Dict[str, Any]) -> Tuple[str, Optional[int]]:
        """Extrae host y puerto de la configuración"""
        host = config.get("host", "localhost")
        port = config.get("port")
        
        if not port:
            args = config.get("args", [])
            try:
                if "--port" in args:
                    port_idx = args.index("--port") + 1
                    port = int(args[port_idx])
                if "--host" in args:
                    host_idx = args.index("--host") + 1
                    host = args[host_idx]
            except (IndexError, ValueError):
                pass
        
        return host, port