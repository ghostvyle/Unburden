"""
Endpoints de gestión de servidores MCP
"""
import json
import logging
from typing import Dict, Any
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from src.backend.models.schemas import MCPImportRequest
from src.backend.mcp.mcp_client import (
    get_mcp_manager,
    get_active_mcp_clients,
    get_connected_mcps
)
from src.backend.agent.agent_manager import initialize_agent

logger = logging.getLogger(__name__)

router = APIRouter()


def _build_server_status(
    server_name: str,
    config: Dict[str, Any],
    active_mcp_clients: Dict[str, Dict[str, Any]],
    server_type: str
) -> Dict[str, Any]:
    """
    Construye el estado de un servidor MCP individual.
    
    Args:
        server_name: Nombre del servidor
        config: Configuración del servidor
        active_mcp_clients: Diccionario de clientes MCP activos
        server_type: Tipo de servidor ("system" o "user")
        
    Returns:
        Dict con el estado del servidor
    """
    if server_name in active_mcp_clients:
        active_data = active_mcp_clients[server_name]
        server_data: Dict[str, Any] = {
            "status": active_data["status"],
            "transport": active_data.get("transport", config.get("transport", "unknown")),
            "tools_count": active_data.get("tools", 0),
            "tool_names": active_data.get("tool_names", []),
            "last_error": active_data.get("error"),
            "type": server_type
        }

        # Agregar información adicional según el transporte
        if active_data.get("endpoint"):
            server_data["endpoint"] = active_data["endpoint"]
        if active_data.get("command"):
            server_data["command"] = active_data["command"]
    else:
        # Servidor configurado pero no conectado
        server_data = {
            "status": "failed",
            "transport": config.get("transport", "unknown"),
            "tools_count": 0,
            "tool_names": [],
            "last_error": "Server not connected",
            "type": server_type
        }
    
    return server_data


@router.get("/estado-mcps")
async def get_mcp_status() -> JSONResponse:
    """
    Obtiene el estado real de todos los servidores MCP basado en los clientes activos.
    
    Returns:
        JSONResponse: Respuesta JSON con el estado de todos los servidores
        
    Raises:
        HTTPException: Si ocurre un error al obtener el estado
    """
    try:
        mcp_manager = get_mcp_manager()
        active_mcp_clients = get_active_mcp_clients()

        # Obtener información clasificada de servidores configurados
        server_info = mcp_manager.get_server_status_info()

        system_status: Dict[str, Dict[str, Any]] = {}
        user_status: Dict[str, Dict[str, Any]] = {}
        connected_count = 0
        failed_count = 0

        # Verificar servidores del sistema
        for name, config in server_info["system_servers"].items():
            server_data = _build_server_status(name, config, active_mcp_clients, "system")
            system_status[name] = server_data
            if server_data["status"] == "connected":
                connected_count += 1
            else:
                failed_count += 1

        # Verificar servidores del usuario
        for name, config in server_info["user_servers"].items():
            server_data = _build_server_status(name, config, active_mcp_clients, "user")
            user_status[name] = server_data
            if server_data["status"] == "connected":
                connected_count += 1
            else:
                failed_count += 1

        return JSONResponse({
            "system_servers": system_status,
            "user_servers": user_status,
            "total_servers": server_info["total_servers"],
            "system_count": server_info["system_count"],
            "user_count": server_info["user_count"],
            "connected_count": connected_count,
            "failed_count": failed_count,
            "active_clients_count": len(active_mcp_clients)
        })

    except Exception as e:
        logger.error(f"Error getting MCP status: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving MCP server status")


@router.delete("/delete-mcp/{server_name}")
async def delete_mcp_server(server_name: str):
    """Elimina un servidor MCP individual (solo servidores de usuario)"""
    try:
        mcp_manager = get_mcp_manager()
        active_mcp_clients = get_active_mcp_clients()
        connected_mcps = get_connected_mcps()

        # Verificar que el servidor existe y es del usuario
        user_servers = mcp_manager.load_user_mcps()
        system_servers = mcp_manager.load_system_mcps()

        if server_name not in user_servers:
            if server_name in system_servers:
                raise HTTPException(status_code=403, detail=f"Cannot delete system server '{server_name}'")
            else:
                raise HTTPException(status_code=404, detail=f"User server '{server_name}' not found")

        # Hacer backup de la configuración del usuario
        mcp_manager._backup_user_config()

        # Eliminar servidor de la configuración del usuario
        del user_servers[server_name]

        # Guardar configuración actualizada del usuario
        success = mcp_manager.save_user_mcps(user_servers)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to save updated user configuration")

        # Regenerar configuración fusionada
        merged_config = mcp_manager.merge_configurations()
        logger.info(f"Server '{server_name}' deleted from user config. {len(merged_config.get('mcpServers', {}))} total servers remaining")

        # Limpiar registros de clientes activos
        if server_name in active_mcp_clients:
            del active_mcp_clients[server_name]
        if server_name in connected_mcps:
            del connected_mcps[server_name]

        # Limpiar tool count
        if server_name in mcp_manager.server_tools:
            del mcp_manager.server_tools[server_name]

        # Reinicializar agente con la nueva configuración
        try:
            await initialize_agent()

            logger.info(f"Successfully deleted user MCP server '{server_name}' and reinitialized agent")
            return JSONResponse({"message": f"Server '{server_name}' deleted successfully"})

        except Exception as e:
            # Si falla la reinicialización, restaurar configuración del usuario
            logger.error(f"Failed to reinitialize agent after deleting '{server_name}': {e}")
            try:
                mcp_manager.restore_user_config()
                await initialize_agent()
                logger.info(f"Restored user config after failed deletion of '{server_name}'")
            except Exception as restore_error:
                logger.error(f"Failed to restore backup after failed deletion: {restore_error}")

            raise HTTPException(status_code=500, detail=f"Failed to delete server: {str(e)}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting MCP server {server_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting server {server_name}")


@router.post("/importar-mcps")
async def import_mcps(mcp_request: MCPImportRequest):
    """Importa servidores MCP personalizados con formato flexible"""
    try:
        mcp_manager = get_mcp_manager()

        # Parsear configuración JSON
        user_config = json.loads(mcp_request.mcpConfig)

        # Añadir servidores usando el manager
        success, message = mcp_manager.add_user_servers(user_config, flexible_format=True)

        if success:
            # Reinicializar agente con nueva configuración fusionada
            try:
                await initialize_agent()
                return JSONResponse({"message": message})
            except Exception as e:
                # Si falla la reinicialización, restaurar configuración anterior
                logger.error(f"Failed to reinitialize with new MCP config: {e}")
                mcp_manager.restore_user_config()
                await initialize_agent()  # Restaurar estado anterior

                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to initialize with new MCP servers: {str(e)}"
                )
        else:
            raise HTTPException(status_code=400, detail=message)

    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON format: {str(e)}")
    except Exception as e:
        logger.error(f"Error importing MCP servers: {e}")
        raise HTTPException(status_code=500, detail=f"Error importing MCP servers: {str(e)}")


@router.delete("/limpiar-user-mcps")
async def clear_user_mcps():
    """Limpia todos los MCPs del usuario y reinicializa el agente"""
    try:
        mcp_manager = get_mcp_manager()
        active_mcp_clients = get_active_mcp_clients()
        connected_mcps = get_connected_mcps()

        # Limpiar configuración de MCPs del usuario
        success = mcp_manager.clear_user_mcps()
        if not success:
            raise HTTPException(status_code=500, detail="Failed to clear user MCP servers")

        # Forzar regeneración del JSON merged
        merged_config = mcp_manager.merge_configurations()
        logger.info(f"Merged configuration updated after clearing user MCPs: {len(merged_config.get('mcpServers', {}))} total servers")

        # Limpiar registros activos de clientes MCP de usuario
        user_servers = mcp_manager.load_user_mcps()  # Debe estar vacío ahora
        system_servers = mcp_manager.load_system_mcps()

        # Filtrar active_mcp_clients para mantener solo los servers del sistema
        servers_to_keep = set(system_servers.keys())
        to_delete_active = [name for name in active_mcp_clients.keys() if name not in servers_to_keep]
        for name in to_delete_active:
            del active_mcp_clients[name]

        to_delete_connected = [name for name in connected_mcps.keys() if name not in servers_to_keep]
        for name in to_delete_connected:
            del connected_mcps[name]

        # Limpiar tool counts de servidores de usuario
        for server_name in list(mcp_manager.server_tools.keys()):
            if server_name not in system_servers:
                del mcp_manager.server_tools[server_name]

        # Reinicializar agente con la nueva configuración
        await initialize_agent()

        logger.info("User MCP servers cleared and agent reinitialized successfully")
        return JSONResponse({"message": "User MCP servers cleared successfully"})

    except Exception as e:
        logger.error(f"Error clearing user MCPs: {e}")
        raise HTTPException(status_code=500, detail=str(e))
