"""
Endpoints de chat de Unburden
"""
import logging
import re
import json
import os
import traceback
from fastapi import APIRouter, Request, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


from src.backend.utils.utils import parse_messages_from_md
from src.backend.agent.agent_manager import (
    handle_user_message,
    get_chat_history_file_path,
    clear_agent_context
)
from src.backend.chat.shell_handler import ShellHandler
from src.backend.chat.chat_manager import ChatHistoryManager
from src.backend.config.config import MAX_FILE_SIZE
from src.backend.utils.utils import (
    filter_unwanted_tags,
    generate_date_based_id
)


# Inicializar
logger = logging.getLogger(__name__)
router = APIRouter()
chat_manager = ChatHistoryManager()

# ------------- ENDPOINTS DE CHAT -----------------

@router.get("/generate-session-id")
async def generate_session_id() -> JSONResponse:
    """
    Genera un nuevo ID de sesión basado en la fecha y hora actual.
    
    Returns:
        JSONResponse: Respuesta JSON con el sessionId generado
        
    Raises:
        HTTPException: Si ocurre un error al generar el ID
    """
    try:
        chat_id = generate_date_based_id()
        return JSONResponse({"sessionId": chat_id})
    except Exception as e:
        logger.error(f"Error generating session ID: {e}")
        raise HTTPException(status_code=500, detail="Error generating session ID")


@router.post("/detect-os")
async def detect_os_endpoint(request: Request) -> JSONResponse:
    """
    Detecta el sistema operativo mediante el TTL de la IP objetivo.
    
    Args:
        request: Request de FastAPI con el JSON que contiene targetIp
        
    Returns:
        JSONResponse: Respuesta JSON con osType, ttl, success y opcionalmente error
        
    Raises:
        HTTPException: Si ocurre un error en el procesamiento
    """

    try:
        data = await request.json()
        target_ip = data.get("targetIp", "").strip()

        if not target_ip:
            return JSONResponse(
                {
                    "osType": "unknown",
                    "ttl": 0,
                    "success": False,
                    "error": "Target IP is required"
                },
                status_code=400
            )

        # Validate IP format
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, target_ip):
            return JSONResponse(
                {
                    "osType": "unknown",
                    "ttl": 0,
                    "success": False,
                    "error": "Invalid IP format"
                },
                status_code=400
            )

        logger.info(f"OS detection request for IP: {target_ip}")

        # Detectar SO mediante TTL
        os_type, ttl, success = await ShellHandler.detect_os_by_ttl(target_ip)

        logger.info(f"OS detection result: os={os_type}, ttl={ttl}, success={success}")

        return JSONResponse({
            "osType": os_type,
            "ttl": ttl,
            "success": success
        })

    except Exception as e:
        logger.error(f"Error in detect-os endpoint: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return JSONResponse(
            {
                "osType": "unknown",
                "ttl": 0,
                "success": False,
                "error": str(e)
            },
            status_code=500
        )


@router.post("/clear-context")
async def clear_context_endpoint() -> JSONResponse:
    """
    Limpia el contexto global del agente (borra toda la memoria).

    Returns:
        JSONResponse: Respuesta JSON con success y message
        
    Raises:
        HTTPException: Si ocurre un error al limpiar el contexto
    """
    try:
        success = clear_agent_context()

        if success:
            logger.info("Context cleared via API endpoint")
            return JSONResponse({
                "success": True,
                "message": "Context cleared successfully"
            })
        else:
            return JSONResponse(
                {
                    "success": False,
                    "message": "Agent not initialized"
                },
                status_code=500
            )

    except Exception as e:
        logger.error(f"Error clearing context: {e}")
        return JSONResponse(
            {
                "success": False,
                "message": str(e)
            },
            status_code=500
        )


@router.post("/refresh-context/{chat_id}")
async def refresh_context_endpoint(chat_id: str) -> JSONResponse:
    """
    Refresca el contexto del agente:
    1. Limpia el contexto actual
    2. Carga el historial completo del chat especificado

    Args:
        chat_id: ID del chat cuyo historial se cargará

    Returns:
        JSONResponse: Respuesta JSON con success y message
        
    Raises:
        HTTPException: Si ocurre un error al refrescar el contexto
    """
    try:
        # 1. Limpiar contexto actual
        logger.info(f"Clearing context before refresh for chat {chat_id}")
        clear_success = clear_agent_context()
        if not clear_success:
            return JSONResponse(
                {
                    "success": False,
                    "message": "Failed to clear context: agent not initialized"
                },
                status_code=500
            )

        # 2. Obtener contenido del chat
        try:
            chat_content = chat_manager.load_chat_content(chat_id)
        except FileNotFoundError:
            return JSONResponse(
                {
                    "success": False,
                    "message": f"Chat {chat_id} not found"
                },
                status_code=404
            )

            # 3. Cargar el contexto ejecutando el agente CON el historial como prompt
            # Pero de forma silenciosa (sin herramientas, solo para cargar memoria)
            logger.info(f"Cargando contexto desde chat {chat_id} ({len(chat_content)} caracteres)")

        try:
            from src.backend.agent.agent_manager import get_agent, get_chat_contexts
            from src.backend.mcp.llm import get_llm

            agent = get_agent()
            agent_context = get_chat_contexts()

            if not agent or not agent_context:
                raise Exception("Agent not initialized")

            # Parsear historial y reconstruir como contexto limpio
            messages = parse_messages_from_md(chat_content)

            if messages:
                conversation_lines = []
                for msg in messages:
                    role = msg.get("role", "user")
                    content = msg.get("content", "")
                    if role == "user":
                        conversation_lines.append(f"User: {content}")
                    elif role == "assistant":
                        conversation_lines.append(f"Assistant: {content}")
                conversation_text = "\n\n".join(conversation_lines)

                # Limitar tamaño para no desbordar contexto
                MAX_CONTEXT_CHARS = 15000
                if len(conversation_text) > MAX_CONTEXT_CHARS:
                    conversation_text = conversation_text[-MAX_CONTEXT_CHARS:]

                context_prompt = (
                    "The following is the previous conversation history for this chat session. "
                    "Read it and use it as context for future messages. "
                    "Respond with only 'OK'.\n\n"
                    f"{conversation_text}"
                )

                # Usar llm.acomplete() en lugar de agent.run() para evitar
                # activar llamadas a herramientas durante la carga del contexto
                llm = get_llm()
                await llm.acomplete(context_prompt)


            logger.info(f"Context loaded successfully into agent memory for chat {chat_id}")
        except Exception as llm_error:
            logger.error(f"Failed to load context into agent memory: {llm_error}")
            raise

        logger.info(f"Context refreshed successfully for chat {chat_id}")
        return JSONResponse({
            "success": True,
            "message": "Context refreshed successfully"
        })

    except Exception as e:
        logger.error(f"Error refreshing context for chat {chat_id}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return JSONResponse(
            {
                "success": False,
                "message": str(e)
            },
            status_code=500
        )


@router.options("/chat")
async def chat_options() -> JSONResponse:
    """
    Maneja la solicitud CORS preflight para el endpoint de chat.
    
    Returns:
        JSONResponse: Respuesta JSON con status "ok"
    """
    return JSONResponse({"status": "ok"})


@router.post("/chat")
async def chat_endpoint(request: Request) -> JSONResponse:
    """
    Endpoint principal de chat con soporte para modo pentesting.
    
    Args:
        request: Request de FastAPI con JSON que contiene:
            - message: Mensaje del usuario
            - pentesting: Boolean indicando si está en modo pentesting
            - sessionId: ID de sesión (legacy)
            - chatId: ID del chat actual
            - shellConfig: Configuración de shell (opcional)
            
    Returns:
        JSONResponse: Respuesta JSON con el contenido de la respuesta del agente
        
    Raises:
        HTTPException: Si ocurre un error en el procesamiento
    """
    try:
        # Parsear datos del request manualmente para manejar mejor la validación
        try:
            data = await request.json()
        except Exception as e:
            logger.error(f"Error parseando JSON: {e}")
            raise HTTPException(status_code=400, detail="Formato de datos inválido")

        # Extraer y validar campos
        message = data.get("message", "").strip()
        pentesting = data.get("pentesting", False)
        session_id = data.get("sessionId", "").strip()  # Legacy: para modo pentesting
        chat_id = data.get("chatId", "").strip()  # Nuevo: ID del chat actual
        shell_config = data.get("shellConfig")  # Nueva: configuración de shell

        # Validación básica
        if not message:
            raise HTTPException(status_code=400, detail="El mensaje no puede estar vacío")

        # Sin límite de caracteres - totalmente flexible

        # Determinar qué ID usar (priorizar chat_id sobre session_id)
        active_id = chat_id if chat_id else session_id

        if not active_id:
            raise HTTPException(status_code=400, detail="Chat ID requerido")

        logger.info(f"Solicitud de chat - ID: {active_id[:8]}, Pentesting: {pentesting}, Longitud del mensaje: {len(message)}")

        # Detectar si hay solicitud de reverse shell
        if ShellHandler.detect_shell_request(message) and not shell_config:
            logger.info("Solicitud de shell detectada pero no hay configuración - solicitando configuración")
            return JSONResponse({
                "type": "shell_config_required",
                "message": "⚠️ Se detectó solicitud de reverse shell. Se requiere configuración.",
                "shell_request": {
                    "detected": True,
                    "message_content": message
                }
            })

        # Si hay configuración de shell, validarla y procesarla
        if shell_config:
            is_valid, error_msg = ShellHandler.validate_shell_config(shell_config)
            if not is_valid:
                raise HTTPException(status_code=400, detail=f"Configuración de shell inválida: {error_msg}")

            # Crear sesión tmux con listener
            lhost = shell_config['lhost']
            lport = int(shell_config['lport'])
            os_type = shell_config['os_type'].lower()

            session_name, output, success = await ShellHandler.create_tmux_session(lhost, lport)

            if not success:
                return JSONResponse({
                    "response": f"❌ Error creando listener tmux: {output}"
                })

            # Generar instrucciones para el LLM
            shell_instructions = ShellHandler.generate_shell_instructions(
                lhost, lport, os_type, session_name
            )

            # Modificar el mensaje para incluir las instrucciones de shell
            message = f"{message}\n\n{shell_instructions}"

            logger.info(f"Configuración de shell procesada: sesión tmux '{session_name}' creada")

        # Manejar el mensaje con el chat ID específico
        raw_response = await handle_user_message(message, active_id)

        # Filtrar etiquetas de pensamiento para el chat (pero mantener para consola)
        logger.info(f"Respuesta del modelo (con pensamiento): {raw_response}")
        cleaned_response = filter_unwanted_tags(raw_response)

        # Guardar mensaje y respuesta en el chat

        # Si se está usando el nuevo sistema de chats (chat_id presente)
        if chat_id:
            try:
                # Usar el nuevo sistema de chat con Markdown SSOT
                chat_manager.append_message_to_chat(chat_id, {
                    "role": "user",
                    "content": message,
                    "type": "text"
                })
                chat_manager.append_message_to_chat(chat_id, {
                    "role": "assistant",
                    "content": cleaned_response,
                    "type": "text"
                })
                logger.debug(f"Mensajes guardados en chat {chat_id}")
            except Exception as e:
                logger.warning(f"Error al guardar mensajes en chat {chat_id}: {e}")

        # Devolver respuesta al frontend
        return JSONResponse({"response": cleaned_response})

    except Exception as e:
        logger.error(f"Error in chat endpoint: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Error interno del servidor. Por favor, inténtalo de nuevo.")



# ------------- CHAT HISTORY ENDPOINTS -----------------


# ===== MODELOS PYDANTIC =====

class CreateChatRequest(BaseModel):
    """Request para crear un nuevo chat"""
    title: str = Field(..., min_length=1, max_length=200, description="Título del chat")
    chat_id: Optional[str] = Field(None, description="ID opcional del chat")
    target: str = Field("", description="Target IP o hostname")


class AppendMessageRequest(BaseModel):
    """Request para añadir un mensaje al chat"""
    role: str = Field(..., pattern="^(user|assistant|system)$", description="Rol del mensaje")
    content: str = Field(..., description="Contenido del mensaje")
    type: str = Field("text", pattern="^(text|tool_call|error)$", description="Tipo de mensaje")
    timestamp: Optional[str] = Field(None, description="Timestamp ISO8601")
    id: Optional[str] = Field(None, description="ID del mensaje")


class SaveFullChatRequest(BaseModel):
    """Request para sobrescribir el contenido completo de un chat"""
    content: str = Field(..., description="Contenido completo en formato Markdown")


class UpdateTitleRequest(BaseModel):
    """Request para actualizar el título de un chat"""
    title: str = Field(..., min_length=1, max_length=200, description="Nuevo título")


class UpdateTargetRequest(BaseModel):
    """Request para actualizar el target de un chat"""
    target: str = Field("", description="Nuevo target (IP o hostname)")


# ===== ENDPOINTS PRINCIPALES =====

@router.get("/chats")
async def list_chats() -> JSONResponse:
    """
    Lista todos los chats disponibles.

    Returns:
        JSONResponse: Respuesta JSON con lista de chats y targets
        
    Raises:
        HTTPException: Si ocurre un error al listar los chats
    """
    try:
        chats_raw = chat_manager.get_chat_index()

        # Transformar al formato que espera el frontend
        chats: List[Dict[str, Any]] = []
        targets_set: set[str] = set()

        for chat in chats_raw:
            target = chat.get("target", "")
            chats.append({
                "id": chat.get("id"),
                "title": chat.get("title", "Sin título"),
                "target": target,
                "createdAt": chat.get("timestamp", ""),
                "updatedAt": chat.get("timestamp", "")
            })

            # Añadir target a la lista si no está vacío
            if target and target.strip():
                targets_set.add(target.strip())

        # Ordenar por createdAt descendente (más recientes primero)
        chats.sort(key=lambda x: x.get("createdAt", ""), reverse=True)

        # Convertir set a lista ordenada
        targets_list: List[str] = sorted(list(targets_set))

        return JSONResponse({
            "chats": chats,
            "targets": targets_list
        })
    except Exception as e:
        logger.error(f"Error listing chats: {e}")
        raise HTTPException(status_code=500, detail=f"Error listing chats: {str(e)}")


@router.post("/chats")
async def create_chat(request: CreateChatRequest) -> JSONResponse:
    """
    Crea un nuevo chat vacío.

    Args:
        request: Request con title, chat_id (opcional) y target
        
    Returns:
        JSONResponse: Respuesta JSON con los datos del chat creado
        
    Raises:
        HTTPException: Si ocurre un error al crear el chat
    """
    try:
        chat_id = chat_manager.create_new_chat(
            title=request.title,
            target=request.target
        )

        logger.info(f"Chat nuevo creado: {chat_id} - {request.title}")

        # Obtener el chat creado para devolverlo
        index = chat_manager.get_chat_index()
        chat_metadata: Optional[Dict[str, Any]] = next((c for c in index if c["id"] == chat_id), None)

        return JSONResponse({
            "id": chat_id,
            "title": request.title,
            "target": request.target,
            "messages": [],
            "createdAt": chat_metadata.get("timestamp", "") if chat_metadata else "",
            "updatedAt": chat_metadata.get("timestamp", "") if chat_metadata else ""
        })
    except Exception as e:
        logger.error(f"Error creating chat: {e}")
        raise HTTPException(status_code=500, detail=f"Error creating chat: {str(e)}")


@router.get("/chats/{chat_id}")
async def get_chat(chat_id: str) -> JSONResponse:
    """
    Obtiene un chat con sus mensajes parseados.

    Args:
        chat_id: ID del chat a obtener
        
    Returns:
        JSONResponse: Respuesta JSON con los datos del chat y sus mensajes
        
    Raises:
        HTTPException: Si el chat no existe o ocurre un error
    """
    try:
        if not chat_manager.chat_exists(chat_id):
            raise HTTPException(status_code=404, detail=f"Chat not found: {chat_id}")

        # Cargar contenido MD
        md_content = chat_manager.load_chat_content(chat_id)

        # Obtener metadata del índice
        index = chat_manager.get_chat_index()
        chat_metadata: Optional[Dict[str, Any]] = next((c for c in index if c["id"] == chat_id), None)

        if not chat_metadata:
            raise HTTPException(status_code=404, detail=f"Chat metadata not found: {chat_id}")

        # Parsear mensajes del markdown
        messages: List[Dict[str, Any]] = parse_messages_from_md(md_content)

        # Construir respuesta compatible con frontend
        return JSONResponse({
            "id": chat_id,
            "title": chat_metadata.get("title", "Sin título"),
            "target": chat_metadata.get("target", ""),
            "messages": messages,
            "createdAt": chat_metadata.get("timestamp", ""),
            "updatedAt": chat_metadata.get("timestamp", "")
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting chat {chat_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error loading chat: {str(e)}")


@router.get("/chats/{chat_id}/raw")
async def get_chat_raw(chat_id: str) -> JSONResponse:
    """
    Obtiene el contenido raw (Markdown) de un chat para edición.

    Args:
        chat_id: ID del chat a obtener
        
    Returns:
        JSONResponse: Respuesta JSON con el contenido Markdown del chat
        
    Raises:
        HTTPException: Si el chat no existe o ocurre un error
    """
    try:
        if not chat_manager.chat_exists(chat_id):
            raise HTTPException(status_code=404, detail=f"Chat not found: {chat_id}")

        # Cargar contenido MD raw
        md_content = chat_manager.load_chat_content(chat_id)

        return JSONResponse({
            "chat_id": chat_id,
            "content": md_content
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting raw chat {chat_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error loading raw chat: {str(e)}")


@router.post("/chats/{chat_id}/messages")
async def append_message(chat_id: str, request: AppendMessageRequest) -> JSONResponse:
    """
    Añade un nuevo mensaje al final del chat (modo Chat → MD).

    Args:
        chat_id: ID del chat
        request: Request con los datos del mensaje (role, content, type, etc.)
        
    Returns:
        JSONResponse: Respuesta JSON con success y message
        
    Raises:
        HTTPException: Si el chat no existe o ocurre un error
    """
    try:
        if not chat_manager.chat_exists(chat_id):
            raise HTTPException(status_code=404, detail=f"Chat not found: {chat_id}")

        message_data: Dict[str, Any] = {
            "role": request.role,
            "content": request.content,
            "type": request.type,
            "timestamp": request.timestamp,
            "id": request.id
        }

        chat_manager.append_message_to_chat(chat_id, message_data)

        logger.debug(f"Mensaje añadido al chat {chat_id}")

        return JSONResponse({
            "success": True,
            "message": "Message appended successfully"
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error appending message to chat {chat_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error appending message: {str(e)}")


@router.put("/chats/{chat_id}")
async def save_full_chat(chat_id: str, request: SaveFullChatRequest) -> JSONResponse:
    """
    Sobrescribe completamente el contenido de un chat (modo MD → Chat).

    Esta ruta se usa cuando el usuario edita el histórico desde
    el editor de Markdown (Vista de Pentest).

    Args:
        chat_id: ID del chat a sobrescribir
        request: Request con el contenido completo en Markdown
        
    Returns:
        JSONResponse: Respuesta JSON con success y message
        
    Raises:
        HTTPException: Si el chat no existe o ocurre un error
    """
    try:
        if not chat_manager.chat_exists(chat_id):
            raise HTTPException(status_code=404, detail=f"Chat not found: {chat_id}")

        chat_manager.save_full_chat(chat_id, request.content)

        logger.info(f"Contenido completo del chat guardado para {chat_id}")

        return JSONResponse({
            "success": True,
            "message": "Chat saved successfully"
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error saving chat {chat_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error saving chat: {str(e)}")


@router.delete("/chats/{chat_id}")
async def delete_chat(chat_id: str) -> JSONResponse:
    """
    Elimina un chat completo (archivo .md, índice, informe y datos de pentest).

    Args:
        chat_id: ID del chat a eliminar
        
    Returns:
        JSONResponse: Respuesta JSON con success y message
        
    Raises:
        HTTPException: Si el chat no existe o ocurre un error
    """
    try:
        # 1. Eliminar el chat (archivo .md e índice)
        deleted = chat_manager.delete_chat(chat_id)

        if not deleted:
            raise HTTPException(status_code=404, detail=f"Chat no encontrado: {chat_id}")

        # 2. Eliminar datos de pentest asociados (informe.md y otros archivos)
        try:
            # Importar aquí para evitar dependencias circulares
            from src.backend.agent.agent_manager import (
                get_pentesting_reports,
                get_chat_histories,
                get_processing_lock
            )

            pentesting_reports = get_pentesting_reports()
            chat_histories = get_chat_histories()
            processing_lock = get_processing_lock()

            with processing_lock:
                # Eliminar informe de pentesting si existe
                if chat_id in pentesting_reports:
                    pentesting_file = pentesting_reports[chat_id]
                    if os.path.exists(pentesting_file):
                        os.remove(pentesting_file)
                        logger.info(f"Informe de pentesting eliminado: {pentesting_file}")
                    del pentesting_reports[chat_id]

                # Eliminar histórico de chat de pentest si existe
                if chat_id in chat_histories:
                    chat_file = chat_histories[chat_id]
                    if os.path.exists(chat_file):
                        os.remove(chat_file)
                        logger.info(f"Archivo de historial de chat eliminado: {chat_file}")
                    del chat_histories[chat_id]

        except Exception as pentest_error:
            # No fallar si hay error borrando datos de pentest
            # (el chat ya fue eliminado, esto es solo limpieza adicional)
            logger.warning(f"Error eliminando datos de pentest para {chat_id}: {pentest_error}")

        logger.info(f"Chat y datos asociados eliminados: {chat_id}")

        return JSONResponse({
            "success": True,
            "message": "Chat deleted successfully"
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting chat {chat_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting chat: {str(e)}")


@router.patch("/chats/{chat_id}/title")
async def update_chat_title(chat_id: str, request: UpdateTitleRequest) -> JSONResponse:
    """
    Actualiza el título de un chat.

    Args:
        chat_id: ID del chat
        request: Request con el nuevo título
        
    Returns:
        JSONResponse: Respuesta JSON con success y message
        
    Raises:
        HTTPException: Si el chat no existe o ocurre un error
    """
    try:
        if not chat_manager.chat_exists(chat_id):
            raise HTTPException(status_code=404, detail=f"Chat not found: {chat_id}")

        chat_manager.update_chat_title(chat_id, request.title)

        logger.info(f"Título actualizado para chat {chat_id}: {request.title}")

        return JSONResponse({
            "success": True,
            "message": "Title updated successfully"
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating title for chat {chat_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error updating title: {str(e)}")


@router.patch("/chats/{chat_id}/target")
async def update_chat_target(chat_id: str, request: UpdateTargetRequest) -> JSONResponse:
    """
    Actualiza el target de un chat.

    Args:
        chat_id: ID del chat
        request: Request con el nuevo target
        
    Returns:
        JSONResponse: Respuesta JSON con success y message
        
    Raises:
        HTTPException: Si el chat no existe o ocurre un error
    """
    try:
        if not chat_manager.chat_exists(chat_id):
            raise HTTPException(status_code=404, detail=f"Chat not found: {chat_id}")

        chat_manager.update_chat_target(chat_id, request.target)

        logger.info(f"Target actualizado para chat {chat_id}: {request.target}")

        return JSONResponse({
            "success": True,
            "message": "Target updated successfully"
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating target for chat {chat_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error updating target: {str(e)}")


# ===== ENDPOINTS DE ARCHIVO =====

@router.get("/chats/{chat_id}/download")
async def download_chat(chat_id: str) -> FileResponse:
    """
    Descarga el archivo .md del chat.

    Args:
        chat_id: ID del chat a descargar
        
    Returns:
        FileResponse: Archivo .md para descarga
        
    Raises:
        HTTPException: Si el chat no existe o ocurre un error
    """
    try:
        if not chat_manager.chat_exists(chat_id):
            raise HTTPException(status_code=404, detail=f"Chat not found: {chat_id}")

        chat_file_path = os.path.join(chat_manager.CHATS_DIR, f"{chat_id}.md")

        # Obtener el título del chat para el nombre del archivo
        index = chat_manager.get_chat_index()
        chat_title: str = "chat"
        for chat in index:
            if chat["id"] == chat_id:
                # Sanitizar el título para nombre de archivo
                chat_title = "".join(
                    c for c in chat["title"] if c.isalnum() or c in (' ', '-', '_')
                ).strip()
                chat_title = chat_title.replace(' ', '_')
                break

        filename: str = f"{chat_title}_{chat_id[:8]}.md"

        return FileResponse(
            path=chat_file_path,
            media_type="text/markdown",
            filename=filename
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading chat {chat_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error downloading chat: {str(e)}")


@router.post("/chats/{chat_id}/upload")
async def upload_chat(chat_id: str, file: UploadFile = File(...)) -> JSONResponse:
    """
    Sube un archivo .md y reemplaza el contenido del chat.

    Args:
        chat_id: ID del chat
        file: Archivo .md a subir
        
    Returns:
        JSONResponse: Respuesta JSON con success y message
        
    Raises:
        HTTPException: Si el chat no existe, el archivo no es .md o ocurre un error
    """
    try:
        if not chat_manager.chat_exists(chat_id):
            raise HTTPException(status_code=404, detail=f"Chat not found: {chat_id}")

        # Validar que es un archivo .md
        if not file.filename or not file.filename.endswith('.md'):
            raise HTTPException(status_code=400, detail="El archivo debe ser .md")

        # Leer contenido con límite de tamaño
        content = await file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File too large ({len(content)} bytes). Max: {MAX_FILE_SIZE} bytes"
            )
        content_str: str = content.decode('utf-8')

        # Guardar contenido
        chat_manager.save_full_chat(chat_id, content_str)

        logger.info(f"Archivo subido al chat {chat_id}")

        return JSONResponse({
            "success": True,
            "message": "File uploaded successfully"
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading file to chat {chat_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error uploading file: {str(e)}")


@router.get("/chats/{chat_id}/exists")
async def check_chat_exists(chat_id: str) -> JSONResponse:
    """
    Verifica si un chat existe.

    Args:
        chat_id: ID del chat a verificar
        
    Returns:
        JSONResponse: Respuesta JSON con exists (boolean) y chat_id
    """
    exists: bool = chat_manager.chat_exists(chat_id)
    return JSONResponse({"exists": exists, "chat_id": chat_id})
