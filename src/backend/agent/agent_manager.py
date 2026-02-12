"""
Gestor del agente principal de Unburden
Maneja la inicialización y ejecución del agente con herramientas MCP
"""
import os
import asyncio
import logging
from typing import Dict
from llama_index.core.workflow import Context
from llama_index.core.agent.workflow import ToolCall, ToolCallResult

from src.backend.reports.report_manager import PentestProcessor
from src.backend.utils.utils import sanitize_filename
from src.backend.mcp.mcp_client import build_mcp_clients_from_config, get_combined_agent_from_clients, get_mcp_manager
from src.backend.chat.sequential_parser import (
    is_sequential_request,
    parse_sequential_request,
    SequentialParser
)

logger = logging.getLogger(__name__)


class AgentService:
    """Encapsula todo el estado y la lógica del agente de Unburden."""

    def __init__(self):
        self.agent = None
        self.agent_context = None
        self.pentesting_processor = None
        self.pentesting_reports: Dict[str, str] = {}
        self.chat_histories: Dict[str, str] = {}
        self.processing_lock = asyncio.Lock()

    async def initialize(self):
        """Inicializa el agente con soporte completo MCP (SSE + STDIO)"""
        try:
            clients, server_names = build_mcp_clients_from_config("mcp_servers/mcp_servers.json")
            self.agent = await get_combined_agent_from_clients(clients, server_names)
            self.agent_context = Context(self.agent)

            self.pentesting_processor = PentestProcessor(
                self.pentesting_reports, self.processing_lock
            )

            logger.info("Agent initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing agent: {e}")
            raise

    def clear_context(self) -> bool:
        """Limpia el contexto global del agente (resetea la memoria)."""
        if self.agent:
            self.agent_context = Context(self.agent)
            logger.info("Agent context cleared successfully")
            return True
        else:
            logger.warning("Cannot clear context: agent not initialized")
            return False

    async def handle_message(self, message_content: str, chat_id: str = None) -> str:
        """
        Maneja un mensaje del usuario usando herramientas MCP con contexto global.
        
        Soporta tanto mensajes regulares como instrucciones secuenciales numeradas.
        
        Args:
            message_content: Contenido del mensaje del usuario
            chat_id: ID del chat (opcional, para compatibilidad)
            
        Returns:
            str: Respuesta del agente al mensaje del usuario
            
        Raises:
            Exception: Si el agente no está inicializado o ocurre un error
        """
        if not self.agent or not self.agent_context:
            return "Agent not initialized. Please restart the application."

        try:
            if is_sequential_request(message_content):
                logger.info("Sequential instruction mode detected")
                return await self._handle_sequential_instructions(message_content)
            else:
                return await self._execute_single_message(message_content)

        except Exception as e:
            logger.error(f"Error handling message: {e}")
            return f"Error processing request: {str(e)}"

    async def _execute_single_message(self, message: str) -> str:
        """
        Ejecuta un mensaje individual en el agente con límite de tool calls para prevenir loops.
        
        Args:
            message: Mensaje a ejecutar
            
        Returns:
            str: Respuesta del agente
            
        Raises:
            Exception: Si ocurre un error durante la ejecución
        """
        try:
            from llama_index.core.workflow.events import StopEvent

            if self.agent and hasattr(self.agent, 'tools'):
                tool_names = [t.metadata.name for t in self.agent.tools] if self.agent.tools else []
                logger.info(f"[AGENT] Available tools count: {len(tool_names)}")
                metasploit_tools = [name for name in tool_names if 'exploit' in name.lower() or 'metasploit' in name.lower()]
                logger.info(f"[AGENT] Metasploit-related tools: {metasploit_tools}")

            handler = self.agent.run(message, ctx=self.agent_context)
            stop_event_detected = False

            tool_call_count = 0
            MAX_TOOL_CALLS = 50
            tool_call_history = []

            async for event in handler.stream_events():
                if isinstance(event, ToolCall):
                    tool_call_count += 1
                    tool_call_history.append(event.tool_name)
                    logger.info(f"[TOOL {tool_call_count}/{MAX_TOOL_CALLS}] Calling {event.tool_name}")

                    if tool_call_count >= MAX_TOOL_CALLS:
                        logger.error(f"[LOOP DETECTED] Exceeded {MAX_TOOL_CALLS} tool calls! Query: '{message[:100]}'")
                        logger.error(f"[LOOP] Tool call pattern: {tool_call_history[-10:]}")
                        return f"⚠️ **Infinite loop detected!** The agent made {tool_call_count} tool calls.\n\nYour query: `{message[:100]}...`\n\n**This usually happens when:**\n- The query is too ambiguous (e.g., just a number or word without context)\n- The agent is trying to guess what you want\n\n**Suggestion:** Please provide a clearer, more specific request with context."

                elif isinstance(event, ToolCallResult):
                    logger.debug(f"[TOOL] {event.tool_name} returned: {str(event.tool_output)[:200]}...")
                elif isinstance(event, StopEvent):
                    stop_event_detected = True
                    logger.info(f"[STOP] StopEvent detected after {tool_call_count} tool calls")

            response = await handler
            logger.info(f"[RESPONSE] Total tool calls: {tool_call_count}")
            logger.info(f"[RESPONSE] Final response length: {len(str(response))} chars")

            if stop_event_detected and len(str(response)) < 10:
                logger.error(f"[CRITICAL] Empty or very short response after StopEvent!")

            return str(response)
        except Exception as e:
            logger.error(f"Error executing message: {e}")
            return f"Error: {str(e)}"

    async def _handle_sequential_instructions(self, message: str) -> str:
        """
        Maneja la ejecución secuencial de instrucciones numeradas.
        
        Args:
            message: Mensaje con instrucciones numeradas a ejecutar secuencialmente
            
        Returns:
            str: Respuesta combinada de todas las instrucciones ejecutadas
        """
        instructions = parse_sequential_request(message)

        if not instructions:
            return "No valid sequential instructions detected."

        logger.info(f"Executing {len(instructions)} sequential instructions...")

        if len(instructions) == 1:
            instruction = instructions[0]
            logger.info(f"Executing single instruction: {instruction.content[:100]}...")

            try:
                instruction_context = SequentialParser.format_instruction_context(
                    instruction, 1
                )
                result = await self._execute_single_message(instruction_context)
                return result
            except Exception as e:
                logger.error(f"Instruction failed: {e}")
                return f"Error: {str(e)}"

        clean_results = []

        for i, instruction in enumerate(instructions, 1):
            logger.info(f"Executing instruction {i}/{len(instructions)}: {instruction.content[:100]}...")

            try:
                instruction_context = SequentialParser.format_instruction_context(
                    instruction, len(instructions)
                )
                result = await self._execute_single_message(instruction_context)

                instruction.result = result
                instruction.executed = True
                logger.info(f"Instruction {i} completed successfully")
                clean_results.append(f"## Tarea {i}: {instruction.content}\n\n{result}")

            except Exception as e:
                instruction.error = str(e)
                instruction.executed = False
                logger.error(f"Instruction {i} failed: {e}")
                clean_results.append(f"## Tarea {i}: {instruction.content}\n\n❌ **Error:** {str(e)}")

        separator = "\n\n---\n\n"
        full_response = separator.join(clean_results)
        return full_response

    async def get_pentesting_file_path(self, chat_id: str) -> str:
        """
        Obtiene la ruta del archivo de informe de pentesting para un chat.
        
        Si el archivo no existe, crea la ruta y la registra.
        
        Args:
            chat_id: ID del chat
            
        Returns:
            str: Ruta completa del archivo de informe
        """
        async with self.processing_lock:
            if chat_id not in self.pentesting_reports:
                safe_chat_id = sanitize_filename(chat_id)
                filename = f"{safe_chat_id}.md"
                reports_dir = os.path.join("data", "reports")
                os.makedirs(reports_dir, exist_ok=True)
                self.pentesting_reports[chat_id] = os.path.join(reports_dir, filename)
        return self.pentesting_reports[chat_id]

    async def get_chat_history_file_path(self, chat_id: str) -> str:
        """
        Obtiene la ruta del archivo de historial para un chat.
        
        Si el archivo no existe, crea la ruta y la registra.
        
        Args:
            chat_id: ID del chat
            
        Returns:
            str: Ruta completa del archivo de historial
        """
        async with self.processing_lock:
            if chat_id not in self.chat_histories:
                safe_chat_id = sanitize_filename(chat_id)
                filename = f"{safe_chat_id}.md"
                chats_dir = os.path.join("data", "chats")
                os.makedirs(chats_dir, exist_ok=True)
                self.chat_histories[chat_id] = os.path.join(chats_dir, filename)
        return self.chat_histories[chat_id]


# === Singleton ===
_service = AgentService()


def get_service() -> AgentService:
    """Obtiene la instancia singleton de AgentService (para testing/DI)."""
    return _service


# === Wrappers module-level (compatibilidad con código existente) ===

async def initialize_agent() -> None:
    """
    Inicializa el agente con soporte completo MCP (SSE + STDIO).
    
    Raises:
        Exception: Si ocurre un error durante la inicialización
    """
    await _service.initialize()


def clear_agent_context() -> bool:
    """
    Limpia el contexto global del agente (resetea la memoria).
    
    Returns:
        bool: True si se limpió exitosamente, False si el agente no está inicializado
    """
    return _service.clear_context()


async def handle_user_message(message_content: str, chat_id: str = None) -> str:
    """
    Maneja un mensaje del usuario usando herramientas MCP con contexto global.
    
    Args:
        message_content: Contenido del mensaje del usuario
        chat_id: ID del chat (opcional)
        
    Returns:
        str: Respuesta del agente
    """
    return await _service.handle_message(message_content, chat_id)


async def get_pentesting_file_path(chat_id: str) -> str:
    """
    Obtiene la ruta del archivo de informe de pentesting para un chat.
    
    Args:
        chat_id: ID del chat
        
    Returns:
        str: Ruta completa del archivo de informe
    """
    return await _service.get_pentesting_file_path(chat_id)


async def get_chat_history_file_path(chat_id: str) -> str:
    """
    Obtiene la ruta del archivo de historial para un chat.
    
    Args:
        chat_id: ID del chat
        
    Returns:
        str: Ruta completa del archivo de historial
    """
    return await _service.get_chat_history_file_path(chat_id)


def get_agent():
    """
    Obtiene la instancia del agente.
    
    Returns:
        FunctionAgent: Instancia del agente o None si no está inicializado
    """
    return _service.agent


def get_chat_contexts():
    """
    Obtiene el contexto del agente.
    
    Returns:
        Context: Contexto del agente o None si no está inicializado
    """
    return _service.agent_context


def get_pentesting_processor():
    """
    Obtiene el procesador de informes de pentesting.
    
    Returns:
        PentestProcessor: Procesador de informes o None si no está inicializado
    """
    return _service.pentesting_processor


def get_pentesting_reports() -> Dict[str, str]:
    """
    Obtiene el diccionario de rutas de informes de pentesting.
    
    Returns:
        Dict[str, str]: Diccionario que mapea chat_id a ruta de archivo
    """
    return _service.pentesting_reports


def get_chat_histories() -> Dict[str, str]:
    """
    Obtiene el diccionario de rutas de historiales de chat.
    
    Returns:
        Dict[str, str]: Diccionario que mapea chat_id a ruta de archivo
    """
    return _service.chat_histories


def get_processing_lock() -> asyncio.Lock:
    """
    Obtiene el lock de procesamiento para sincronización.
    
    Returns:
        asyncio.Lock: Lock para sincronización de operaciones
    """
    return _service.processing_lock
