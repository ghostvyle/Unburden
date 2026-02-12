"""
Chat History Manager - Sistema de persistencia con Markdown como SSOT
Evita crashes de frontend mediante formato híbrido parseable y editable.
"""

from asyncio.log import logger
import os
import json
import re
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path


class ChatHistoryManager:
    """
    Gestiona el histórico de chat usando archivos Markdown como Single Source of Truth.

    Características:
    - Formato híbrido: JSON en comentarios HTML + Markdown
    - Editable por humanos, parseable por máquinas
    - Sincronización bidireccional Chat <-> Editor MD
    - Robusto ante errores de parseo
    """

    CHATS_DIR = "data/chats"
    INDEX_FILE = "data/chat_index.json"

    def __init__(self):
        """Inicializa el gestor y asegura que existen los directorios necesarios."""
        self._cached_index = None
        self._cache_dirty = True
        self._ensure_directories()

    def _ensure_directories(self):
        """Crea los directorios data/ y data/chats/ si no existen."""
        os.makedirs(self.CHATS_DIR, exist_ok=True)

        # Crear chat_index.json vacío si no existe
        if not os.path.exists(self.INDEX_FILE):
            with open(self.INDEX_FILE, 'w', encoding='utf-8') as f:
                json.dump([], f, indent=2, ensure_ascii=False)

    def get_chat_index(self) -> List[Dict]:
        """
        Devuelve el índice completo de chats.
        Usa caché en memoria para evitar lecturas de disco repetidas.

        Returns:
            Lista de diccionarios con metadata de cada chat:
            [{"id": "uuid", "title": "...", "timestamp": "..."}]
        """
        if not self._cache_dirty and self._cached_index is not None:
            return self._cached_index

        try:
            with open(self.INDEX_FILE, 'r', encoding='utf-8') as f:
                self._cached_index = json.load(f)
                self._cache_dirty = False
                return self._cached_index
        except (FileNotFoundError, json.JSONDecodeError):
            # Si hay error, devolver lista vacía y recrear el archivo
            self._cached_index = []
            self._cache_dirty = False
            with open(self.INDEX_FILE, 'w', encoding='utf-8') as f:
                json.dump([], f, indent=2, ensure_ascii=False)
            return self._cached_index
        
    def create_chat_history_entry(user_message: str, assistant_response: str) -> str:
        """Crea una entrada de historial de chat formateada"""
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return f"""
    ## [{timestamp}] Chat Entry

    **Usuario**: {user_message}

    **Unburden**: {assistant_response}

    ---
    """

    def load_or_create_chat_history(file_path: str) -> str:
        """Carga el historial de chat existente o crea uno nuevo"""
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Error loading chat history from {file_path}: {e}")
        
        # Crear historial inicial
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return f"""# Historial de Chat - Unburden v.1

    **Sesión iniciada**: {timestamp}
    **Sistema**: Unburden Cybersecurity Assistant

    ---
    """

    def save_chat_history(file_path: str, content: str):
        """Guarda el historial de chat"""
        try:
            # Crear directorio padre si no existe
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.debug(f"Chat history saved to: {file_path}")
        except Exception as e:
            logger.error(f"Error saving chat history to {file_path}: {e}")
            raise

    def _save_chat_index(self, index: List[Dict]):
            """Guarda el índice de chats en disco y actualiza la caché."""
            with open(self.INDEX_FILE, 'w', encoding='utf-8') as f:
                json.dump(index, f, indent=2, ensure_ascii=False)
            self._cached_index = index
            self._cache_dirty = False

    def create_new_chat(self, title: str, target: str = "") -> str:
            """
            Crea un nuevo chat con archivo .md vacío.

            Args:
                title: Título descriptivo del chat
                target: IP o hostname del objetivo (opcional)

            Returns:
                El ID del chat creado (UUID string)
            """
            # Generar ID único
      
            chat_id = str(uuid.uuid4())
            timestamp = datetime.utcnow().isoformat() + "Z"

            # Crear cabecera del archivo Markdown
            header = f"""# [Pentesting] {title}
    * **ID:** {chat_id}
    * **Timestamp:** {timestamp}
    * **Target:** {target}

    """

            # Crear el archivo .md
            chat_file_path = os.path.join(self.CHATS_DIR, f"{chat_id}.md")
            with open(chat_file_path, 'w', encoding='utf-8') as f:
                f.write(header)

            # Añadir entrada al índice
            index = self.get_chat_index()
            index.append({
                "id": chat_id,
                "title": title,
                "timestamp": timestamp,
                "target": target
            })
            self._save_chat_index(index)

            return chat_id

    def append_message_to_chat(self, chat_id: str, message_data: Dict):
        """
        Añade un nuevo mensaje al final del archivo .md del chat.

        Args:
            chat_id: UUID del chat
            message_data: Diccionario con los datos del mensaje:
                {
                    "role": "user" | "assistant" | "system",
                    "content": "...",
                    "type": "text" | "tool_call" | "error",
                    "timestamp": "2025-10-28T15:40:00Z" (opcional),
                    "id": "msg_uuid" (opcional)
                }
        """
        chat_file_path = os.path.join(self.CHATS_DIR, f"{chat_id}.md")

        # Verificar que el archivo existe
        if not os.path.exists(chat_file_path):
            raise FileNotFoundError(f"Chat file not found: {chat_id}")

        # Generar ID y timestamp si no existen
        msg_id = message_data.get("id", str(uuid.uuid4()))
        timestamp = message_data.get("timestamp", datetime.utcnow().isoformat() + "Z")

        # Construir metadatos JSON
        metadata = {
            "id": msg_id,
            "role": message_data["role"],
            "timestamp": timestamp,
            "type": message_data.get("type", "text")
        }

        # Determinar el label visible según el rol
        role_label = {
            "user": "**User:**",
            "assistant": "**Unburden:**",
            "system": "**System:**"
        }.get(message_data["role"], "**Unknown:**")

        # Determinar el tipo de bloque de código
        code_type = "json" if message_data.get("type") == "tool_call" else "text"

        # Construir el bloque completo
        block = f"""---
<!--
{json.dumps(metadata, indent=2, ensure_ascii=False)}
-->
{role_label}
````{code_type}
{message_data["content"]}
````

"""

        # Añadir al archivo (modo append)
        with open(chat_file_path, 'a', encoding='utf-8') as f:
            f.write(block)

    def save_full_chat(self, chat_id: str, full_md_content: str):
        """
        Sobrescribe completamente el contenido del archivo .md del chat.

        Esta función se usa cuando el usuario edita el histórico desde
        la "Vista de Pentest" (editor de Markdown).

        Args:
            chat_id: UUID del chat
            full_md_content: Contenido completo del archivo Markdown
        """
        chat_file_path = os.path.join(self.CHATS_DIR, f"{chat_id}.md")

        # Sobrescribir el archivo completo
        with open(chat_file_path, 'w', encoding='utf-8') as f:
            f.write(full_md_content)

    def load_chat_content(self, chat_id: str) -> str:
        """
        Carga el contenido raw (texto completo) del archivo .md.

        Args:
            chat_id: UUID del chat

        Returns:
            String con el contenido completo del archivo Markdown

        Raises:
            FileNotFoundError: Si el archivo no existe
        """
        chat_file_path = os.path.join(self.CHATS_DIR, f"{chat_id}.md")

        if not os.path.exists(chat_file_path):
            raise FileNotFoundError(f"Chat file not found: {chat_id}")

        with open(chat_file_path, 'r', encoding='utf-8') as f:
            return f.read()

    def delete_chat(self, chat_id: str) -> bool:
        """
        Elimina un chat completo (archivo .md y entrada en el índice).

        Args:
            chat_id: UUID del chat a eliminar

        Returns:
            True si se eliminó correctamente, False si no existía
        """
        chat_file_path = os.path.join(self.CHATS_DIR, f"{chat_id}.md")

        # Eliminar el archivo .md
        if os.path.exists(chat_file_path):
            os.remove(chat_file_path)
        else:
            return False

        # Eliminar del índice
        index = self.get_chat_index()
        index = [chat for chat in index if chat["id"] != chat_id]
        self._save_chat_index(index)

        return True

    def update_chat_title(self, chat_id: str, new_title: str):
        """
        Actualiza el título de un chat en el índice y en la cabecera del .md.

        Args:
            chat_id: UUID del chat
            new_title: Nuevo título
        """
        # Actualizar en el índice
        index = self.get_chat_index()
        for chat in index:
            if chat["id"] == chat_id:
                chat["title"] = new_title
                break
        self._save_chat_index(index)

        # Actualizar en el archivo .md (solo la primera línea)
        chat_file_path = os.path.join(self.CHATS_DIR, f"{chat_id}.md")
        if os.path.exists(chat_file_path):
            with open(chat_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Reemplazar la primera línea (título)
            if lines and lines[0].startswith("# "):
                lines[0] = f"# [Pentest] {new_title}\n"

            with open(chat_file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)

    def update_chat_target(self, chat_id: str, new_target: str):
        """
        Actualiza el target de un chat en el índice y en la cabecera del .md.

        Args:
            chat_id: UUID del chat
            new_target: Nuevo target (IP o hostname)
        """
        # Actualizar en el índice
        index = self.get_chat_index()
        for chat in index:
            if chat["id"] == chat_id:
                chat["target"] = new_target
                break
        self._save_chat_index(index)

        # Actualizar en el archivo .md (línea del Target)
        chat_file_path = os.path.join(self.CHATS_DIR, f"{chat_id}.md")
        if os.path.exists(chat_file_path):
            with open(chat_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Buscar y reemplazar la línea del Target
            for i, line in enumerate(lines):
                if line.startswith("* **Target:**"):
                    lines[i] = f"* **Target:** {new_target}\n"
                    break

            with open(chat_file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)

    def chat_exists(self, chat_id: str) -> bool:
        """Verifica si un chat existe."""
        chat_file_path = os.path.join(self.CHATS_DIR, f"{chat_id}.md")
        return os.path.exists(chat_file_path)

def validate_session_id(session_id: str) -> bool:
    """Valida que el session_id sea seguro para usar como nombre de archivo"""
    if not session_id or len(session_id.strip()) == 0:
        return False
    
    # Permitir solo caracteres alfanuméricos, guiones y guiones bajos
    if not re.match(r'^[a-zA-Z0-9_-]+$', session_id):
        return False
    
    # Limitar longitud
    if len(session_id) > 100:
        return False
    
    return True

def create_chat_history_entry(user_message: str, assistant_response: str) -> str:
    """Crea una entrada de historial de chat formateada"""
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    return f"""
## [{timestamp}] Chat Entry

**Usuario**: {user_message}

**Unburden**: {assistant_response}

---
"""

def load_or_create_chat_history(file_path: str) -> str:
    """Carga el historial de chat existente o crea uno nuevo"""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error loading chat history from {file_path}: {e}")
    
    # Crear historial inicial
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return f"""# Historial de Chat - Unburden v.1

**Sesión iniciada**: {timestamp}
**Sistema**: Unburden Cybersecurity Assistant

---
"""

def save_chat_history(file_path: str, content: str):
    """Guarda el historial de chat"""
    try:
        # Crear directorio padre si no existe
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.debug(f"Chat history saved to: {file_path}")
    except Exception as e:
        logger.error(f"Error saving chat history to {file_path}: {e}")
        raise
