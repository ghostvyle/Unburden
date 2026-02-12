"""
Funciones de utilidad principales para Unburden
"""
import json
import os
import re
import logging
from datetime import datetime
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Patrones regex precompilados para mejor rendimiento
_THINKING_TAG_PATTERNS = [
    re.compile(r'<think>.*?</think>', re.DOTALL | re.IGNORECASE),
    re.compile(r'<THINK>.*?</THINK>', re.DOTALL | re.IGNORECASE),
    re.compile(r'<thinking>.*?</thinking>', re.DOTALL | re.IGNORECASE),
    re.compile(r'<THINKING>.*?</THINKING>', re.DOTALL | re.IGNORECASE),
    re.compile(r'<reasoning>.*?</reasoning>', re.DOTALL | re.IGNORECASE),
    re.compile(r'<REASONING>.*?</REASONING>', re.DOTALL | re.IGNORECASE),
    re.compile(r'<internal>.*?</internal>', re.DOTALL | re.IGNORECASE),
    re.compile(r'<INTERNAL>.*?</INTERNAL>', re.DOTALL | re.IGNORECASE),
    re.compile(r'<debug>.*?</debug>', re.DOTALL | re.IGNORECASE),
    re.compile(r'<DEBUG>.*?</DEBUG>', re.DOTALL | re.IGNORECASE),
    re.compile(r'<think[^>]*>.*?</think[^>]*>', re.DOTALL | re.IGNORECASE),
    re.compile(r'<THINK[^>]*>.*?</THINK[^>]*>', re.DOTALL | re.IGNORECASE)
]

def filter_unwanted_tags(text: str) -> str:
    """
    Filtra y elimina etiquetas de pensamiento interno del texto.
    
    Elimina todas las etiquetas relacionadas con el razonamiento interno
    del modelo (como <THINK>, <thinking>, <reasoning>, etc.) y limpia
    líneas vacías y espacios extra.
    
    Args:
        text: Texto a filtrar
        
    Returns:
        str: Texto limpio sin etiquetas de pensamiento
    """
    if not text:
        return text
    
    # Eliminar etiquetas de pensamiento usando patrones precompilados
    cleaned_text = text
    for pattern in _THINKING_TAG_PATTERNS:
        cleaned_text = pattern.sub('', cleaned_text)
    
    # Limpiar líneas vacías y espacios extra
    lines = cleaned_text.split('\n')
    cleaned_lines = []
    for line in lines:
        stripped_line = line.strip()
        if stripped_line:
            cleaned_lines.append(stripped_line)
    
    return '\n'.join(cleaned_lines)

def sanitize_filename(filename: str, max_length: int = 100) -> str:
    """
    Sanitiza un nombre de archivo para uso seguro en el sistema de archivos.
    
    Reemplaza caracteres no válidos por guiones bajos y limita la longitud
    del nombre de archivo.
    
    Args:
        filename: Nombre de archivo a sanitizar
        max_length: Longitud máxima permitida (por defecto 100)
        
    Returns:
        str: Nombre de archivo sanitizado y seguro
    """
    # Eliminar caracteres no válidos
    safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    
    # Limitar longitud
    if len(safe_filename) > max_length:
        safe_filename = safe_filename[:max_length]
    
    return safe_filename

def generate_date_based_id() -> str:
    """
    Genera un ID único basado en la fecha y hora actual.
    
    El formato es: YYYY-MM-DD-HH-MM-SS (año-mes-día-hora-minuto-segundo)
    
    Returns:
        str: ID generado basado en la fecha y hora actual
    """
    return datetime.now().strftime('%Y-%m-%d-%H-%M-%S')

def parse_messages_from_md(md_content: str) -> List[Dict[str, Any]]:
    """
    Parsea mensajes desde contenido Markdown.
    Parser simple y robusto que nunca falla.

    Args:
        md_content: Contenido del archivo .md

    Returns:
        Lista de mensajes: [{"role": "user", "content": "...", "timestamp": "..."}]
    """
    messages: List[Dict[str, Any]] = []

    # Separar por bloques usando el separador real entre mensajes
    # El separador completo es: \n---\n seguido de comentario HTML <!--
    # Esto evita dividir cuando --- aparece dentro del contenido del mensaje
    # Usar split con un patrón que capture el separador completo
    blocks = re.split(r'\n---\n(?=<!--)', md_content)

    # Regex para extraer JSON de comentarios HTML
    json_regex = re.compile(r'<!--\s*(.*?)\s*-->', re.DOTALL)

    # Regex para extraer contenido de bloques de código
    content_regex = re.compile(r'````(?:json|text)\n(.*?)\n````', re.DOTALL)

    for block in blocks:
        if not block.strip():
            continue

        # Verificar que contenga un comentario HTML y un label de rol válido
        # (el primer bloque es la cabecera, no tiene esto)
        if not ('<!--' in block and ('**User:**' in block or '**Unburden:**' in block or '**System:**' in block)):
            continue

        try:
            # Extraer metadatos JSON
            json_match = json_regex.search(block)
            role: str
            timestamp: str
            if json_match:
                try:
                    metadata: Dict[str, Any] = json.loads(json_match.group(1))
                    role = metadata.get("role", "system")
                    timestamp = metadata.get("timestamp", "")
                except (json.JSONDecodeError, KeyError):
                    role = "system"
                    timestamp = ""
            else:
                # Fallback: inferir rol del label
                if '**User:**' in block:
                    role = "user"
                elif '**Unburden:**' in block:
                    role = "assistant"
                else:
                    role = "system"
                timestamp = ""

            # Extraer contenido
            content_match = content_regex.search(block)
            if content_match:
                content: str = content_match.group(1).strip()
            else:
                # Fallback: tomar todo el texto que no sea JSON ni labels
                content = block
                content = json_regex.sub('', content)  # Quitar JSON
                content = re.sub(r'\*\*(?:User|Unburden|System|Unknown):\*\*', '', content)  # Quitar labels
                content = content.strip()

            if content:
                messages.append({
                    "role": role,
                    "content": content,
                    "timestamp": timestamp
                })
        except Exception as e:
            logger.warning(f"Error parseando bloque: {e}")
            continue

    return messages