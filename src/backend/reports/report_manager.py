"""
Módulo mejorado para el procesamiento de informes de pentesting
"""
import os
import asyncio
import logging
import traceback
from datetime import datetime
from typing import Optional, Dict

from src.backend.utils.utils import filter_unwanted_tags, sanitize_filename

logger = logging.getLogger(__name__)

class PentestProcessor:
    """Procesador profesional de informes de pentesting"""

    REPORTS_DIR = "data/reports"
    
    def __init__(self, pentesting_files: Dict[str, str], processing_lock: asyncio.Lock):
        self.pentesting_files = pentesting_files
        self.processing_lock = processing_lock
        self._ensure_report_directories()

    def _ensure_report_directories(self):
        """Crea los directorios data/ y data/reports/ si no existen."""
        os.makedirs(self.REPORTS_DIR, exist_ok=True)

    
    async def extract_context_from_md(self, chat_id: str) -> str:
        """Extrae el contexto existente del archivo .md"""
        try:
            async with self.processing_lock:
                file_path = self.pentesting_files.get(chat_id)

            if file_path and os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                logger.debug(f"Extracted {len(content)} characters from pentesting file for chat {chat_id}")
                return content
            return ""
        except Exception as e:
            logger.error(f"Error extracting context from .md for chat {chat_id}: {e}")
            return ""
    
    async def save_report_to_md(self, chat_id: str, report_content: str):
        """Guarda el contenido del informe en el archivo .md de forma segura"""
        try:
            # Validar contenido (sin límite de tamaño - totalmente flexible)
            if not report_content:
                raise ValueError("Report content is empty")

            # Crear archivo si no existe
            async with self.processing_lock:
                if chat_id not in self.pentesting_files:
                    safe_filename = f"{sanitize_filename(chat_id)}.md"
                    file_path = os.path.join(self.REPORTS_DIR, safe_filename)
                    self.pentesting_files[chat_id] = file_path

            # Guardar el contenido en el archivo .md
            file_path = self.pentesting_files[chat_id]
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report_content)

            logger.debug(f"Report saved to: {file_path}")

        except Exception as e:
            logger.error(f"Error saving report for chat {chat_id}: {e}")
            raise
    
    async def process_pentesting_report(self, chat_id: str, user_prompt: str, model_response: str, processing_timeout: int = None) -> Optional[str]:
        """
        Procesa y actualiza el informe de pentesting de forma profesional.
        Crea un informe básico directamente sin LLM (la generación avanzada
        se maneja desde el endpoint /generar-informe).
        """
        logger.info(f"Starting pentesting processing for chat {chat_id}")

        try:
            # Extraer contexto existente
            logger.debug(f"Extracting context for chat {chat_id}")
            current_report_text = await self.extract_context_from_md(chat_id)

            # Determinar si es el primer entry o una continuación
            is_first_entry = not current_report_text or len(current_report_text.strip()) < 200
            logger.debug(f"Is first entry: {is_first_entry}")

            # Crear informe básico directamente
            processed_report = await self._create_basic_report(user_prompt, model_response, current_report_text)

            # Guardar el informe procesado
            logger.debug(f"Saving report for chat {chat_id}")
            await self.save_report_to_md(chat_id, processed_report)

            logger.info(f"Basic pentesting report {'created' if is_first_entry else 'updated'} for chat {chat_id}")
            return processed_report

        except Exception as e:
            logger.error(f"Error processing pentesting report for chat {chat_id}: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            # Crear informe básico como fallback final
            try:
                basic_report = await self._create_basic_report(user_prompt, model_response, "")
                await self.save_report_to_md(chat_id, basic_report)
                logger.info(f"Fallback basic report created for chat {chat_id}")
                return basic_report
            except Exception as backup_error:
                logger.error(f"Error creating fallback basic report for chat {chat_id}: {backup_error}")
                return None
    
    async def _create_basic_report(self, user_prompt: str, model_response: str, existing_content: str = "") -> str:
        """Crea un informe básico cuando falla el procesamiento avanzado"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cleaned_response = filter_unwanted_tags(model_response)
        
        if existing_content and existing_content.strip():
            # Actualizar informe existente - añadir nueva entrada
            logger.debug(f"Updating existing report with {len(existing_content)} characters")
            new_entry = f"""

### [{timestamp}] - Nueva Actividad
- **Pregunta**: {user_prompt}
- **Respuesta**: {cleaned_response[:500]}{'...' if len(cleaned_response) > 500 else ''}

---
"""
            return existing_content + new_entry
        else:
            # Crear nuevo informe básico
            logger.debug("Creating new basic report")
            return f"""# Informe de Pentesting de Ciberseguridad

**Sesión iniciada**: {timestamp}
**Herramienta**: Unburden v.1

## Actividades Registradas

### [{timestamp}] - Primera Actividad
- **Pregunta**: {user_prompt}
- **Respuesta**: {cleaned_response[:500]}{'...' if len(cleaned_response) > 500 else ''}

---
*Informe generado automáticamente por Unburden v.1*
"""