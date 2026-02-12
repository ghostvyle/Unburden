"""
Gestor del LLM (Large Language Model)
"""
import logging
from llama_index.llms.ollama import Ollama
from llama_index.core import Settings
from src.backend.config.config import LLM_MODEL

logger = logging.getLogger(__name__)

# === Inicializar LLM ===
llm = Ollama(
    model=LLM_MODEL,
    request_timeout=999999,  # Timeout muy alto para operaciones largas
    thinking=True,  # Activar modo de pensamiento para razonamiento complejo
    temperature=0.1,  # Baja pero no 0: determinista con tool calling + evita loops de razonamiento
    additional_kwargs={
        "num_predict": 32768,  # Límite muy alto para tareas complejas multi-step (default: 256)
    }
)
Settings.llm = llm

logger.debug(f"LLM initialized with model: {LLM_MODEL}, num_predict: 32768, thinking: enabled")


def get_llm():
    """Obtiene la instancia del LLM"""
    return llm
