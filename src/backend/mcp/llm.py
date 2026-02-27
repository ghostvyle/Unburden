"""
Gestor del LLM - carga configuración desde active_model.json y el perfil correspondiente
"""
import json
import logging
import os
from pathlib import Path

from llama_index.llms.ollama import Ollama
from llama_index.core import Settings

logger = logging.getLogger(__name__)

# Rutas de configuración
_CONFIG_DIR = Path("config/llms")
_ACTIVE_MODEL_FILE = _CONFIG_DIR / "active_model.json"
_PROFILES_DIR = _CONFIG_DIR / "profiles"

# LLM global (singleton, puede ser reemplazado con reload_llm)
llm: Ollama = None


def _load_active_profile() -> dict:
    """
    Lee active_model.json y carga el perfil correspondiente.

    Returns:
        dict: Perfil del modelo activo, o defaults si no se encuentra
    """
    defaults = {
        "id": "qwen3_14b",
        "name": "Qwen3 14B",
        "model": os.getenv("LLM_MODEL", "qwen3:14b"),
        "thinking": True,
        "temperature": 0.1,
        "num_predict": 32768,
    }

    try:
        with open(_ACTIVE_MODEL_FILE, "r") as f:
            active = json.load(f)

        profile_id = active.get("profile")
        profile_file = _PROFILES_DIR / f"{profile_id}.json"

        if profile_file.exists():
            with open(profile_file, "r") as f:
                return json.load(f)
        else:
            logger.warning(f"Profile file '{profile_file}' not found, using defaults")
            return defaults

    except FileNotFoundError:
        logger.warning(
            f"active_model.json not found at '{_ACTIVE_MODEL_FILE}', using defaults"
        )
        return defaults
    except Exception as e:
        logger.error(f"Error loading LLM profile: {e}, using defaults")
        return defaults


def _build_llm(profile: dict) -> Ollama:
    """Construye instancia Ollama a partir de un perfil."""
    model = profile.get("model", os.getenv("LLM_MODEL", "qwen3:14b"))
    thinking = profile.get("thinking", True)
    temperature = profile.get("temperature", 0.1)
    num_predict = profile.get("num_predict", 32768)

    ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    instance = Ollama(
        model=model,
        base_url=ollama_host,
        request_timeout=999999,
        thinking=thinking,
        temperature=temperature,
        additional_kwargs={"num_predict": num_predict},
    )
    logger.info(
        f"LLM initialized: model={model}, thinking={thinking}, "
        f"temperature={temperature}, num_predict={num_predict}"
    )
    return instance


def reload_llm() -> Ollama:
    """
    Recarga el LLM desde la configuración activa actual.
    Llamar después de modificar active_model.json.

    Returns:
        Ollama: Nueva instancia del LLM
    """
    global llm
    profile = _load_active_profile()
    llm = _build_llm(profile)
    Settings.llm = llm
    logger.info(f"LLM reloaded with profile: {profile.get('id', 'unknown')}")
    return llm


def get_llm() -> Ollama:
    """Obtiene la instancia del LLM (inicializa si no existe)."""
    global llm
    if llm is None:
        llm = reload_llm()
    return llm


def get_active_profile() -> dict:
    """Devuelve el perfil activo actualmente cargado."""
    return _load_active_profile()


# Inicializar al importar el módulo
reload_llm()
