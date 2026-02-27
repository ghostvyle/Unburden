"""
Gestor del LLM - carga configuración desde active_model.json y el perfil correspondiente
"""
import json
import logging
import os
from pathlib import Path
from typing import List, Optional

import httpx
from llama_index.llms.ollama import Ollama
from llama_index.core import Settings

logger = logging.getLogger(__name__)

# Rutas de configuración
_CONFIG_DIR = Path("config/llms")
_ACTIVE_MODEL_FILE = _CONFIG_DIR / "active_model.json"
_PROFILES_DIR = _CONFIG_DIR / "profiles"
_OLLAMA_BASE = os.getenv("OLLAMA_HOST", "http://localhost:11434")

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
        "num_ctx": 4096,
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


def _load_all_profiles() -> List[dict]:
    """Carga todos los perfiles disponibles."""
    profiles = []
    if not _PROFILES_DIR.exists():
        return profiles
    for file in sorted(_PROFILES_DIR.glob("*.json")):
        try:
            with open(file) as f:
                profiles.append(json.load(f))
        except Exception:
            pass
    return profiles


def _save_active_model(profile_id: str, model: str) -> None:
    """Persiste el modelo activo en active_model.json."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(_ACTIVE_MODEL_FILE, "w") as f:
        json.dump({"model": model, "profile": profile_id}, f, indent=2)


def _build_llm(profile: dict) -> Ollama:
    """Construye instancia Ollama a partir de un perfil."""
    model = profile.get("model", os.getenv("LLM_MODEL", "qwen3:14b"))
    thinking = profile.get("thinking", True)
    temperature = profile.get("temperature", 0.1)
    num_predict = profile.get("num_predict", 32768)
    num_ctx = profile.get("num_ctx", 4096)

    instance = Ollama(
        model=model,
        base_url=_OLLAMA_BASE,
        request_timeout=999999,
        thinking=thinking,
        temperature=temperature,
        context_window=num_ctx,
        additional_kwargs={"num_predict": num_predict, "num_ctx": num_ctx},
    )
    logger.info(
        f"LLM initialized: model={model}, thinking={thinking}, "
        f"temperature={temperature}, num_predict={num_predict}, num_ctx={num_ctx}"
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


async def validate_and_fix_active_model() -> Optional[str]:
    """
    Valida que el modelo activo esté descargado en Ollama.
    Si no lo está, busca el mayor modelo descargado que tenga perfil y lo activa.

    Returns:
        Optional[str]: Nombre del modelo al que se hizo fallback, o None si todo OK.
    """
    profile = _load_active_profile()
    active_model = profile.get("model", "")

    # Comprobar si Ollama está disponible
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{_OLLAMA_BASE}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            available = [m["name"] for m in data.get("models", [])]
    except Exception as e:
        logger.error(f"[LLM] Ollama not reachable at {_OLLAMA_BASE}: {e}")
        return None

    # Comprobar si el modelo activo está descargado
    active_lower = active_model.lower()
    if any(m.lower() == active_lower for m in available):
        logger.info(f"[LLM] Active model '{active_model}' is available in Ollama")
        return None

    logger.warning(f"[LLM] Active model '{active_model}' is NOT downloaded in Ollama!")
    logger.warning(f"[LLM] Available models: {available}")

    # Buscar fallback: el mayor modelo descargado que tenga perfil configurado
    profiles = _load_all_profiles()
    fallback = None
    for p in sorted(profiles, key=lambda x: x.get("size_gb", 0), reverse=True):
        p_model = p.get("model", "")
        if any(m.lower() == p_model.lower() for m in available):
            fallback = p
            break

    if fallback:
        fallback_model = fallback["model"]
        fallback_id = fallback["id"]
        logger.warning(
            f"[LLM] Switching to fallback model: '{fallback['name']}' ({fallback_model})"
        )
        _save_active_model(fallback_id, fallback_model)
        reload_llm()
        return fallback_model
    else:
        logger.error(
            "[LLM] No downloaded model matches any configured profile. "
            "Please download a model with: ollama pull <model>"
        )
        return None


# Inicializar al importar el módulo
reload_llm()
