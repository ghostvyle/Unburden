"""
Endpoints de gestión del modelo LLM activo
"""
import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/llm", tags=["LLM"])

_CONFIG_DIR = Path("config/llms")
_ACTIVE_MODEL_FILE = _CONFIG_DIR / "active_model.json"
_PROFILES_DIR = _CONFIG_DIR / "profiles"
_OLLAMA_BASE = os.getenv("OLLAMA_HOST", "http://localhost:11434")


# ── Schemas ──────────────────────────────────────────────────────────────────

class SwitchModelRequest(BaseModel):
    profile_id: str
    confirm_pull: bool = False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_all_profiles() -> List[Dict[str, Any]]:
    """Carga todos los perfiles disponibles en config/llms/profiles/."""
    profiles = []
    if not _PROFILES_DIR.exists():
        return profiles
    for file in sorted(_PROFILES_DIR.glob("*.json")):
        try:
            with open(file) as f:
                profiles.append(json.load(f))
        except Exception as e:
            logger.warning(f"Could not load profile '{file.name}': {e}")
    return profiles


def _get_active_model_info() -> Dict[str, Any]:
    """Lee el estado actual de active_model.json."""
    try:
        with open(_ACTIVE_MODEL_FILE) as f:
            return json.load(f)
    except Exception:
        return {"model": "unknown", "profile": "unknown"}


async def _get_ollama_available_models() -> List[str]:
    """Modelos descargados en Ollama (via API HTTP)."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{_OLLAMA_BASE}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
    except Exception as e:
        logger.warning(f"Could not list Ollama models: {e}")
        return []


async def _get_ollama_loaded_models() -> List[str]:
    """Modelos actualmente en RAM/VRAM (via API HTTP)."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{_OLLAMA_BASE}/api/ps")
            resp.raise_for_status()
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
    except Exception as e:
        logger.warning(f"Could not list loaded Ollama models: {e}")
        return []


def _is_model_downloaded(model: str, available: List[str]) -> bool:
    """Comprueba si un modelo está descargado — coincidencia exacta por nombre:tag."""
    model_lower = model.lower()
    for av in available:
        if av.lower() == model_lower:
            return True
    return False


async def _stop_ollama_model(model: str) -> None:
    """Para un modelo en Ollama para liberar memoria (via API HTTP)."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{_OLLAMA_BASE}/api/generate",
                json={"model": model, "keep_alive": 0},
            )
            logger.info(f"ollama stop {model}: {resp.status_code}")
    except Exception as e:
        logger.warning(f"Could not stop model {model}: {e}")


def _save_active_model(profile_id: str, model: str) -> None:
    """Persiste el modelo activo en active_model.json."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(_ACTIVE_MODEL_FILE, "w") as f:
        json.dump({"model": model, "profile": profile_id}, f, indent=2)


async def _async_ollama_pull(model: str, timeout: int = 600) -> tuple[bool, str]:
    """Descarga un modelo via API HTTP de Ollama."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            resp = await client.post(
                f"{_OLLAMA_BASE}/api/pull",
                json={"name": model},
            )
            if resp.status_code != 200:
                return False, f"HTTP {resp.status_code}: {resp.text}"
            return True, ""
    except httpx.TimeoutException:
        return False, f"Timeout pulling '{model}' after {timeout}s"
    except Exception as e:
        return False, str(e)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status")
async def get_llm_status() -> JSONResponse:
    """Devuelve el modelo activo actual."""
    active = _get_active_model_info()
    loaded = await _get_ollama_loaded_models()
    available = await _get_ollama_available_models()

    model = active.get("model", "unknown")
    return JSONResponse({
        "model": model,
        "profile": active.get("profile", "unknown"),
        "is_loaded": any(m.lower() == model.lower() for m in loaded),
        "is_downloaded": _is_model_downloaded(model, available),
    })


@router.get("/models")
async def list_models() -> JSONResponse:
    """
    Lista todos los perfiles configurados en config/llms/profiles/,
    enriquecidos con estado real de Ollama.
    """
    profiles = _load_all_profiles()
    available = await _get_ollama_available_models()
    loaded = await _get_ollama_loaded_models()
    active_info = _get_active_model_info()
    active_profile = active_info.get("profile", "")

    result = []
    for p in profiles:
        model = p.get("model", "")
        downloaded = _is_model_downloaded(model, available)
        in_memory = any(m.lower() == model.lower() for m in loaded)
        result.append({
            **p,
            "is_downloaded": downloaded,
            "is_loaded": in_memory,
            "is_active": p.get("id") == active_profile,
        })

    return JSONResponse({"models": result, "active_profile": active_profile})


@router.post("/switch")
async def switch_model(request: SwitchModelRequest) -> JSONResponse:
    """
    Cambia el modelo activo.

    Flujo:
    1. Valida perfil
    2. Si no está descargado y confirm_pull=False → 202 needs_pull
    3. Para el modelo actual en Ollama
    4. Descarga si confirm_pull=True (async, no bloquea)
    5. Actualiza active_model.json
    6. Recarga LLM + reinicia agente
    """
    profile_file = _PROFILES_DIR / f"{request.profile_id}.json"
    if not profile_file.exists():
        raise HTTPException(404, detail=f"Profile '{request.profile_id}' not found")

    try:
        with open(profile_file) as f:
            profile = json.load(f)
    except Exception as e:
        raise HTTPException(500, detail=f"Error leyendo perfil: {e}")

    target_model = profile.get("model", "")
    if not target_model:
        raise HTTPException(400, detail="Perfil sin campo 'model'")

    available = await _get_ollama_available_models()
    downloaded = _is_model_downloaded(target_model, available)

    # 2. Sin confirmación y no descargado → pedir confirmación al usuario
    if not downloaded and not request.confirm_pull:
        return JSONResponse({
            "needs_pull": True,
            "model": target_model,
            "name": profile.get("name"),
            "size_gb": profile.get("size_gb", "?"),
            "message": (
                f"El modelo '{profile.get('name')}' no está descargado. "
                f"Ocupa ~{profile.get('size_gb', '?')} GB. "
                "Envía confirm_pull=true para descargarlo."
            ),
        }, status_code=202)

    # 3. Parar modelo actual
    active_info = _get_active_model_info()
    current_model = active_info.get("model", "")
    if current_model and current_model != target_model:
        await _stop_ollama_model(current_model)

    # 4. Pull asíncrono si hace falta
    if not downloaded:
        logger.info(f"Pulling '{target_model}' (async)...")
        success, err = await _async_ollama_pull(target_model)
        if not success:
            raise HTTPException(500, detail=f"Error descargando modelo: {err}")
        logger.info(f"Pull completado: {target_model}")

    # 5. Actualizar configuración
    _save_active_model(request.profile_id, target_model)

    # 6. Recargar LLM + agente
    try:
        from src.backend.mcp.llm import reload_llm
        from src.backend.agent.agent_manager import initialize_agent

        reload_llm()
        await initialize_agent()

        logger.info(f"Model switched to '{target_model}' (profile: {request.profile_id})")
        return JSONResponse({
            "success": True,
            "model": target_model,
            "profile": request.profile_id,
            "name": profile.get("name"),
            "message": f"Modelo cambiado a '{profile.get('name')}' correctamente.",
        })
    except Exception as e:
        logger.error(f"Error reiniciando agente tras cambio: {e}")
        raise HTTPException(500, detail=f"Error reiniciando agente: {e}")


@router.get("/ollama/running")
async def get_running_models() -> JSONResponse:
    """Modelos actualmente cargados en memoria por Ollama."""
    loaded = await _get_ollama_loaded_models()
    available = await _get_ollama_available_models()
    return JSONResponse({
        "loaded_in_memory": loaded,
        "downloaded": available,
    })
