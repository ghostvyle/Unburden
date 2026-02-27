"""
Endpoints de gestión del modelo LLM activo
"""
import asyncio
import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/llm", tags=["LLM"])

_CONFIG_DIR = Path("config/llms")
_ACTIVE_MODEL_FILE = _CONFIG_DIR / "active_model.json"
_PROFILES_DIR = _CONFIG_DIR / "profiles"


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


def _run_ollama(args: List[str], timeout: int = 10) -> str:
    """Ejecuta un comando ollama de forma síncrona (solo para comandos rápidos)."""
    try:
        result = subprocess.run(
            ["ollama"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        logger.warning(f"ollama {' '.join(args)} timed out after {timeout}s")
        return ""
    except FileNotFoundError:
        logger.error("ollama command not found in PATH")
        return ""
    except Exception as e:
        logger.debug(f"ollama {' '.join(args)} failed: {e}")
        return ""


def _parse_ollama_list(output: str) -> List[str]:
    """Parsea la salida de 'ollama list' → lista de nombres:tag."""
    models = []
    lines = output.strip().splitlines()
    for line in lines[1:]:  # skip header
        parts = line.split()
        if parts:
            models.append(parts[0])
    return models


def _get_ollama_available_models() -> List[str]:
    """Modelos descargados localmente."""
    return _parse_ollama_list(_run_ollama(["list"]))


def _get_ollama_loaded_models() -> List[str]:
    """Modelos actualmente en RAM/VRAM."""
    return _parse_ollama_list(_run_ollama(["ps"]))


def _is_model_downloaded(model: str, available: List[str]) -> bool:
    """Comprueba si un modelo está descargado — coincidencia exacta por nombre:tag."""
    model_lower = model.lower()
    for av in available:
        if av.lower() == model_lower:
            return True
    return False


def _stop_ollama_model(model: str) -> None:
    """Para un modelo en Ollama para liberar memoria."""
    out = _run_ollama(["stop", model], timeout=10)
    logger.info(f"ollama stop {model}: {out or 'ok'}")


def _save_active_model(profile_id: str, model: str) -> None:
    """Persiste el modelo activo en active_model.json."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(_ACTIVE_MODEL_FILE, "w") as f:
        json.dump({"model": model, "profile": profile_id}, f, indent=2)


async def _async_ollama_pull(model: str, timeout: int = 600) -> tuple[bool, str]:
    """
    Descarga un modelo usando asyncio.create_subprocess_exec para no bloquear
    el event loop de FastAPI durante la descarga.
    Returns (success, stderr_on_failure)
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "ollama", "pull", model,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return False, f"Timeout pulling '{model}' after {timeout}s"

        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            return False, err
        return True, ""
    except FileNotFoundError:
        return False, "ollama command not found in PATH"
    except Exception as e:
        return False, str(e)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status")
async def get_llm_status() -> JSONResponse:
    """Devuelve el modelo activo actual."""
    active = _get_active_model_info()
    # Run quick ollama queries in a thread to avoid blocking
    loop = asyncio.get_event_loop()
    loaded = await loop.run_in_executor(None, _get_ollama_loaded_models)
    available = await loop.run_in_executor(None, _get_ollama_available_models)

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
    loop = asyncio.get_event_loop()
    available = await loop.run_in_executor(None, _get_ollama_available_models)
    loaded = await loop.run_in_executor(None, _get_ollama_loaded_models)
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

    loop = asyncio.get_event_loop()
    available = await loop.run_in_executor(None, _get_ollama_available_models)
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

    # 3. Parar modelo actual (rápido → executor)
    active_info = _get_active_model_info()
    current_model = active_info.get("model", "")
    if current_model and current_model != target_model:
        await loop.run_in_executor(None, _stop_ollama_model, current_model)

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
    loop = asyncio.get_event_loop()
    loaded = await loop.run_in_executor(None, _get_ollama_loaded_models)
    available = await loop.run_in_executor(None, _get_ollama_available_models)
    return JSONResponse({
        "loaded_in_memory": loaded,
        "downloaded": available,
    })
