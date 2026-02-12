"""
Unburden v.1 - Punto de entrada principal de la API
Sistema de asistente de ciberseguridad con integración MCP
"""
import atexit
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os

# Import config and logger
from src.backend.config.config import CORS_ORIGINS, logger
from src.backend.agent.agent_manager import initialize_agent
from src.backend.mcp.mcp_client import get_mcp_manager

# Import routes
from src.backend.routes.chat import router as chat_router
from src.backend.routes.pentesting import router as pentesting_router
from src.backend.routes.mcp import router as mcp_router


# === Lifecycle del servidor ===
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestión del ciclo de vida de la aplicación"""
    # Startup
    # Initialization happens silently

    # Fusionar configuraciones MCP
    mcp_manager = get_mcp_manager()
    mcp_manager.merge_configurations()

    #Create directory for data if not exists
    os.makedirs('data', exist_ok=True)


    # Inicializar agente
    await initialize_agent()

    yield


# === Inicializar FastAPI ===
app = FastAPI(title="Unburden", lifespan=lifespan)


# === Configurar CORS ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permitir todos los orígenes temporalmente para debug
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"]
)


# === Health check ===
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok", "message": "Unburden is running"}


# === Registrar routers ===
app.include_router(chat_router, tags=["Chat"])
app.include_router(pentesting_router, tags=["Pentesting"])
app.include_router(mcp_router, tags=["MCP"])


# === Servir frontend ===
app.mount("/app", StaticFiles(directory="src/frontend/dist", html=True), name="frontend")


@app.get("/")
async def root():
    """Redirige a la aplicación frontend"""
    return RedirectResponse("/app")


# === Punto de entrada ===
if __name__ == "__main__":
    uvicorn.run("backend.server.main:app", host="0.0.0.0", port=7777, reload=True)
