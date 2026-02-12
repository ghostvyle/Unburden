"""
Modelos Pydantic para la API de Unburden
"""
import json
from pydantic import BaseModel, validator
from src.backend.config.config import MAX_FILE_SIZE


class ContentRequest(BaseModel):
    """Modelo para solicitudes de edición de contenido"""
    content: str

    @validator('content')
    def validate_content(cls, v):
        if len(v.encode('utf-8')) > MAX_FILE_SIZE:
            raise ValueError(f'Content too large (max {MAX_FILE_SIZE} bytes)')
        return v


class MCPImportRequest(BaseModel):
    """Modelo para importación de configuraciones MCP"""
    mcpConfig: str

    @validator('mcpConfig')
    def validate_mcp_config(cls, v):
        try:
            # Validar que sea JSON válido
            parsed = json.loads(v)
            if not isinstance(parsed, dict):
                raise ValueError('MCP config must be a JSON object')
            return v
        except json.JSONDecodeError:
            raise ValueError('Invalid JSON format')
