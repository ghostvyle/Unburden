#!/usr/bin/env python3
"""
=========================================
Unburden - Pentesting Assistant
By Ghostvyle
=========================================
"""

import sys
import os
from pathlib import Path

# Add project root and src to Python path
src_path = Path(__file__).parent  # This is the 'src' directory
project_root = src_path.parent      # This is the project root
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(src_path))

# Import and run the main API server
if __name__ == "__main__":
    import argparse
    import logging
    import uvicorn

    # Importar config
    from src.backend.config.config import LLM_MODEL, CORS_ORIGINS, logger

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Unburden - Pentesting Assistant')
    parser.add_argument('--host', default='0.0.0.0', help='Host to start the server on')
    parser.add_argument('--port', type=int, default='7777', help='Port to start the server on')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload')
    parser.add_argument('--log-level', default='info', choices=['debug', 'info', 'warning', 'error'], help='Log level')

    args = parser.parse_args()

    # Configure logging level
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if isinstance(numeric_level, int):
        logging.getLogger().setLevel(numeric_level)

    logger.info(f"Starting Unburden on {args.host}:{args.port}")

    try:
        uvicorn.run(
            "src.backend.main:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            log_level=args.log_level,
            access_log=True
        )
    except KeyboardInterrupt:
        logger.info("Shutting down Unburden...")
    except Exception as e:
        logger.error(f"Error starting server: {e}")
        raise
