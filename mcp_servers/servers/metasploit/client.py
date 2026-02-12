import asyncio
from typing import Any, Dict, Optional

from pymetasploit3.msfrpc import MsfConsole, MsfRpcClient, MsfRpcError

# Support both relative imports (package) and absolute imports (direct execution)
try:
    from .config import (
        MSF_PASSWORD,
        MSF_PORT_STR,
        MSF_SERVER,
        MSF_SSL_STR,
        RPC_CALL_TIMEOUT,
        logger,
    )
except ImportError:
    from config import (
        MSF_PASSWORD,
        MSF_PORT_STR,
        MSF_SERVER,
        MSF_SSL_STR,
        RPC_CALL_TIMEOUT,
        logger,
    )

_msf_client_instance: Optional[MsfRpcClient] = None

def initialize_msf_client() -> MsfRpcClient:
    global _msf_client_instance
    if _msf_client_instance is not None:
        return _msf_client_instance
    logger.debug("Attempting to initialize Metasploit RPC client...")
    try:
        msf_port = int(MSF_PORT_STR)
        msf_ssl = MSF_SSL_STR.lower() == 'true'
    except ValueError as e:
        logger.error(f"Invalid MSF connection parameters (PORT: {MSF_PORT_STR}, SSL: {MSF_SSL_STR}). Error: {e}")
        raise ValueError("Invalid MSF connection parameters") from e
    try:
        logger.debug(f"Attempting to create MsfRpcClient connection to {MSF_SERVER}:{msf_port} (SSL: {msf_ssl})...")
        client = MsfRpcClient(password=MSF_PASSWORD, server=MSF_SERVER, port=msf_port, ssl=msf_ssl)
        logger.debug("Testing connection with core.version call...")
        version_info = client.core.version
        msf_version = version_info.get('version', 'unknown') if isinstance(version_info, dict) else 'unknown'
        logger.debug(f"Metasploit RPC connected ({msf_version})")
        _msf_client_instance = client
        return _msf_client_instance
    except MsfRpcError as e:
        logger.error(f"Failed to connect or authenticate to Metasploit RPC ({MSF_SERVER}:{msf_port}, SSL: {msf_ssl}): {e}")
        raise ConnectionError(f"Failed to connect/authenticate to Metasploit RPC: {e}") from e
    except Exception as e:
        logger.error(f"An unexpected error occurred during MSF client initialization: {e}", exc_info=True)
        raise RuntimeError(f"Unexpected error initializing MSF client: {e}") from e

def get_msf_client() -> MsfRpcClient:
    if _msf_client_instance is None:
        logger.error("Metasploit client has not been initialized. Check MSF server connection.")
        raise ConnectionError("Metasploit client has not been initialized.")
    logger.debug("Retrieved MSF client instance successfully.")
    return _msf_client_instance

async def check_msf_connection() -> Dict[str, Any]:
    try:
        client = get_msf_client()
        logger.debug(f"Testing MSF connection with {RPC_CALL_TIMEOUT}s timeout...")
        version_info = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.core.version),
            timeout=RPC_CALL_TIMEOUT
        )
        msf_version = version_info.get('version', 'N/A') if isinstance(version_info, dict) else 'N/A'
        return {
            "status": "connected",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "version": msf_version,
            "message": "Connection to Metasploit RPC is healthy"
        }
    except asyncio.TimeoutError:
        return {"status": "timeout", "server": f"{MSF_SERVER}:{MSF_PORT_STR}", "ssl": MSF_SSL_STR, "timeout_seconds": RPC_CALL_TIMEOUT, "message": f"Metasploit server not responding within {RPC_CALL_TIMEOUT}s timeout"}
    except ConnectionError as e:
        return {"status": "not_initialized", "server": f"{MSF_SERVER}:{MSF_PORT_STR}", "ssl": MSF_SSL_STR, "message": f"Metasploit client not initialized: {e}"}
    except MsfRpcError as e:
        return {"status": "rpc_error", "server": f"{MSF_SERVER}:{MSF_PORT_STR}", "ssl": MSF_SSL_STR, "message": f"Metasploit RPC error: {e}"}
    except Exception as e:
        return {"status": "error", "server": f"{MSF_SERVER}:{MSF_PORT_STR}", "ssl": MSF_SSL_STR, "message": f"Unexpected error: {e}"}

# Global persistent console
_persistent_console: Optional[MsfConsole] = None
_persistent_console_lock = asyncio.Lock()

async def get_persistent_console() -> MsfConsole:
    global _persistent_console
    async with _persistent_console_lock:
        if _persistent_console is None:
            client = get_msf_client()
            logger.info("Creating PERSISTENT MSF console for session management...")
            try:
                console_object = await asyncio.to_thread(lambda: client.consoles.console())
                if isinstance(console_object, MsfConsole) and hasattr(console_object, 'cid'):
                    console_id_val = getattr(console_object, 'cid')
                    console_id_str = str(console_id_val) if console_id_val is not None else None
                    if not console_id_str:
                        raise ValueError("Console object created, but .cid attribute is empty or None.")
                    logger.info(f"PERSISTENT MSF console created (ID: {console_id_str}) - will NOT be destroyed")
                    await asyncio.sleep(0.2)
                    initial_read = await asyncio.to_thread(lambda: console_object.read())
                    logger.debug(f"Initial console read (clearing buffer): {initial_read}")
                    _persistent_console = console_object
                else:
                    logger.error(f"client.consoles.console() did not return expected MsfConsole object with .cid. Got type: {type(console_object)}")
                    raise MsfRpcError(f"Unexpected result from console creation: {console_object}")
            except MsfRpcError as e:
                logger.error(f"MsfRpcError during persistent console creation: {e}")
                raise MsfRpcError(f"Error creating persistent MSF console: {e}") from e
            except Exception as e:
                logger.exception("Unexpected error during persistent console creation")
                raise RuntimeError(f"Unexpected error creating persistent console: {e}") from e
        return _persistent_console
