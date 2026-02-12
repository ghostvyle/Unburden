import asyncio
import contextlib
from typing import AsyncGenerator, Optional
from pymetasploit3.msfrpc import MsfConsole, MsfRpcError
from mcp.server.session import ServerSession

# Support both relative imports (package) and absolute imports (direct execution)
try:
    from .config import (
        logger, DEFAULT_CONSOLE_READ_TIMEOUT, LONG_CONSOLE_READ_TIMEOUT,
        SESSION_READ_INACTIVITY_TIMEOUT, MSF_PROMPT_RE
    )
    from .client import get_msf_client, _msf_client_instance
except ImportError:
    from config import (
        logger, DEFAULT_CONSOLE_READ_TIMEOUT, LONG_CONSOLE_READ_TIMEOUT,
        SESSION_READ_INACTIVITY_TIMEOUT, MSF_PROMPT_RE
    )
    from client import get_msf_client, _msf_client_instance


@contextlib.asynccontextmanager
async def get_msf_console() -> AsyncGenerator[MsfConsole, None]:
    client = get_msf_client()
    console_object: Optional[MsfConsole] = None
    console_id_str: Optional[str] = None
    try:
        logger.debug("Creating temporary MSF console...")
        console_object = await asyncio.to_thread(lambda: client.consoles.console())
        if isinstance(console_object, MsfConsole) and hasattr(console_object, 'cid'):
            console_id_val = getattr(console_object, 'cid')
            console_id_str = str(console_id_val) if console_id_val is not None else None
            if not console_id_str:
                raise ValueError("Console object created, but .cid attribute is empty or None.")
            logger.info(f"MSF console created (ID: {console_id_str})")
            await asyncio.sleep(0.2)
            initial_read = await asyncio.to_thread(lambda: console_object.read())
            logger.debug(f"Initial console read (clearing buffer): {initial_read}")
            yield console_object
        else:
            logger.error(f"client.consoles.console() did not return expected MsfConsole object with .cid. Got type: {type(console_object)}")
            raise MsfRpcError(f"Unexpected result from console creation: {console_object}")
    except MsfRpcError as e:
        logger.error(f"MsfRpcError during console operation: {e}")
        raise MsfRpcError(f"Error creating/accessing MSF console: {e}") from e
    except Exception as e:
        logger.exception("Unexpected error during console creation/setup")
        raise RuntimeError(f"Unexpected error during console operation: {e}") from e
    finally:
        if console_id_str and _msf_client_instance:
            try:
                logger.info(f"Attempting to destroy Metasploit console (ID: {console_id_str})...")
                destroy_result = await asyncio.to_thread(
                    lambda cid=console_id_str: _msf_client_instance.consoles.destroy(cid)
                )
                logger.debug(f"Console destroy result: {destroy_result}")
            except Exception as e:
                logger.error(f"Error destroying MSF console {console_id_str}: {e}")
        elif console_object and not console_id_str:
             logger.warning("Console object created but no valid ID obtained, cannot explicitly destroy.")


async def run_command_safely(console: MsfConsole, cmd: str, execution_timeout: Optional[int] = None) -> str:
    if not (hasattr(console, 'write') and hasattr(console, 'read')):
        logger.error(f"Console object {type(console)} lacks required methods (write, read).")
        raise TypeError("Unsupported console object type for command execution.")
    try:
        logger.debug(f"Running console command: {cmd}")
        await asyncio.to_thread(lambda: console.write(cmd + '\n'))
        output_buffer = b""
        start_time = asyncio.get_event_loop().time()
        read_timeout = execution_timeout or (LONG_CONSOLE_READ_TIMEOUT if cmd.strip().startswith(("run", "exploit", "check")) else DEFAULT_CONSOLE_READ_TIMEOUT)
        check_interval = 0.1
        last_data_time = start_time
        while True:
            await asyncio.sleep(check_interval)
            current_time = asyncio.get_event_loop().time()
            if (current_time - start_time) > read_timeout:
                 logger.warning(f"Overall timeout ({read_timeout}s) reached for console command '{cmd}'.")
                 break
            try:
                chunk_result = await asyncio.to_thread(lambda: console.read())
                chunk_data = chunk_result.get('data', '').encode('utf-8', errors='replace')
                prompt_str = chunk_result.get('prompt', '')
                prompt_bytes = prompt_str.encode('utf-8', errors='replace') if isinstance(prompt_str, str) else prompt_str
            except Exception as read_err:
                logger.warning(f"Error reading from console during command '{cmd}': {read_err}")
                await asyncio.sleep(0.5)
                continue
            if chunk_data:
                output_buffer += chunk_data
                last_data_time = current_time
                if prompt_bytes and MSF_PROMPT_RE.search(prompt_bytes):
                     logger.debug(f"Detected MSF prompt in console.read() result for '{cmd}'. Command likely complete.")
                     break
                if MSF_PROMPT_RE.search(output_buffer):
                     logger.debug(f"Detected MSF prompt at end of buffer for '{cmd}'. Command likely complete.")
                     break
            elif (current_time - last_data_time) > SESSION_READ_INACTIVITY_TIMEOUT:
                logger.debug(f"Console inactivity timeout ({SESSION_READ_INACTIVITY_TIMEOUT}s) reached for command '{cmd}'. Assuming complete.")
                break
        final_output = output_buffer.decode('utf-8', errors='replace').strip()
        logger.debug(f"Final output for '{cmd}' (length {len(final_output)}):\n{final_output[:500]}{'...' if len(final_output) > 500 else ''}")
        return final_output
    except Exception as e:
        logger.exception(f"Error executing console command '{cmd}'")
        raise RuntimeError(f"Failed executing console command '{cmd}': {e}") from e


old__received_request = ServerSession._received_request

async def _received_request(self, *args, **kwargs):
    try:
        return await old__received_request(self, *args, **kwargs)
    except RuntimeError:
        pass

ServerSession._received_request = _received_request
