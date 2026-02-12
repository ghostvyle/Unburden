import asyncio
import re
import shlex
from typing import Any, Dict, List, Optional, Tuple, Union
from pymetasploit3.msfrpc import MsfRpcError
from .config import (
    logger, DEFAULT_CONSOLE_READ_TIMEOUT, LONG_CONSOLE_READ_TIMEOUT,
    SESSION_READ_INACTIVITY_TIMEOUT, EXPLOIT_SESSION_POLL_TIMEOUT,
    EXPLOIT_SESSION_POLL_INTERVAL, RPC_CALL_TIMEOUT
)
from .client import get_msf_client, get_persistent_console
from .console import get_msf_console, run_command_safely


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
             start_time = asyncio.get_event_loop().time()
             logger.info(f"Exploit job {job_id} (UUID: {uuid}) started. Polling for session (timeout: {EXPLOIT_SESSION_POLL_TIMEOUT}s)...")
             while (asyncio.get_event_loop().time() - start_time) < EXPLOIT_SESSION_POLL_TIMEOUT:
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
