# -*- coding: utf-8 -*-
"""Configuration constants, environment variables, and regex patterns."""
import logging
import os
import pathlib
import re
from typing import Dict

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("metasploit_mcp_server")
logging.getLogger('mcp.server.lowlevel.server').setLevel(logging.WARNING)
session_shell_type: Dict[str, str] = {}

# Metasploit Connection Config (from environment variables)
MSF_PASSWORD = "123456"
MSF_SERVER = os.getenv('MSF_SERVER', '127.0.0.1')
MSF_PORT_STR = os.getenv('MSF_PORT', '55553')
MSF_SSL_STR = os.getenv('MSF_SSL', 'false')
PAYLOAD_SAVE_DIR = os.environ.get('PAYLOAD_SAVE_DIR', str(pathlib.Path.home() / "payloads"))

# Timeouts and Polling Intervals (in seconds)
DEFAULT_CONSOLE_READ_TIMEOUT = 15
LONG_CONSOLE_READ_TIMEOUT = 60
SESSION_COMMAND_TIMEOUT = 60
SESSION_READ_INACTIVITY_TIMEOUT = 10
EXPLOIT_SESSION_POLL_TIMEOUT = 60
EXPLOIT_SESSION_POLL_INTERVAL = 2
RPC_CALL_TIMEOUT = 30
PAYLOAD_GENERATION_TIMEOUT = 120
EXPLOIT_EXECUTION_TIMEOUT = 300
SHELL_COMMAND_DEFAULT_TIMEOUT = 180
ATTACH_SESSION_POLL_INTERVAL = 0.5
BUFFER_CLEAR_DELAY = 0.5

# Regular Expressions for Prompt Detection
MSF_PROMPT_RE = re.compile(rb'\x01\x02msf\d+\x01\x02 \x01\x02> \x01\x02')
SHELL_PROMPT_RE = re.compile(r'([#$>]|%)\s*$')
