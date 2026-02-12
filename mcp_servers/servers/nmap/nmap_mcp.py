#!/usr/bin/env python3
"""
MCP Server: Nmap
================
Expone capacidades de Nmap a clientes MCP con herramientas seguras y flexibles.

- Transportes: stdio (por defecto) o HTTP/SSE.
- Presets: top-ports, full TCP/UDP, service+OS detection, vuln NSE, script runner.
- Modo libre: run_nmap(raw_args) con allowlist de flags.
- Parser NL: nl_scan(prompt) convierte lenguaje natural en comando nmap.
- Salidas opcionales: normal (-oN), greppable (-oG), XML (-oX) guardadas en ./runs/<timestamp>/.

Seguridad:
- Validación de objetivos (IP/CIDR/hostname razonable).
- Allowlist de flags y valores; bloqueo de metacaracteres de shell; sin shell=True.
- Rutas de salida confinadas bajo ./runs.

Uso:
  $ python nmap_mcp_server.py --transport stdio
  $ python nmap_mcp_server.py --transport http --host 0.0.0.0 --port 9876
"""

import argparse
import asyncio
import os
import re
import shlex
import sys
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional, Dict

from mcp.server.fastmcp import FastMCP

# Suprimir logs verbosos de la librería MCP
logging.getLogger('mcp.server.lowlevel.server').setLevel(logging.WARNING)

# Opcional HTTP/SSE
try:
    from mcp.server.sse import SseServerTransport
    from fastapi import FastAPI
    import uvicorn
    HAVE_HTTP = True
except Exception:
    HAVE_HTTP = False

# -------------------------
# Utils y validaciones
# -------------------------

RUNS_DIR = Path(__file__).parent.joinpath("runs")
RUNS_DIR.mkdir(exist_ok=True, parents=True)

# Regex simples para validar targets
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
CIDR_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\/([0-9]|[12][0-9]|3[0-2])$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$")

SHELL_META = re.compile(r"[;&|><`$(){}\\]")

# Allowlist conservadora de flags nmap (amplía cuando lo necesites)
ALLOWED_FLAGS = {
    # Selección de puertos/protocolos
    "-p": "value",         # Especificar rango de puertos
    "-p-": "bool",         # Escanear todos los puertos
    "--top-ports": "value",# Escanear N puertos más comunes
    "-6": "bool",          # Escaneo IPv6
    "-sS": "bool",         # TCP SYN scan
    "-sT": "bool",         # TCP connect scan
    "-sU": "bool",         # UDP scan
    "-sV": "bool",         # Detección de versiones
    "-sC": "bool",         # Scripts por defecto
    "-sA": "bool",         # ACK scan
    "-sW": "bool",         # Window scan
    "-sM": "bool",         # Maimon scan
    "-O": "bool",          # Detección de SO
    "-Pn": "bool",         # No hacer ping
    "-n": "bool",          # No resolver DNS
    "-R": "bool",          # Forzar resolución DNS
    
    # Timing/performance
    "-T0": "bool", "-T1": "bool", "-T2": "bool",
    "-T3": "bool", "-T4": "bool", "-T5": "bool",
    "--max-retries": "value",
    "--host-timeout": "value",
    "--min-rate": "value",
    "--max-rate": "value",
    
    # NSE (Nmap Scripting Engine)
    "--script": "value",
    "--script-args": "value",
    "--script-timeout": "value", # Límite de tiempo para scripts
    
    # Traceroute y extras
    "--traceroute": "bool",
    "-vv": "bool",
    "-d": "bool",
    "-dd": "bool",        # Depuración extra
    "--reason": "bool",
    "--open": "bool",     # Mostrar solo puertos abiertos
    
    # Output (se reescribe a rutas confinadas)
    "-oN": "value",
    "-oG": "value",
    "-oX": "value",
    "-oA": "value",       # Salida en los tres formatos
    
    # Otros útiles
    "-A": "bool",         # Escaneo agresivo
    "--defeat-rst-ratelimit": "bool", # Evitar limitación de RST
    "--max-scan-delay": "value",      # Retraso máximo entre probes
}


def now_stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")

def ensure_nmap_available() -> None:
    from shutil import which
    if which("nmap") is None:
        raise RuntimeError("nmap no está en PATH. Instálalo para usar este servidor MCP.")

def is_valid_target(t: str) -> bool:
    t = t.strip()
    if IPV4_RE.match(t) or CIDR_RE.match(t) or HOST_RE.match(t):
        return True
    # Acepta 'localhost' y host simples sin TLD si son razonables
    if t == "localhost" or re.match(r"^[a-zA-Z0-9\-_.]{1,253}$", t):
        return True
    return False

def validate_targets(targets: List[str]) -> List[str]:
    cleaned = []
    for t in targets:
        t = t.strip()
        if not t or SHELL_META.search(t):
            raise ValueError(f"Target no permitido: {t!r}")
        if not is_valid_target(t):
            raise ValueError(f"Target inválido: {t!r}")
        cleaned.append(t)
    if not cleaned:
        raise ValueError("Debes indicar al menos un target.")
    return cleaned

def sanitize_port_list(s: str) -> str:
    if not s:
        raise ValueError("Lista de puertos vacía.")
    if not re.match(r"^[0-9,\-]+$", s):
        raise ValueError("Lista de puertos inválida. Usa números, comas y guiones (ej: 1-1024,80,443).")
    return s

def confine_output_path(base_dir: Path, filename: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)
    p = base_dir.joinpath(safe)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

def split_args_safe(raw: str) -> List[str]:
    if SHELL_META.search(raw):
        raise ValueError("Argumentos contienen metacaracteres de shell no permitidos.")
    return shlex.split(raw)

def rewrite_output_flags(args: List[str], stamp_dir: Path) -> List[str]:
    """
    Reescribe -oN/-oG/-oX a rutas confinadas dentro de stamp_dir.
    """
    out = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-oN", "-oG", "-oX"):
            if i+1 >= len(args):
                raise ValueError(f"Flag {a} requiere un valor.")
            target_name = Path(args[i+1]).name
            out.append(a)
            out.append(str(confine_output_path(stamp_dir, target_name)))
            i += 2
        else:
            out.append(a)
            i += 1
    return out

def filter_allowlist(args: List[str]) -> List[str]:
    """
    Deja pasar solo flags permitidos; conserva targets y valores asociados.
    """
    filtered: List[str] = []
    i = 0
    while i < len(args):
        tok = args[i]
        if tok.startswith("-"):
            if tok not in ALLOWED_FLAGS:
                raise ValueError(f"Flag no permitido: {tok}")
            t = ALLOWED_FLAGS[tok]
            filtered.append(tok)
            if t == "value":
                if i+1 >= len(args):
                    raise ValueError(f"Flag {tok} requiere un valor.")
                val = args[i+1]
                if SHELL_META.search(val):
                    raise ValueError(f"Valor peligroso en {tok}.")
                filtered.append(val)
                i += 2
            else:
                i += 1
        else:
            # Puede ser un target. Validaremos al final cuando juntemos todo.
            filtered.append(tok)
            i += 1
    return filtered

async def run_proc(cmd: List[str], timeout: int = 900) -> Tuple[int, str, str]:
    """
    Ejecuta proceso y devuelve (rc, stdout, stderr).
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise TimeoutError(f"Comando excedió {timeout}s.")
    return proc.returncode, out.decode("utf-8", "ignore"), err.decode("utf-8", "ignore")

def make_stamp_dir(prefix: str = "scan") -> Path:
    d = RUNS_DIR.joinpath(f"{prefix}_{now_stamp()}")
    d.mkdir(parents=True, exist_ok=True)
    return d

def build_nmap_cmd(args: List[str], targets: List[str]) -> List[str]:
    return ["nmap", *args, *targets]

# -------------------------
# MCP Server
# -------------------------

mcp = FastMCP("Nmap MCP Server")

@mcp.tool()
async def nl_scan(prompt: str, save_outputs: bool = True, timing: str = "T4") -> str:
    """
    (Natural Language) Interpreta una petición en lenguaje natural y ejecuta el escaneo apropiado.

    Ejemplos:
      - "dime los puertos abiertos de 10.10.10.10"
      - "escaneo completo tcp a 192.168.1.0/24 sin ping"
      - "usa scripts de vulnerabilidades contra example.com"
      - "udp top 100 en 10.0.0.5"

    Args:
      prompt: Instrucción en lenguaje natural.
      save_outputs: Si True, guarda -oN/-oX en ./runs/<timestamp>/
      timing: Perfil de timing nmap (T0..T5). Por defecto T4.

    Returns:
      Salida estándar de nmap + rutas de salida si aplica.
    """
    ensure_nmap_available()

    p = prompt.lower().strip()

    # Heurísticas simples -> flags razonables
    args: List[str] = []
    targets: List[str] = []

    # Timing
    if timing.upper() in ("T0","T1","T2","T3","T4","T5"):
        args.append(f"-{timing.upper()}")

    # Ping off
    if "sin ping" in p or "no ping" in p or "skip ping" in p:
        args.append("-Pn")

    # Verbosidad si lo piden
    if "detalles" in p or "verbose" in p:
        args.append("-vv")

    # UDP?
    is_udp = "udp" in p
    if is_udp:
        args.append("-sU")

    # Service/OS detection
    if "servicio" in p or "version" in p or "versión" in p or "detectar servicios" in p or "service" in p:
        args.append("-sV")
    if "so" in p or "sistema operativo" in p or "os detection" in p:
        args.append("-O")

    # Top ports
    m = re.search(r"top\s*(\d+)", p) or re.search(r"top\s*ports?\s*(\d+)", p) or re.search(r"los\s*(\d+)\s*puertos", p)
    if m:
        args.extend(["--top-ports", m.group(1)])

    # Rango de puertos “-p”
    m = re.search(r"puertos?\s+([0-9,\-]+)", p)
    if m:
        ports = sanitize_port_list(m.group(1))
        args.extend(["-p", ports])

    # “vulnerabilidad”
    if "vulnerab" in p:
        args.extend(["--script", "vuln"])

    # Objetivos: intenta extraer IP/CIDR/host simples
    for token in re.findall(r"[a-zA-Z0-9\.\-_/]+", prompt):
        tok = token.strip().lower()
        if is_valid_target(tok):
            targets.append(tok)

    targets = validate_targets(list(dict.fromkeys(targets)))  # únicos y validados
    if not targets:
        raise ValueError("No pude identificar el/los objetivo(s) en tu petición. Incluye una IP/host/CIDR.")

    stamp_dir = make_stamp_dir("nl") if save_outputs else None
    if save_outputs and stamp_dir:
        args = args + ["-oN", str(confine_output_path(stamp_dir, "output.nmap")),
                       "-oX", str(confine_output_path(stamp_dir, "output.xml"))]

    # Validación final allowlist
    args = filter_allowlist(args)

    cmd = build_nmap_cmd(args, targets)
    rc, out, err = await run_proc(cmd)
    if rc != 0 and not out:
        raise RuntimeError(f"nmap retornó código {rc}: {err.strip()}")

    footer = ""
    if save_outputs and stamp_dir:
        footer = f"\n[Guardado en] {stamp_dir}"
    return out + footer + (f"\n[stderr]\n{err}" if err.strip() else "")

@mcp.tool()
async def top_ports(targets: List[str], count: int = 1000, tcp: bool = True,
                    save_outputs: bool = True, timing: str = "T4") -> str:
    """
    Escaneo rápido de top-N puertos.

    Args:
      targets: Lista de objetivos (IP/host/CIDR).
      count: Número de puertos top (por defecto 1000).
      tcp: Si True TCP (rápido con -sS si privilegios, o nmap decide). UDP si False.
      save_outputs: Guarda salidas en ./runs
      timing: T0..T5

    Returns:
      Salida estándar de nmap y rutas de salida si aplica.
    """
    ensure_nmap_available()
    targets = validate_targets(targets)
    args = [f"-{timing.upper()}", "--top-ports", str(count)]
    if not tcp:
        args.append("-sU")

    stamp_dir = make_stamp_dir("top") if save_outputs else None
    if save_outputs and stamp_dir:
        args += ["-oN", str(confine_output_path(stamp_dir, "output.nmap")),
                 "-oX", str(confine_output_path(stamp_dir, "output.xml"))]

    args = filter_allowlist(args)
    cmd = build_nmap_cmd(args, targets)
    rc, out, err = await run_proc(cmd)
    if rc != 0 and not out:
        raise RuntimeError(f"nmap error {rc}: {err.strip()}")

    return out + (f"\n[Guardado en] {stamp_dir}" if stamp_dir else "") + (f"\n[stderr]\n{err}" if err.strip() else "")

@mcp.tool()
async def full_tcp(targets: List[str], no_ping: bool = True, timing: str = "T4",
                   save_outputs: bool = True, service_detection: bool = True) -> str:
    """
    Escaneo TCP “completo” (puertos por defecto de nmap + timing + opcional detección de servicios).
    Para TODOS los puertos TCP usa: run_nmap con "-p 1-65535 -sS -sV" (más flexible).

    Args:
      targets: objetivos
      no_ping: usa -Pn
      timing: T0..T5
      save_outputs: guarda salidas
      service_detection: añade -sV

    """
    ensure_nmap_available()
    targets = validate_targets(targets)
    args = [f"-{timing.upper()}"]
    if no_ping:
        args.append("-Pn")
    if service_detection:
        args.append("-sV")

    stamp_dir = make_stamp_dir("fulltcp") if save_outputs else None
    if save_outputs and stamp_dir:
        args += ["-oN", str(confine_output_path(stamp_dir, "output.nmap")),
                 "-oX", str(confine_output_path(stamp_dir, "output.xml"))]

    args = filter_allowlist(args)
    cmd = build_nmap_cmd(args, targets)
    rc, out, err = await run_proc(cmd, timeout=1800)
    if rc != 0 and not out:
        raise RuntimeError(f"nmap error {rc}: {err.strip()}")

    return out + (f"\n[Guardado en] {stamp_dir}" if stamp_dir else "") + (f"\n[stderr]\n{err}" if err.strip() else "")

@mcp.tool()
async def service_os_detection(targets: List[str], ports: Optional[str] = None,
                               timing: str = "T4", no_ping: bool = True,
                               save_outputs: bool = True) -> str:
    """
    Detección de servicios (-sV) y SO (-O). Opcional limitar puertos con -p.

    Args:
      targets: objetivos
      ports: lista o rango (ej: "80,443,8000-8100")
    """
    ensure_nmap_available()
    targets = validate_targets(targets)
    args = [f"-{timing.upper()}", "-sV", "-O"]
    if no_ping:
        args.append("-Pn")
    if ports:
        args += ["-p", sanitize_port_list(ports)]

    stamp_dir = make_stamp_dir("svc_os") if save_outputs else None
    if save_outputs and stamp_dir:
        args += ["-oN", str(confine_output_path(stamp_dir, "output.nmap")),
                 "-oX", str(confine_output_path(stamp_dir, "output.xml"))]

    args = filter_allowlist(args)
    cmd = build_nmap_cmd(args, targets)
    rc, out, err = await run_proc(cmd, timeout=1800)
    if rc != 0 and not out:
        raise RuntimeError(f"nmap error {rc}: {err.strip()}")

    return out + (f"\n[Guardado en] {stamp_dir}" if stamp_dir else "") + (f"\n[stderr]\n{err}" if err.strip() else "")

@mcp.tool()
async def vuln_scan(targets: List[str], ports: Optional[str] = None, timing: str = "T4",
                    no_ping: bool = True, save_outputs: bool = True) -> str:
    """
    Escaneo con detección de versiones y scripts por defecto (nmap -sCV).
    Ejecuta -sC (scripts por defecto) y -sV (detección de versiones) contra los puertos especificados.

    Args:
      targets: objetivos (IP/host/CIDR)
      ports: puertos específicos a escanear (ej: "80,443,8080"). Si no se especifica, nmap usa puertos por defecto.
      timing: perfil de timing T0..T5 (por defecto T4)
      no_ping: usa -Pn para no hacer ping previo
      save_outputs: guarda salida en formato normal (-oN) y XML (-oX)
    """
    ensure_nmap_available()
    targets = validate_targets(targets)

    args = [f"-{timing.upper()}", "-sC", "-sV"]
    if no_ping:
        args.append("-Pn")
    if ports:
        args += ["-p", sanitize_port_list(ports)]

    stamp_dir = make_stamp_dir("targeted") if save_outputs else None
    if save_outputs and stamp_dir:
        args += ["-oN", str(confine_output_path(stamp_dir, "output.nmap")),
                 "-oX", str(confine_output_path(stamp_dir, "output.xml"))]

    args = filter_allowlist(args)
    cmd = build_nmap_cmd(args, targets)
    rc, out, err = await run_proc(cmd, timeout=3600)
    if rc != 0 and not out:
        raise RuntimeError(f"nmap error {rc}: {err.strip()}")

    return out + (f"\n[Guardado en] {stamp_dir}" if stamp_dir else "") + (f"\n[stderr]\n{err}" if err.strip() else "")

@mcp.tool()
async def run_script(targets: List[str], script: str, script_args: Optional[str] = None,
                     ports: Optional[str] = None, timing: str = "T4",
                     save_outputs: bool = True) -> str:
    """
    Ejecuta un script o patrón de scripts NSE concreto.

    Args:
      targets: objetivos
      script: ej. "http-enum" o "http-*"
      script_args: ej. "userdb=users.txt,passdb=pass.txt"
      ports: "-p" si quieres limitar el escaneo
    """
    ensure_nmap_available()
    targets = validate_targets(targets)
    if SHELL_META.search(script):
        raise ValueError("Nombre de script sospechoso.")
    if script_args and SHELL_META.search(script_args):
        raise ValueError("script_args contiene metacaracteres no permitidos.")

    args = [f"-{timing.upper()}", "--script", script]
    if script_args:
        args += ["--script-args", script_args]
    if ports:
        args += ["-p", sanitize_port_list(ports)]

    stamp_dir = make_stamp_dir("script") if save_outputs else None
    if save_outputs and stamp_dir:
        args += ["-oN", str(confine_output_path(stamp_dir, "output.nmap")),
                 "-oX", str(confine_output_path(stamp_dir, "output.xml"))]

    args = filter_allowlist(args)
    cmd = build_nmap_cmd(args, targets)
    rc, out, err = await run_proc(cmd, timeout=3600)
    if rc != 0 and not out:
        raise RuntimeError(f"nmap error {rc}: {err.strip()}")

    return out + (f"\n[Guardado en] {stamp_dir}" if stamp_dir else "") + (f"\n[stderr]\n{err}" if err.strip() else "")

@mcp.tool()
async def udp_scan(targets: List[str], top: Optional[int] = 200, no_ping: bool = True,
                   save_outputs: bool = True, timing: str = "T4") -> str:
    """
    Escaneo UDP básico (por defecto top 200). Para exhaustivo usa -p 1-65535 con run_nmap.

    Args:
      targets: objetivos
      top: --top-ports N UDP
    """
    ensure_nmap_available()
    targets = validate_targets(targets)
    args = [f"-{timing.upper()}", "-sU"]
    if no_ping:
        args.append("-Pn")
    if top:
        args += ["--top-ports", str(top)]

    stamp_dir = make_stamp_dir("udp") if save_outputs else None
    if save_outputs and stamp_dir:
        args += ["-oN", str(confine_output_path(stamp_dir, "output.nmap")),
                 "-oX", str(confine_output_path(stamp_dir, "output.xml"))]

    args = filter_allowlist(args)
    cmd = build_nmap_cmd(args, targets)
    rc, out, err = await run_proc(cmd, timeout=3600)
    if rc != 0 and not out:
        raise RuntimeError(f"nmap error {rc}: {err.strip()}")

    return out + (f"\n[Guardado en] {stamp_dir}" if stamp_dir else "") + (f"\n[stderr]\n{err}" if err.strip() else "")

@mcp.tool()
async def run_nmap(raw_args: str, targets: Optional[List[str]] = None,
                   save_outputs: bool = True) -> str:
    """
    Modo libre: pasa argumentos de nmap directamente (validados con allowlist).
    Úsalo para cubrir cualquier modalidad de nmap.

    Ejemplos:
      raw_args="-sS -sV -p 1-65535 -T4 -Pn --reason"
      raw_args="--script http-enum -p 80,443 --script-args http.useragent=Mozilla"
    """
    ensure_nmap_available()
    args = split_args_safe(raw_args)
    args = filter_allowlist(args)

    # Extrae targets si los incluyeron sueltos en raw_args
    trailing_targets = [t for t in args if not t.startswith("-")]
    cleaned_flags = [t for t in args if t.startswith("-") or t in ("-oN","-oG","-oX")]

    t_final = targets or trailing_targets
    t_final = validate_targets(list(dict.fromkeys(t_final)))

    if not t_final:
        raise ValueError("Debes indicar targets (en 'targets' o como tokens al final de raw_args).")

    stamp_dir = make_stamp_dir("free") if save_outputs else None
    if stamp_dir:
        cleaned_flags = rewrite_output_flags(cleaned_flags, stamp_dir)
        # Si no había flags de salida, añade por defecto
        if "-oN" not in cleaned_flags and "-oG" not in cleaned_flags and "-oX" not in cleaned_flags:
            cleaned_flags += ["-oN", str(confine_output_path(stamp_dir, "output.nmap")),
                              "-oX", str(confine_output_path(stamp_dir, "output.xml"))]

    cmd = build_nmap_cmd(cleaned_flags, t_final)
    rc, out, err = await run_proc(cmd, timeout=7200)
    if rc != 0 and not out:
        raise RuntimeError(f"nmap error {rc}: {err.strip()}")

    return out + (f"\n[Guardado en] {stamp_dir}" if stamp_dir else "") + (f"\n[stderr]\n{err}" if err.strip() else "")

# ---------------------------------
# Arranque (stdio o http/sse)
# ---------------------------------

def main():
    parser = argparse.ArgumentParser(description="Nmap MCP Server")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9876)
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        if not HAVE_HTTP:
            print("Transporte HTTP no disponible (instala fastapi/uvicorn).", file=sys.stderr)
            sys.exit(2)
        app = FastAPI()
        transport = SseServerTransport(app, path="/sse")
        mcp.run(transport=transport, app=app)
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")

if __name__ == "__main__":
    main()
