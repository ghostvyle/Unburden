"""
Parser de instrucciones secuenciales para Unburden
Detecta y separa instrucciones numeradas para ejecución independiente
"""
import re
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class SequentialInstruction:
    """Representa una instrucción individual en una secuencia"""

    def __init__(self, number: int, content: str, original_text: str):
        self.number = number
        self.content = content.strip()
        self.original_text = original_text
        self.result: Optional[str] = None
        self.executed: bool = False
        self.error: Optional[str] = None

    def __repr__(self):
        return f"Instruction({self.number}: {self.content[:50]}...)"


class SequentialParser:
    """
    Parser para detectar y procesar instrucciones numeradas secuenciales

    Soporta formatos:
    - "1- <instrucción>"
    - "1. <instrucción>"
    - "1) <instrucción>"
    """

    # Patrones para detectar instrucciones numeradas
    PATTERNS = [
        r'^(\d+)\s*-\s*(.+)$',      # "1- instrucción"
        r'^(\d+)\.\s*(.+)$',        # "1. instrucción"
        r'^(\d+)\)\s*(.+)$',        # "1) instrucción"
    ]

    @staticmethod
    def detect_sequential_instructions(message: str) -> bool:
        """
        Detecta si el mensaje contiene instrucciones secuenciales numeradas

        Args:
            message: Mensaje del usuario

        Returns:
            True si detecta al menos 2 instrucciones numeradas consecutivas
        """
        lines = message.strip().split('\n')
        numbered_lines = 0

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Intentar cada patrón
            for pattern in SequentialParser.PATTERNS:
                if re.match(pattern, line, re.MULTILINE):
                    numbered_lines += 1
                    break

        # Considerar secuencial si hay al menos 2 instrucciones numeradas
        return numbered_lines >= 2

    @staticmethod
    def parse_instructions(message: str) -> List[SequentialInstruction]:
        """
        Parsea un mensaje en instrucciones secuenciales individuales

        Args:
            message: Mensaje del usuario con instrucciones numeradas

        Returns:
            Lista de SequentialInstruction ordenadas por número
        """
        lines = message.strip().split('\n')
        instructions = []
        current_instruction = None
        current_lines = []

        for line in lines:
            stripped = line.strip()

            # Intentar detectar nueva instrucción numerada
            matched = False
            for pattern in SequentialParser.PATTERNS:
                match = re.match(pattern, stripped, re.MULTILINE)
                if match:
                    # Guardar instrucción anterior si existe
                    if current_instruction is not None:
                        content = '\n'.join(current_lines)
                        instructions.append(
                            SequentialInstruction(
                                current_instruction,
                                content,
                                f"{current_instruction}- {content}"
                            )
                        )

                    # Nueva instrucción
                    current_instruction = int(match.group(1))
                    current_lines = [match.group(2)]
                    matched = True
                    break

            # Si no es nueva instrucción, añadir a la actual (continuación multilínea)
            if not matched and current_instruction is not None and stripped:
                current_lines.append(stripped)

        # Guardar última instrucción
        if current_instruction is not None:
            content = '\n'.join(current_lines)
            instructions.append(
                SequentialInstruction(
                    current_instruction,
                    content,
                    f"{current_instruction}- {content}"
                )
            )

        # Ordenar por número
        instructions.sort(key=lambda x: x.number)

        logger.info(f"Parsed {len(instructions)} sequential instructions")
        for inst in instructions:
            logger.debug(f"  Instruction {inst.number}: {inst.content[:100]}")

        return instructions

    @staticmethod
    def format_instruction_context(instruction: SequentialInstruction, total: int) -> str:
        """
        Formatea el contexto de una instrucción individual para el LLM

        Args:
            instruction: Instrucción a formatear
            total: Número total de instrucciones

        Returns:
            Contexto formateado para el LLM
        """
        context = f"""**SEQUENTIAL INSTRUCTION MODE ACTIVE**

You are executing instruction {instruction.number} of {total}.

**CRITICAL: CONTEXT ISOLATION**
- This is an INDEPENDENT instruction
- Do NOT mix parameters, IPs, ports, or data from other instructions
- Use ONLY the information specified in THIS instruction
- Previous instructions are completed and isolated

**CURRENT INSTRUCTION ({instruction.number}/{total}):**
{instruction.content}

**EXECUTION RULES:**
- Execute ONLY what is specified in this instruction
- Do NOT assume parameters from previous instructions
- If information is missing, use DEFAULTS (LHOST=192.168.56.1, LPORT=4444)
- Do NOT ask for clarification - execute with available data
- Report results clearly for this specific instruction

Execute NOW."""

        return context

    @staticmethod
    def format_results_summary(instructions: List[SequentialInstruction]) -> str:
        """
        Genera un resumen de todas las instrucciones ejecutadas

        Args:
            instructions: Lista de instrucciones ejecutadas

        Returns:
            Resumen formateado
        """
        summary_lines = ["**SEQUENTIAL EXECUTION SUMMARY**\n"]

        for inst in instructions:
            status = "✓ COMPLETED" if inst.executed and not inst.error else "✗ FAILED"
            summary_lines.append(f"\n**Instruction {inst.number}:** {status}")
            summary_lines.append(f"Task: {inst.content[:100]}...")

            if inst.error:
                summary_lines.append(f"Error: {inst.error}")
            elif inst.result:
                # Truncar resultado si es muy largo
                result = inst.result[:500]
                if len(inst.result) > 500:
                    result += "... (truncated)"
                summary_lines.append(f"Result: {result}")

        return '\n'.join(summary_lines)


def is_sequential_request(message: str) -> bool:
    """
    Función helper para detectar si un mensaje es una petición secuencial

    Args:
        message: Mensaje del usuario

    Returns:
        True si el mensaje contiene instrucciones secuenciales
    """
    return SequentialParser.detect_sequential_instructions(message)


def parse_sequential_request(message: str) -> List[SequentialInstruction]:
    """
    Función helper para parsear instrucciones secuenciales

    Args:
        message: Mensaje del usuario

    Returns:
        Lista de instrucciones parseadas
    """
    return SequentialParser.parse_instructions(message)
