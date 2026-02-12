/**
 * Chat Markdown Parser - Función anti-"pantalla negra"
 *
 * Parsea el contenido de archivos .md de histórico de chat y lo convierte
 * en un array de objetos para renderizar en la UI.
 *
 * CARACTERÍSTICAS:
 * - Extremadamente robusto a errores de formato
 * - No crashea nunca, siempre devuelve un array válido
 * - Maneja bloques malformados sin romper el resto del parsing
 * - Logs detallados de errores para debugging
 */

export interface ChatMessage {
  id?: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp?: string;
  type: 'text' | 'tool_call' | 'error' | 'unknown';
}

/**
 * Parsea el contenido de un archivo .md de histórico y lo convierte
 * en un array de objetos para renderizar en la UI.
 * Extremadamente robusto a errores de formato.
 *
 * @param mdContent El contenido raw del archivo .md
 * @returns Array de mensajes para la UI
 */
export function parseChatMarkdown(mdContent: string): ChatMessage[] {
  const messages: ChatMessage[] = [];

  // Separar por bloques usando el separador real entre mensajes
  // El separador completo es: \n---\n seguido de comentario HTML <!--
  // Esto evita dividir cuando --- aparece dentro del contenido del mensaje
  const messageSplitRegex = /\n---\n(?=<!--)/g;

  const rawBlocks = mdContent.split(messageSplitRegex);

  // Filtrar bloques vacíos y la cabecera
  const blocks = rawBlocks.filter(block => {
    const trimmed = block.trim();
    // Solo aceptar bloques que contengan comentario HTML y label de rol
    // (el primer bloque es la cabecera, no tiene esto)
    return trimmed &&
           trimmed.includes('<!--') &&
           (trimmed.includes('**User:**') ||
            trimmed.includes('**Unburden:**') ||
            trimmed.includes('**System:**'));
  });

  // Regex para extraer el JSON dentro de los comentarios HTML
  const jsonRegex = /<!--\s*([\s\S]*?)\s*-->/;

  // Regex para extraer el contenido del bloque de código
  // Soporta tanto ````json como ````text
  const contentRegex = /````(json|text)\n([\s\S]*?)\n````/;

  // Regex para extraer el label del rol (**User:**, **Unburden:**, etc.)
  const roleLabelRegex = /\*\*(User|Unburden|System|Unknown):\*\*/;

  for (const block of blocks) {
    // Saltar bloques vacíos
    if (!block.trim()) continue;

    // Defaults para mensajes malformados
    let metadata: Partial<ChatMessage> = {
      role: 'system',
      type: 'unknown'
    };
    let content = '';
    let hasValidMetadata = false;

    // ===== PASO 1: Extraer metadatos JSON =====
    try {
      const jsonMatch = block.match(jsonRegex);
      if (jsonMatch && jsonMatch[1]) {
        const jsonString = jsonMatch[1].trim();
        const parsedMetadata = JSON.parse(jsonString);

        // Validar que tiene los campos mínimos necesarios
        if (parsedMetadata.role) {
          metadata = {
            id: parsedMetadata.id,
            role: parsedMetadata.role,
            timestamp: parsedMetadata.timestamp,
            type: parsedMetadata.type || 'text'
          };
          hasValidMetadata = true;
        }
      }
    } catch (e) {
      // Error parseando JSON - No crashear
      console.error(
        `[parseChatMarkdown] Error parseando metadatos JSON:`,
        e,
        '\nBloque problemático:',
        block.substring(0, 200) + '...'
      );

      // Intentar inferir el rol desde el label visible
      const roleLabelMatch = block.match(roleLabelRegex);
      if (roleLabelMatch) {
        const roleMap: Record<string, ChatMessage['role']> = {
          'User': 'user',
          'Unburden': 'assistant',
          'System': 'system',
          'Unknown': 'system'
        };
        metadata.role = roleMap[roleLabelMatch[1]] || 'system';
        metadata.type = 'error';
      }
    }

    // ===== PASO 2: Extraer contenido del bloque de código =====
    try {
      const contentMatch = block.match(contentRegex);

      if (contentMatch && contentMatch[2]) {
        // Contenido encontrado en bloque ````
        content = contentMatch[2].trim();

        // Si el tipo en los metadatos es 'tool_call', validar que sea JSON válido
        if (metadata.type === 'tool_call') {
          try {
            JSON.parse(content); // Validar JSON
          } catch (jsonErr) {
            console.warn(
              `[parseChatMarkdown] Bloque marcado como tool_call pero contenido no es JSON válido`
            );
            // Mantener el contenido aunque no sea JSON válido
          }
        }
      } else {
        // ===== FALLBACK: No hay bloque de código =====
        // Intentar extraer texto después del comentario HTML
        let textContent = block.replace(jsonRegex, '').trim();

        // Eliminar el label del rol si existe (**User:**, **Unburden:**, etc.)
        textContent = textContent.replace(roleLabelRegex, '').trim();

        // Eliminar posibles backticks sueltos
        textContent = textContent.replace(/^`+|`+$/g, '').trim();

        content = textContent;

        if (!content) {
          console.warn(
            `[parseChatMarkdown] Bloque no contiene contenido extraíble. Saltando.`
          );
          continue; // Saltar este bloque
        }
      }
    } catch (e) {
      console.error(
        `[parseChatMarkdown] Error parseando contenido:`,
        e,
        '\nBloque problemático:',
        block.substring(0, 200) + '...'
      );

      // Último recurso: mostrar un mensaje de error
      content = '[Error al cargar contenido del bloque]';
      metadata.type = 'error';
    }

    // ===== PASO 3: Añadir al array de mensajes =====
    // Solo añadir si tiene contenido o es una tool_call (puede tener contenido vacío)
    if (content || metadata.type === 'tool_call') {
      messages.push({
        id: metadata.id,
        role: metadata.role || 'system',
        content: content,
        timestamp: metadata.timestamp,
        type: metadata.type || 'text'
      } as ChatMessage);
    }
  }

  // Log de resultado final
  console.log(
    `[parseChatMarkdown] Parseados ${messages.length} mensajes de ${blocks.length - 1} bloques`
  );

  return messages;
}

/**
 * Función auxiliar para detectar si un contenido MD tiene el formato correcto.
 * Útil para validaciones antes de guardar.
 *
 * @param mdContent Contenido Markdown a validar
 * @returns true si el formato parece correcto
 */
export function validateChatMarkdownFormat(mdContent: string): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Verificar que tiene cabecera
  if (!mdContent.includes('# [Pentest]')) {
    errors.push('Falta la cabecera con formato "# [Pentest] Título"');
  }

  // Verificar que tiene al menos un separador ---
  const blocks = mdContent.split('---');
  if (blocks.length < 2) {
    errors.push('No se encontraron bloques de mensajes (separador ---)');
  }

  // Verificar que los bloques tienen comentarios HTML
  const hasHTMLComments = mdContent.includes('<!--') && mdContent.includes('-->');
  if (!hasHTMLComments) {
    errors.push('No se encontraron comentarios HTML con metadatos');
  }

  // Verificar que los bloques tienen bloques de código
  const hasCodeBlocks = mdContent.includes('````');
  if (!hasCodeBlocks) {
    errors.push('No se encontraron bloques de código (````)');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Función auxiliar para convertir mensajes de la UI al formato Markdown.
 * Útil para exportar o generar archivos .md desde la UI.
 *
 * @param messages Array de mensajes de la UI
 * @param title Título del chat
 * @param chatId ID del chat
 * @returns String con el contenido Markdown completo
 */
export function chatMessagesToMarkdown(
  messages: ChatMessage[],
  title: string,
  chatId: string
): string {
  const timestamp = new Date().toISOString();

  let md = `# [Pentest] ${title}
* **ID:** ${chatId}
* **Timestamp:** ${timestamp}

`;

  for (const msg of messages) {
    const metadata = {
      id: msg.id || crypto.randomUUID(),
      role: msg.role,
      timestamp: msg.timestamp || new Date().toISOString(),
      type: msg.type || 'text'
    };

    const roleLabel = {
      user: '**User:**',
      assistant: '**Unburden:**',
      system: '**System:**'
    }[msg.role] || '**Unknown:**';

    const codeType = msg.type === 'tool_call' ? 'json' : 'text';

    md += `---
<!--
${JSON.stringify(metadata, null, 2)}
-->
${roleLabel}
\`\`\`\`${codeType}
${msg.content}
\`\`\`\`

`;
  }

  return md;
}
