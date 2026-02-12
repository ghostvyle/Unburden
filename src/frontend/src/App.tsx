import { useState, useRef, useEffect, useCallback } from "react";
import { usePentestManager } from "./hooks/usePentestManager";
import { useChatManager } from "./hooks/useChatManager";
import MarkdownRenderer from "./components/MarkdownRenderer";
import MarkdownEditor from "./components/MarkdownEditor";
import ShellConfigModal from "./components/ShellConfigModal";
import ChatSidebar from "./components/ChatSidebar";

interface Message {
  role: string;
  content: string;
  timestamp?: Date;
}

// Detectar automáticamente la URL del servidor según el host actual
const getApiBaseUrl = () => {
  if (import.meta.env.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL;
  }
  
  // Obtener puerto desde variable de entorno, con fallback a 7777
  const port = import.meta.env.VITE_API_PORT || '7777';
  
  // Si estamos en desarrollo local, usar localhost
  if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    return `http://localhost:${port}`;
  }
  
  // Para acceso remoto, usar la misma IP/host pero con el puerto configurado
  return `http://${window.location.hostname}:${port}`;
};

const API_BASE_URL = getApiBaseUrl();

// Función para generar sessionId basado en fecha
const generateDateBasedSessionId = async (): Promise<string> => {
  try {
    const response = await fetch(`${API_BASE_URL}/generate-session-id`);
    if (response.ok) {
      const data = await response.json();
      return data.sessionId;
    }
  } catch (error) {
    console.error("Error generating session ID:", error);
  }
  // Fallback: generar ID local basado en fecha si falla la API
  const now = new Date();
  return now.getFullYear() + '-' + 
         String(now.getMonth() + 1).padStart(2, '0') + '-' +
         String(now.getDate()).padStart(2, '0') + '-' +
         String(now.getHours()).padStart(2, '0') + '-' +
         String(now.getMinutes()).padStart(2, '0') + '-' +
         String(now.getSeconds()).padStart(2, '0');
};

const App = () => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [pentestingMode, setPentestingMode] = useState(false);
  const [sessionId, setSessionId] = useState<string>("");
  const [currentChatId, setCurrentChatId] = useState<string | null>(null);
  const [showSidebar, setShowSidebar] = useState(true);
  const [editMode, setEditMode] = useState<'none' | 'report' | 'history'>('none');
  const [showReportButtons, setShowReportButtons] = useState(false);
  const [showMcpModal, setShowMcpModal] = useState(false);
  const [mcpModalMode, setMcpModalMode] = useState<'import' | 'manage'>('import');
  const [mcpJsonInput, setMcpJsonInput] = useState('');
  const [mcpServers, setMcpServers] = useState<any>(null);
  const [expandedServers, setExpandedServers] = useState<Set<string>>(new Set());
  const [showShellConfigModal, setShowShellConfigModal] = useState(false);
  const [pendingMessage, setPendingMessage] = useState<string>("");
  const reportFileInputRef = useRef<HTMLInputElement>(null);
  const historyFileInputRef = useRef<HTMLInputElement>(null);
  const mcpFileInputRef = useRef<HTMLInputElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Hook para gestión de chats múltiples
  const {
    chats,
    targets,
    currentChat,
    loadChats,
    createChat,
    loadChat,
    deleteChat,
    renameChat,
    updateTarget,
  } = useChatManager(API_BASE_URL);

  // Custom hooks para manejar estado del informe
  
  const addStatusMessage = useCallback((message: string) => {
    setMessages((prev) => [...prev, {
      role: "system",
      content: message,
      timestamp: new Date()
    }]);
  }, []);

  // Manejar selección de chat
  const handleSelectChat = useCallback(async (chatId: string) => {
    // No permitir cambio de chat si hay una query en proceso
    if (loading) {
      addStatusMessage('⚠️ Espera a que termine la consulta actual antes de cambiar de chat');
      return;
    }

    const chat = await loadChat(chatId);
    if (chat) {
      setCurrentChatId(chatId);
      // Limpiar el estado de loading por si acaso
      setLoading(false);
    }
  }, [loadChat, loading, addStatusMessage]);

  // Crear nuevo chat
  const handleNewChat = useCallback(async (title?: string, target?: string) => {
    const newChatId = await createChat(title || "Nueva conversación", target || "");
    if (newChatId) {
      await handleSelectChat(newChatId);
    }
  }, [createChat, handleSelectChat]);

  // Eliminar chat
  const handleDeleteChat = useCallback(async (chatId: string) => {
    const success = await deleteChat(chatId);
    if (success) {
      // Si era el chat actual, seleccionar otro o crear uno nuevo
      if (chatId === currentChatId) {
        if (chats.length > 1) {
          const otherChat = chats.find((c) => c.id !== chatId);
          if (otherChat) {
            await handleSelectChat(otherChat.id);
          }
        } else {
          // Crear un nuevo chat si era el único
          await handleNewChat();
        }
      }
    }
  }, [deleteChat, currentChatId, chats, handleSelectChat, handleNewChat]);

  // Renombrar chat
  const handleRenameChat = useCallback(async (chatId: string, newTitle: string) => {
    await renameChat(chatId, newTitle);
  }, [renameChat]);

  // MCP Server Management Functions
  const loadMcpServers = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/estado-mcps`);
      if (response.ok) {
        const data = await response.json();
        setMcpServers(data);
        return data;
      } else {
        throw new Error('Failed to load MCP servers');
      }
    } catch (error) {
      console.error('Error loading MCP servers:', error);
      addStatusMessage(`❌ Error loading MCP servers: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return null;
    }
  }, [addStatusMessage]);


  const deleteMcpServer = useCallback(async (serverName: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/delete-mcp/${serverName}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        addStatusMessage(`✅ MCP server '${serverName}' deleted`);
        await loadMcpServers(); // Reload server status
      } else {
        throw new Error('Failed to delete server');
      }
    } catch (error) {
      console.error('Error deleting MCP server:', error);
      addStatusMessage(`❌ Error deleting server '${serverName}': ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }, [addStatusMessage, loadMcpServers]);

  const clearAllUserMcps = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/limpiar-user-mcps`, {
        method: 'DELETE'
      });

      if (response.ok) {
        addStatusMessage(`✅ All user MCP servers cleared successfully`);
        await loadMcpServers(); // Reload server status
      } else {
        throw new Error('Failed to clear user MCP servers');
      }
    } catch (error) {
      console.error('Error clearing user MCP servers:', error);
      addStatusMessage(`❌ Error clearing user MCP servers: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }, [addStatusMessage, loadMcpServers]);

  const toggleServerExpansion = useCallback((serverName: string) => {
    setExpandedServers(prev => {
      const newSet = new Set(prev);
      if (newSet.has(serverName)) {
        newSet.delete(serverName);
      } else {
        newSet.add(serverName);
      }
      return newSet;
    });
  }, []);

  const {
    // Informe
    reportContent,
    setReportContent,
    loadReportContent,
    saveEditedReport,
    uploadReport,
    downloadReport,
    generateReport,
    updateReport,
    generateNewReport,
    
    // Histórico del chat
    historyContent,
    setHistoryContent,
    loadHistoryContent,
    saveEditedHistory,
    uploadHistory,
    downloadHistory,
    
    // General
    clearPentest,
    isProcessing
  } = usePentestManager(currentChatId || sessionId || "", addStatusMessage);

  // Inicializar modo pentesting
  const initializePentestMode = useCallback(async () => {
    try {
      // IMPORTANTE: Usar currentChatId para que el reporte se cree con el mismo ID que el chat
      // Así el reporte estará en data/reports/{chat_id}.md y será fácil de encontrar
      const chatIdToUse = currentChatId || sessionId;

      const response = await fetch(`${API_BASE_URL}/inicializar-pentesting/${chatIdToUse}`, {
        method: "POST",
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      // Solo inicializar, no cargar contenido (ya no hay informe por defecto)
      console.log(`Pentesting mode initialized successfully for chat: ${chatIdToUse}`);
    } catch (error) {
      console.error("Error initializing pentesting mode:", error);
      const errorMessage = error instanceof Error ? error.message : "Error desconocido";
      addStatusMessage(`❌ Error inicializando modo pentesting: ${errorMessage}`);
    }
  }, [currentChatId, sessionId, addStatusMessage]);

  // Crear chat inicial al cargar el componente
  useEffect(() => {
    const initializeApp = async () => {
      // Si no hay chats, crear uno por defecto
      if (chats.length === 0 && !currentChatId) {
        const newChatId = await createChat("Nueva conversación", "");
        if (newChatId) {
          await handleSelectChat(newChatId);
        }
      }

      // Generar sessionId para modo pentesting (legacy)
      if (!sessionId) {
        const newSessionId = await generateDateBasedSessionId();
        setSessionId(newSessionId);
      }
    };

    initializeApp();
  }, [chats.length, currentChatId, sessionId]);

  // Cargar mensajes del chat actual
  useEffect(() => {
    if (currentChat) {
      const chatMessages: Message[] = currentChat.messages.map((msg: any) => {
        // Parsear timestamp de forma segura
        let timestamp: Date;
        try {
          timestamp = msg.timestamp ? new Date(msg.timestamp) : new Date();
        } catch {
          timestamp = new Date();
        }

        return {
          role: msg.role,
          content: msg.content,
          timestamp: timestamp,
        };
      });
      setMessages(chatMessages);
    }
  }, [currentChat]);

  // Efecto para modo pentesting
  useEffect(() => {
    if (pentestingMode && sessionId) {
      initializePentestMode();
    }
  }, [pentestingMode, sessionId, initializePentestMode]);

  // Auto-resize textarea basado en contenido
  useEffect(() => {
    const textarea = textareaRef.current;
    if (textarea) {
      // Reset height to auto to get the correct scrollHeight
      textarea.style.height = 'auto';
      // Set height to scrollHeight (content height)
      const newHeight = Math.min(textarea.scrollHeight, 200); // Max 200px
      textarea.style.height = `${newHeight}px`;
    }
  }, [input]);

  // Hook de procesamiento ya no es necesario - se maneja en sendMessage

  const sendMessage = async (shellConfig?: any) => {
    if (!input.trim() || loading) return;

    // Asegurar que hay un chat activo
    if (!currentChatId && !pentestingMode) {
      addStatusMessage("⚠️ No hay chat activo. Creando nuevo chat...");
      await handleNewChat();
      return;
    }

    const userMessage: Message = {
      role: "user",
      content: input.trim(),
      timestamp: new Date()
    };

    setMessages((prev) => [...prev, userMessage]);
    setLoading(true);
    const currentInput = input;
    setInput("");

    try {
      const requestBody: any = {
        message: currentInput,
        pentesting: pentestingMode,
      };

      // Usar chatId si existe, sino sessionId (legacy para pentesting)
      if (currentChatId) {
        requestBody.chatId = currentChatId;
      } else if (sessionId) {
        requestBody.sessionId = sessionId;
      }

      // Incluir shellConfig si se proporcionó
      if (shellConfig) {
        requestBody.shellConfig = shellConfig;
      }

      const response = await fetch(`${API_BASE_URL}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();

      // Verificar si se requiere configuración de shell
      if (data.type === "shell_config_required") {
        setLoading(false);
        setPendingMessage(currentInput);
        setShowShellConfigModal(true);

        // Mensaje informativo para el usuario
        const infoMessage: Message = {
          role: "system",
          content: "⚠️ Se detectó solicitud de reverse shell. Por favor configura los parámetros requeridos.",
          timestamp: new Date()
        };
        setMessages((prev) => [...prev, infoMessage]);
        return;
      }

      // Añadir respuesta del asistente
      const assistantMessage: Message = {
        role: "assistant",
        content: data.response,
        timestamp: new Date()
      };
      setMessages((prev) => [...prev, assistantMessage]);

      // En el nuevo flujo, no hay procesamiento automático de informes
      // El histórico del chat se maneja automáticamente en el backend
    } catch (error) {
      console.error("Error sending message:", error);
      const errorMessage: Message = {
        role: "assistant",
        content: "Error en el servidor. Por favor, inténtalo de nuevo.",
        timestamp: new Date()
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  const handleShellConfigConfirm = async (config: any) => {
    setShowShellConfigModal(false);

    // Re-enviar el mensaje con la configuración de shell
    // NO añadir el mensaje del usuario de nuevo - ya está en el chat
    if (pendingMessage) {
      setLoading(true);

      try {
        const requestBody: any = {
          message: pendingMessage,
          pentesting: pentestingMode,
          shellConfig: config
        };

        // Usar chatId si existe, sino sessionId (legacy)
        if (currentChatId) {
          requestBody.chatId = currentChatId;
        } else if (sessionId) {
          requestBody.sessionId = sessionId;
        }

        const response = await fetch(`${API_BASE_URL}/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(requestBody),
        });

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        const assistantMessage: Message = {
          role: "assistant",
          content: data.response,
          timestamp: new Date()
        };
        setMessages((prev) => [...prev, assistantMessage]);

      } catch (error) {
        console.error("Error sending message with shell config:", error);
        const errorMessage: Message = {
          role: "assistant",
          content: "Error al configurar la shell. Por favor, inténtalo de nuevo.",
          timestamp: new Date()
        };
        setMessages((prev) => [...prev, errorMessage]);
      } finally {
        setLoading(false);
        setPendingMessage("");
      }
    }
  };

  const handleShellConfigCancel = () => {
    setShowShellConfigModal(false);
    setPendingMessage("");

    const cancelMessage: Message = {
      role: "system",
      content: "❌ Configuración de shell cancelada. Puedes intentarlo nuevamente cuando estés listo.",
      timestamp: new Date()
    };
    setMessages((prev) => [...prev, cancelMessage]);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const toggleReportEdit = async () => {
    if (editMode !== 'report') {
      await loadReportContent();
      setEditMode('report');
    } else {
      setEditMode('none');
    }
  };

  const toggleHistoryEdit = async () => {
    if (editMode !== 'history') {
      // Si hay chat activo, cargar su contenido MD raw
      if (currentChatId) {
        try {
          const response = await fetch(`${API_BASE_URL}/chats/${currentChatId}/raw`);
          if (response.ok) {
            const data = await response.json();
            setHistoryContent(data.content);
          } else {
            throw new Error('Error cargando contenido raw');
          }
        } catch (error) {
          console.error('Error loading chat for edit:', error);
          addStatusMessage('❌ Error cargando histórico');
        }
      } else {
        // Modo antiguo (pentest)
        await loadHistoryContent();
      }
      setEditMode('history');
    } else {
      setEditMode('none');
    }
  };

  const handleSaveEditedReport = async () => {
    const success = await saveEditedReport();
    if (success) {
      setEditMode('none');
    }
  };

  const handleSaveEditedHistory = async () => {
    // Si hay chat activo, guardar en ese chat
    if (currentChatId) {
      try {
        const response = await fetch(`${API_BASE_URL}/chats/${currentChatId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content: historyContent })
        });

        if (!response.ok) {
          throw new Error('Error guardando histórico');
        }

        addStatusMessage('✅ Histórico guardado correctamente');

        // Recargar el chat para actualizar los mensajes
        await loadChat(currentChatId);

        setEditMode('none');
      } catch (error) {
        console.error('Error saving history:', error);
        addStatusMessage('❌ Error guardando histórico');
      }
    } else {
      // Modo antiguo (pentest)
      const success = await saveEditedHistory();
      if (success) {
        setEditMode('none');
      }
    }
  };

  const handleReportUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const success = await uploadReport(file);
    if (success && reportFileInputRef.current) {
      reportFileInputRef.current.value = ""; // Limpiar input
    }
  };

  const handleHistoryDownload = () => {
    // Si hay chat activo, descargar ese chat
    if (currentChatId) {
      try {
        window.open(`${API_BASE_URL}/chats/${currentChatId}/download`, "_blank");
      } catch (error) {
        console.error('Error downloading chat:', error);
        addStatusMessage('❌ Error al descargar histórico');
      }
    } else {
      // Modo antiguo (pentest)
      downloadHistory();
    }
  };

  const refreshContext = async () => {
    if (!currentChatId) {
      addStatusMessage('❌ No hay chat activo');
      return;
    }

    if (loading) {
      addStatusMessage('⚠️ Espera a que termine la operación actual');
      return;
    }

    setLoading(true); // BLOQUEAR toda la UI
    try {
      addStatusMessage('🔄 Refrescando contexto del agente...');
      addStatusMessage('   1️⃣ Limpiando contexto actual...');

      // Llamar al endpoint que limpia y carga el contexto
      const response = await fetch(`${API_BASE_URL}/refresh-context/${currentChatId}`, {
        method: 'POST'
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Error refrescando contexto');
      }

      const data = await response.json();

      if (data.success) {
        addStatusMessage('   2️⃣ Cargando historial del chat...');
        addStatusMessage('✅ Contexto refrescado correctamente');
      } else {
        throw new Error(data.message || 'Unknown error');
      }
    } catch (error) {
      console.error('Error refreshing context:', error);
      addStatusMessage(`❌ Error al refrescar contexto: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setLoading(false); // DESBLOQUEAR UI
    }
  };

  const clearContext = async () => {
    if (loading) {
      addStatusMessage('⚠️ Espera a que termine la operación actual');
      return;
    }

    setLoading(true); // BLOQUEAR toda la UI
    try {
      addStatusMessage('🗑️ Limpiando contexto del agente...');

      const response = await fetch(`${API_BASE_URL}/clear-context`, {
        method: 'POST'
      });

      if (!response.ok) {
        throw new Error('Error clearing context');
      }

      const data = await response.json();

      if (data.success) {
        addStatusMessage('✅ Contexto limpiado correctamente (memoria del agente reseteada)');
      } else {
        throw new Error(data.message || 'Unknown error');
      }
    } catch (error) {
      console.error('Error clearing context:', error);
      addStatusMessage(`❌ Error al limpiar contexto: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setLoading(false); // DESBLOQUEAR UI
    }
  };

  const handleHistoryUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Si hay un chat activo, subir a ese chat
    if (currentChatId) {
      try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch(`${API_BASE_URL}/chats/${currentChatId}/upload`, {
          method: 'POST',
          body: formData
        });

        if (!response.ok) {
          throw new Error('Error al subir archivo');
        }

        addStatusMessage('✅ Histórico subido correctamente');

        // Recargar el chat para mostrar los mensajes actualizados
        await loadChat(currentChatId);

        if (historyFileInputRef.current) {
          historyFileInputRef.current.value = "";
        }
      } catch (error) {
        console.error('Error uploading history to chat:', error);
        addStatusMessage('❌ Error al subir histórico');
      }
    } else {
      // Modo antiguo (pentest)
      const success = await uploadHistory(file);
      if (success && historyFileInputRef.current) {
        historyFileInputRef.current.value = "";
      }
    }
  };

  const handleMcpFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.json')) {
      addStatusMessage("❌ Solo se permiten archivos .json");
      return;
    }

    try {
      const text = await file.text();
      setMcpJsonInput(text);
      if (mcpFileInputRef.current) {
        mcpFileInputRef.current.value = "";
      }
    } catch (error) {
      addStatusMessage("❌ Error leyendo archivo JSON");
    }
  };

  const handleImportMcps = async () => {
    if (!mcpJsonInput.trim()) {
      addStatusMessage("❌ Debe proporcionar una configuración JSON de MCPs");
      return;
    }

    try {
      // Validar JSON
      JSON.parse(mcpJsonInput);
      
      const response = await fetch(`${API_BASE_URL}/importar-mcps`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mcpConfig: mcpJsonInput }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      addStatusMessage(`✅ MCPs importados correctamente: ${data.message}`);
      setShowMcpModal(false);
      setMcpJsonInput('');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Error desconocido";
      if (errorMessage.includes("JSON")) {
        addStatusMessage("❌ JSON inválido. Por favor, verifique el formato");
      } else {
        addStatusMessage(`❌ Error importando MCPs: ${errorMessage}`);
      }
    }
  };

  const handleTogglePentestingMode = () => {
    if (pentestingMode) {
      // Desactivando modo pentesting - enviar mensaje de finalización
      setPentestingMode(false);
      setEditMode('none');
      setShowReportButtons(false);

      // Usar currentChatId para descargar (mismo ID usado al inicializar)
      const chatIdForDownload = currentChatId || sessionId;
      const reportUrl = `${API_BASE_URL}/descargar-pentesting/${chatIdForDownload}`;
      const historyUrl = `${API_BASE_URL}/chats/${chatIdForDownload}/download`;
      const finalMessage = `📊 **Modo Pentesting Finalizado**

Puede descargar los archivos generados durante esta sesión:

🔗 **Descargar Informe**: [pentesting_${chatIdForDownload}.md](${reportUrl})
🔗 **Descargar Histórico**: [historico_chat_${chatIdForDownload}.md](${historyUrl})

✅ Archivos incluidos:
- **Informe**: Análisis profesional y recomendaciones (si se generó)
- **Histórico**: Registro completo de la conversación

*Los botones de descarga permanecen disponibles en la interfaz.*`;
      
      addStatusMessage(finalMessage);
    } else {
      // Activando modo pentesting
      setPentestingMode(true);
      setShowReportButtons(true);
      addStatusMessage("📋 **Modo Pentesting Activado**\n\nEl sistema guardará automáticamente el histórico de la conversación. Use los botones para generar informes profesionales cuando desee.");
    }
  };

  const isDisabled = loading || isProcessing;
  const isHeaderDisabled = loading || editMode !== 'none' || isProcessing;

  return (
    <div className="h-full max-h-full flex bg-black overflow-hidden">
      {/* Sidebar de chats */}
      {showSidebar && (
        <div className="w-80 h-full flex-shrink-0 hidden md:block">
          <ChatSidebar
            currentChatId={currentChatId}
            onSelectChat={handleSelectChat}
            onNewChat={handleNewChat}
            onDeleteChat={handleDeleteChat}
            onRenameChat={handleRenameChat}
            onUpdateTarget={updateTarget}
            chats={chats}
            targets={targets}
            apiBaseUrl={API_BASE_URL}
            disabled={loading || isProcessing || editMode !== 'none'}
          />
        </div>
      )}

      {/* Contenido principal */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="border-b border-green-400/40 bg-black/95 backdrop-blur-sm shadow-2xl shadow-green-500/10 flex-shrink-0">
        <div className="w-full px-2 sm:px-3 lg:px-4 py-2">
          {/* Top row - Title and sidebar toggle */}
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              {/* Botón toggle sidebar */}
              <button
                onClick={() => setShowSidebar(!showSidebar)}
                className="hidden md:block px-2 py-1 border border-green-400/70 bg-green-400/10 text-green-400 hover:bg-green-400/20 font-mono text-xs transition-all"
                title={showSidebar ? "Ocultar chats" : "Mostrar chats"}
              >
                [{showSidebar ? "◀" : "▶"}]
              </button>

              <div className="flex items-center gap-2">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <h1 className="text-sm sm:text-base lg:text-lg font-mono font-bold text-green-400 whitespace-nowrap">
                  [Unburden@pentestingAssistant:~]$
                </h1>
              </div>
              <div className="hidden lg:flex items-center gap-2 text-xs text-gray-500 font-mono">
                <span>[v1.0.0]</span>
                <span className="text-green-400">|</span>
                <span>[ACTIVE]</span>
              </div>
            </div>
          </div>

          {/* Control buttons - Responsive con flex wrap */}
          <div className="flex flex-wrap items-center justify-center gap-2 sm:gap-3 font-mono">
            {/* Pentest Mode */}
            <div className="flex items-center gap-2 border border-gray-600/50 bg-gray-900/30 rounded-md px-3 py-2 min-w-fit shadow-lg shadow-gray-900/50">
              <span className="text-xs sm:text-sm text-green-400 whitespace-nowrap font-semibold">PENTEST:</span>
              <button
                className={`px-3 py-2 border font-mono text-xs sm:text-sm font-bold transition-all touch-manipulation rounded-md min-w-[50px] ${
                  pentestingMode
                    ? "border-red-400/70 bg-red-400/20 text-red-400 animate-pulse shadow-md shadow-red-500/20"
                    : "border-gray-600 bg-gray-900/50 text-gray-400 hover:border-green-400/70 hover:text-green-400 hover:bg-green-400/10"
                }`}
                onClick={handleTogglePentestingMode}
                disabled={isHeaderDisabled}
              >
                [{pentestingMode ? "ON" : "OFF"}]
              </button>
            </div>

            {/* MCP+ */}
            <button
              className="px-4 py-2 border-2 border-purple-400/70 bg-purple-400/15 text-purple-400 hover:border-purple-400 hover:bg-purple-400/25 font-mono text-xs sm:text-sm font-bold transition-all disabled:opacity-50 touch-manipulation rounded-md min-w-fit shadow-lg shadow-purple-900/30 hover:shadow-purple-500/30"
              onClick={() => {
                setMcpModalMode('import');
                setShowMcpModal(true);
              }}
              disabled={isHeaderDisabled}
              title="Import custom MCP servers"
            >
              [MCP+]
            </button>

            {/* MCP≡ */}
            <button
              className="px-4 py-2 border-2 border-cyan-400/70 bg-cyan-400/15 text-cyan-400 hover:border-cyan-400 hover:bg-cyan-400/25 font-mono text-xs sm:text-sm font-bold transition-all disabled:opacity-50 touch-manipulation rounded-md min-w-fit shadow-lg shadow-cyan-900/30 hover:shadow-cyan-500/30"
              onClick={() => {
                setMcpModalMode('manage');
                setShowMcpModal(true);
                loadMcpServers();
              }}
              disabled={isHeaderDisabled}
              title="Manage MCP servers"
            >
              [MCP≡]
            </button>

            {/* REFRESH CTX */}
            <button
              className="px-4 py-2 border-2 border-yellow-400/70 bg-yellow-400/15 text-yellow-400 hover:border-yellow-400 hover:bg-yellow-400/25 font-mono text-xs sm:text-sm font-bold transition-all disabled:opacity-50 touch-manipulation rounded-md whitespace-nowrap min-w-fit shadow-lg shadow-yellow-900/30 hover:shadow-yellow-500/30"
              onClick={refreshContext}
              disabled={isHeaderDisabled || !currentChatId}
              title="Refresh context from chat history"
            >
              <span className="hidden lg:inline">[REFRESH CTX]</span>
              <span className="lg:hidden">[↻ CTX]</span>
            </button>

            {/* CLEAR CTX */}
            <button
              className="px-4 py-2 border-2 border-red-400/70 bg-red-400/15 text-red-400 hover:border-red-400 hover:bg-red-400/25 font-mono text-xs sm:text-sm font-bold transition-all disabled:opacity-50 touch-manipulation rounded-md whitespace-nowrap min-w-fit shadow-lg shadow-red-900/30 hover:shadow-red-500/30"
              onClick={clearContext}
              disabled={isHeaderDisabled}
              title="Clear agent context (reset memory)"
            >
              <span className="hidden lg:inline">[CLEAR CTX]</span>
              <span className="lg:hidden">[✕ CTX]</span>
            </button>
          </div>

          {/* Tools row - Mobile Optimized */}
          {pentestingMode && showReportButtons && (
            <div className="space-y-3 mt-3">
              {/* Mobile: Show all buttons in stacked groups */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {/* Report Generation Group */}
                <div className="border border-green-400/30 bg-green-400/5 p-3 rounded">
                  <div className="text-green-400 text-xs font-mono mb-2 text-center sm:text-left">REPORT:</div>
                  <div className="flex flex-col sm:flex-row gap-2">
                    <button
                      onClick={generateReport}
                      className="px-3 py-2 border border-green-400/50 bg-green-400/10 text-green-400 hover:bg-green-400/20 transition-colors disabled:opacity-50 font-mono text-sm min-h-[36px] touch-manipulation"
                      disabled={isHeaderDisabled}
                      title="Generate report"
                    >
                      [GEN]
                    </button>
                    <button
                      onClick={updateReport}
                      className="px-3 py-2 border border-blue-400/50 bg-blue-400/10 text-blue-400 hover:bg-blue-400/20 transition-colors disabled:opacity-50 font-mono text-sm min-h-[36px] touch-manipulation"
                      disabled={isHeaderDisabled}
                      title="Update report"
                    >
                      [UPD]
                    </button>
                  </div>
                </div>

                {/* File Operations Group */}
                <div className="border border-cyan-400/30 bg-cyan-400/5 p-3 rounded">
                  <div className="text-cyan-400 text-xs font-mono mb-2 text-center sm:text-left">FILES:</div>
                  <div className="flex flex-col sm:flex-row gap-2">
                    <button
                      onClick={downloadReport}
                      className="px-3 py-2 border border-cyan-400/50 bg-cyan-400/10 text-cyan-400 hover:bg-cyan-400/20 transition-colors disabled:opacity-50 font-mono text-sm min-h-[36px] touch-manipulation"
                      disabled={isHeaderDisabled}
                      title="Download report"
                    >
                      [RPT↓]
                    </button>
                    <button
                      onClick={handleHistoryDownload}
                      className="px-3 py-2 border border-cyan-400/50 bg-cyan-400/10 text-cyan-400 hover:bg-cyan-400/20 transition-colors disabled:opacity-50 font-mono text-sm min-h-[36px] touch-manipulation"
                      disabled={isHeaderDisabled}
                      title="Download history"
                    >
                      [LOG↓]
                    </button>
                  </div>
                </div>

                {/* Edit & Tools Group */}
                <div className="border border-purple-400/30 bg-purple-400/5 p-3 rounded">
                  <div className="text-purple-400 text-xs font-mono mb-2 text-center sm:text-left">EDIT & TOOLS:</div>
                  <div className="flex flex-col gap-2">
                    <div className="flex gap-2">
                      <button
                        onClick={toggleReportEdit}
                        className={`flex-1 px-3 py-2 border transition-colors disabled:opacity-50 font-mono text-sm min-h-[36px] touch-manipulation ${
                          editMode === 'report'
                            ? "border-red-400/50 bg-red-400/10 text-red-400 animate-pulse"
                            : "border-purple-400/50 bg-purple-400/10 text-purple-400 hover:bg-purple-400/20"
                        }`}
                        disabled={loading || isProcessing}
                        title={editMode === 'report' ? "Cancel edit" : "Edit report"}
                      >
                        {editMode === 'report' ? "[CANCEL]" : "[RPT]"}
                      </button>
                      <button
                        onClick={toggleHistoryEdit}
                        className={`flex-1 px-3 py-2 border transition-colors disabled:opacity-50 font-mono text-sm min-h-[36px] touch-manipulation ${
                          editMode === 'history'
                            ? "border-red-400/50 bg-red-400/10 text-red-400 animate-pulse"
                            : "border-purple-400/50 bg-purple-400/10 text-purple-400 hover:bg-purple-400/20"
                        }`}
                        disabled={loading || isProcessing}
                        title={editMode === 'history' ? "Cancel edit" : "Edit history"}
                      >
                        {editMode === 'history' ? "[CANCEL]" : "[LOG]"}
                      </button>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => reportFileInputRef.current?.click()}
                        className="flex-1 px-3 py-2 border border-gray-500/50 bg-gray-500/10 text-gray-400 hover:bg-gray-500/20 transition-colors disabled:opacity-50 font-mono text-sm min-h-[36px] touch-manipulation"
                        disabled={isHeaderDisabled}
                        title="Upload report"
                      >
                        [↑RPT]
                      </button>
                      <button
                        onClick={() => historyFileInputRef.current?.click()}
                        className="flex-1 px-3 py-2 border border-gray-500/50 bg-gray-500/10 text-gray-400 hover:bg-gray-500/20 transition-colors disabled:opacity-50 font-mono text-sm min-h-[36px] touch-manipulation"
                        disabled={isHeaderDisabled}
                        title="Upload history"
                      >
                        [↑LOG]
                      </button>
                      <button
                        onClick={clearPentest}
                        className="flex-1 px-3 py-2 border border-red-400/50 bg-red-400/10 text-red-400 hover:bg-red-400/20 transition-colors disabled:opacity-50 font-mono text-sm min-h-[36px] touch-manipulation"
                        disabled={isHeaderDisabled}
                        title="Clear all data"
                      >
                        [WIPE]
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Inputs ocultos para archivos */}
        <input
          ref={reportFileInputRef}
          type="file"
          accept=".md"
          className="hidden"
          onChange={handleReportUpload}
        />
        <input
          ref={historyFileInputRef}
          type="file"
          accept=".md"
          className="hidden"
          onChange={handleHistoryUpload}
        />
      </header>

      <main className="flex-1 overflow-y-auto px-2 py-1 sm:p-3 bg-black/95 relative min-h-0">
        {/* Matrix-like background effect */}
        <div className="absolute inset-0 opacity-5 pointer-events-none">
          <div className="absolute top-0 left-0 w-full h-full bg-green-400/5" 
               style={{
                 backgroundImage: 'repeating-linear-gradient(90deg, transparent, transparent 2px, rgba(34, 197, 94, 0.1) 2px, rgba(34, 197, 94, 0.1) 4px)',
                 backgroundSize: '20px 20px'
               }}>
          </div>
        </div>
        {editMode === 'report' ? (
          <MarkdownEditor
            value={reportContent}
            onChange={setReportContent}
            placeholder="# [CLASSIFIED] CYBER SECURITY PENTESTING REPORT
# Generated by Unburden v1.0
# ========================================

## EXECUTIVE SUMMARY
[Enter executive summary here...]

## METHODOLOGY 
[Describe testing methodology...]

## FINDINGS
### CRITICAL
[List critical vulnerabilities...]

### HIGH
[List high-priority issues...]

## RECOMMENDATIONS
[Security recommendations...]

## TECHNICAL APPENDIX
[Technical details...]

# END OF REPORT"
            disabled={isDisabled}
            title="[EDITOR:REPORT]$ nano pentesting_report.md"
            fileType="report"
            onSave={handleSaveEditedReport}
            onCancel={() => setEditMode('none')}
            isProcessing={isProcessing}
          />
        ) : editMode === 'history' ? (
          <MarkdownEditor
            value={historyContent}
            onChange={setHistoryContent}
            placeholder="# SESSION LOG - Unburden Cyber Terminal
# =====================================
# Timestamp: $(date)
# User: user@terminal
# System: Unburden@pentestingAssistant
# =====================================

[2024-XX-XX XX:XX:XX] user@terminal: initial query here...

[2024-XX-XX XX:XX:XX] Unburden@pentestingAssistant: system response here...

[2024-XX-XX XX:XX:XX] user@terminal: follow-up query...

[2024-XX-XX XX:XX:XX] Unburden@pentestingAssistant: detailed analysis...

# END OF SESSION LOG"
            disabled={isDisabled}
            title="[EDITOR:LOG]$ tail -f session.log"
            fileType="history"
            onSave={handleSaveEditedHistory}
            onCancel={() => setEditMode('none')}
            isProcessing={isProcessing}
          />
        ) : (
          <div className="w-full max-w-none px-3 sm:px-4 space-y-2 sm:space-y-3">
            {messages.map((msg, index) => (
              <div
                key={index}
                className={`font-mono text-sm border-l-4 pl-3 sm:pl-4 py-2 sm:py-3 rounded-r ${
                  msg.role === "user" 
                    ? "border-l-cyan-400 bg-cyan-400/5" 
                    : msg.role === "system"
                    ? "border-l-yellow-400 bg-yellow-400/5"
                    : "border-l-green-400 bg-green-400/5"
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-2">
                  <div className="flex items-center space-x-2 flex-wrap">
                    <span className={`text-xs sm:text-sm font-bold ${
                      msg.role === "user" 
                        ? "text-cyan-400" 
                        : msg.role === "system"
                        ? "text-yellow-400"
                        : "text-green-400"
                    }`}>
                      [{msg.role === "user" ? "user@terminal" : "Unburden@pentestingAssistant"}]$
                    </span>
                    {msg.timestamp && (
                      <span className="text-xs text-gray-500 hidden sm:inline">
                        [{msg.timestamp.toLocaleTimeString()}]
                      </span>
                    )}
                  </div>
                </div>
                <div className={`text-sm sm:text-base leading-relaxed ${
                  msg.role === "user" 
                    ? "text-cyan-200" 
                    : msg.role === "system"
                    ? "text-yellow-200"
                    : "text-green-200"
                }`}>
                  <MarkdownRenderer 
                    content={msg.content}
                    className="break-words"
                  />
                </div>
                {index < messages.length - 1 && (
                  <div className="mt-3 text-gray-600 text-xs">
                    {Array.from({length: Math.min(40, Math.floor(window.innerWidth / 10))}).map((_, i) => (
                      <span key={i}>-</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {loading && (
              <div className="font-mono text-sm border-l-4 border-l-orange-400 bg-orange-400/5 pl-3 sm:pl-4 py-2 sm:py-3 rounded-r">
                <div className="flex items-center space-x-2 mb-2">
                  <span className="text-orange-400 text-xs sm:text-sm font-bold">
                    [Unburden@pentestingAssistant]$
                  </span>
                  <div className="flex items-center space-x-2">
                    <span className="text-orange-400 text-xs sm:text-sm animate-pulse">PROCESSING</span>
                    <div className="flex space-x-1">
                      <div className="w-2 h-2 bg-orange-400 rounded-full animate-bounce"></div>
                      <div className="w-2 h-2 bg-orange-400 rounded-full animate-bounce" style={{animationDelay: '0.1s'}}></div>
                      <div className="w-2 h-2 bg-orange-400 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
                    </div>
                  </div>
                </div>
                <div className="text-orange-200 text-sm leading-relaxed">
                  Analyzing query... Please wait
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* MCP Import Modal */}
      {showMcpModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-2 sm:p-4">
          <div className="w-full max-w-4xl max-h-[95vh] sm:max-h-[90vh] overflow-y-auto border border-purple-400/30 bg-black/95 backdrop-blur-sm rounded-lg">
            {/* Modal Header */}
            <div className="border-b border-purple-400/30 bg-purple-400/5 p-3 sm:p-4 font-mono sticky top-0 z-10">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2 flex-1 min-w-0">
                  <span className="text-purple-400 text-xs sm:text-sm font-bold truncate">
                    {mcpModalMode === 'import' 
                      ? '[MCP:IMPORT]$ configure custom_servers.json'
                      : '[MCP:MANAGE]$ server_control_panel.sh'
                    }
                  </span>
                </div>
                <button
                  onClick={() => {
                    setShowMcpModal(false);
                    setMcpJsonInput('');
                  }}
                  className="text-gray-400 hover:text-gray-300 transition-colors px-2 py-1 border border-gray-500/50 min-w-[40px] touch-manipulation"
                  title="Close"
                >
                  [X]
                </button>
              </div>
            </div>

            {/* Modal Content */}
            <div className="p-3 sm:p-4 space-y-4 max-h-[calc(95vh-80px)] sm:max-h-[calc(90vh-80px)] overflow-y-auto">
              {mcpModalMode === 'import' ? (
                <>
                  {/* Import Mode Content */}
                  {/* Instructions */}
                  <div className="bg-gray-900/50 border border-gray-700/50 p-3 font-mono text-xs sm:text-sm">
                    <div className="text-purple-300 mb-2">IMPORT CUSTOM MCP SERVERS:</div>
                    <div className="text-gray-400 space-y-1">
                      <div>• Paste your MCP configuration JSON below</div>
                      <div>• Or upload a .json file with your MCP servers</div>
                      <div>• Servers will be merged with existing system MCPs</div>
                      <div>• Use unique server names to avoid conflicts</div>
                    </div>
                  </div>

              {/* Example format */}
              <div className="bg-gray-900/80 border border-gray-600 p-3">
                <div className="text-xs text-gray-400 font-mono mb-2">EXAMPLE FORMAT:</div>
                <div className="text-green-300 font-mono text-xs leading-relaxed">
                  {`{
  "my_custom_server": {
    "command": "node",
    "args": ["/path/to/server.js"],
    "transport": "sse",
    "env": {},
    "host": "localhost",
    "port": 3002
  },
  "another_server": {
    "command": "python",
    "args": ["/path/to/server.py"],
    "transport": "stdio"
  }
}`}
                </div>
              </div>

                  {/* JSON Input */}
                  <div>
                    <div className="bg-gray-900/80 px-3 py-2 border-b border-gray-600">
                      <span className="text-xs text-gray-400 font-mono">
                        MCP CONFIGURATION EDITOR | Paste or edit your JSON configuration
                      </span>
                    </div>
                    <textarea
                      className="w-full h-48 sm:h-64 bg-black/90 text-purple-300 p-3 font-mono text-xs sm:text-sm resize-none focus:outline-none focus:ring-1 focus:ring-purple-400 transition-all leading-relaxed border border-gray-600 border-t-0"
                      value={mcpJsonInput}
                      onChange={(e) => setMcpJsonInput(e.target.value)}
                      placeholder="Paste your MCP configuration JSON here..."
                    />
                  </div>

                  {/* File Upload */}
                  <div className="flex flex-col sm:flex-row items-start sm:items-center gap-2 sm:gap-3">
                    <button
                      onClick={() => mcpFileInputRef.current?.click()}
                      className="border border-gray-500 bg-gray-500/10 text-gray-400 hover:bg-gray-500/20 px-3 py-2 font-mono text-sm min-h-[36px] transition-colors touch-manipulation"
                    >
                      [LOAD FILE]
                    </button>
                    <span className="text-xs sm:text-sm text-gray-500 font-mono">
                      Load configuration from .json file
                    </span>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex flex-col sm:flex-row justify-end gap-3 pt-4 border-t border-gray-700/50">
                    <button
                      onClick={() => {
                        setShowMcpModal(false);
                        setMcpJsonInput('');
                      }}
                      className="border border-gray-500 bg-gray-500/10 text-gray-400 hover:bg-gray-500/20 px-4 py-3 font-mono text-sm transition-colors min-h-[44px] touch-manipulation"
                    >
                      [CANCEL]
                    </button>
                    <button
                      onClick={handleImportMcps}
                      className="border border-purple-400/50 bg-purple-400/10 text-purple-400 hover:bg-purple-400/20 px-4 py-3 font-mono text-sm transition-colors disabled:opacity-50 min-h-[44px] touch-manipulation"
                      disabled={!mcpJsonInput.trim()}
                    >
                      [IMPORT MCPs]
                    </button>
                  </div>
                </>
              ) : (
                <>
                  {/* Manage Mode Content */}
                  <div className="bg-gray-900/50 border border-gray-700/50 p-3 font-mono text-xs sm:text-sm">
                    <div className="text-cyan-300 mb-2">MCP SERVER CONTROL PANEL:</div>
                    <div className="text-gray-400 space-y-1">
                      <div>• System servers are managed by the application</div>
                      <div>• User servers can be deleted individually or all at once</div>
                      <div>• Changes take effect immediately</div>
                    </div>
                  </div>

                  {/* Server Status Panel */}
                  {mcpServers && (
                    <div className="space-y-4">
                      {/* System Servers */}
                      {Object.keys(mcpServers.system_servers).length > 0 && (
                        <div>
                          <div className="text-green-400 font-mono text-sm mb-3 border-b border-green-400/30 pb-1">
                            SYSTEM SERVERS ({Object.keys(mcpServers.system_servers).length})
                          </div>
                          <div className="space-y-2">
                            {Object.entries(mcpServers.system_servers).map(([name, server]: [string, any]) => (
                              <div key={name} className="bg-gray-900/80 border border-gray-600 p-3 font-mono text-xs">
                                <div className="flex items-center justify-between mb-2">
                                  <div className="flex items-center space-x-2">
                                    <button
                                      onClick={() => toggleServerExpansion(name)}
                                      className="text-green-400 hover:text-green-300 transition-colors"
                                      title="Show/hide tools"
                                    >
                                      <svg
                                        className={`w-4 h-4 transition-transform ${expandedServers.has(name) ? 'rotate-90' : ''}`}
                                        fill="none"
                                        stroke="currentColor"
                                        viewBox="0 0 24 24"
                                      >
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                      </svg>
                                    </button>
                                    <span className="text-green-300 font-bold">{name}</span>
                                    <span className={`px-2 py-1 text-xs ${
                                      server.status === 'connected'
                                        ? 'bg-green-400/10 text-green-400 border border-green-400/30'
                                        : 'bg-red-400/10 text-red-400 border border-red-400/30'
                                    }`}>
                                      {server.status.toUpperCase()}
                                    </span>
                                  </div>
                                  <div className="text-gray-400">
                                    {server.transport} | {server.tools_count} tools
                                  </div>
                                </div>

                                {/* Tool list dropdown */}
                                {expandedServers.has(name) && server.tool_names && server.tool_names.length > 0 && (
                                  <div className="mt-2 pl-6 border-l-2 border-green-400/30">
                                    <div className="text-green-400/80 text-xs mb-1">Available Tools:</div>
                                    <ul className="space-y-1">
                                      {server.tool_names.map((toolName: string) => (
                                        <li key={toolName} className="text-gray-300 text-xs">
                                          • {toolName}
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}

                                {server.last_error && (
                                  <div className="text-red-300 text-xs mt-1">
                                    Error: {server.last_error}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* User Servers */}
                      {Object.keys(mcpServers.user_servers).length > 0 && (
                        <div>
                          <div className="text-purple-400 font-mono text-sm mb-3 border-b border-purple-400/30 pb-1">
                            USER SERVERS ({Object.keys(mcpServers.user_servers).length})
                          </div>
                          <div className="space-y-2">
                            {Object.entries(mcpServers.user_servers).map(([name, server]: [string, any]) => (
                              <div key={name} className="bg-gray-900/80 border border-gray-600 p-3 font-mono text-xs">
                                <div className="flex items-center justify-between mb-2">
                                  <div className="flex items-center space-x-2">
                                    <button
                                      onClick={() => toggleServerExpansion(name)}
                                      className="text-purple-400 hover:text-purple-300 transition-colors"
                                      title="Show/hide tools"
                                    >
                                      <svg
                                        className={`w-4 h-4 transition-transform ${expandedServers.has(name) ? 'rotate-90' : ''}`}
                                        fill="none"
                                        stroke="currentColor"
                                        viewBox="0 0 24 24"
                                      >
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                      </svg>
                                    </button>
                                    <span className="text-purple-300 font-bold">{name}</span>
                                    <span className={`px-2 py-1 text-xs ${
                                      server.status === 'connected'
                                        ? 'bg-green-400/10 text-green-400 border border-green-400/30'
                                        : 'bg-red-400/10 text-red-400 border border-red-400/30'
                                    }`}>
                                      {server.status.toUpperCase()}
                                    </span>
                                  </div>
                                  <div className="text-gray-400">
                                    {server.transport} | {server.tools_count} tools
                                  </div>
                                </div>

                                {/* Tool list dropdown */}
                                {expandedServers.has(name) && server.tool_names && server.tool_names.length > 0 && (
                                  <div className="mt-2 pl-6 border-l-2 border-purple-400/30">
                                    <div className="text-purple-400/80 text-xs mb-1">Available Tools:</div>
                                    <ul className="space-y-1">
                                      {server.tool_names.map((toolName: string) => (
                                        <li key={toolName} className="text-gray-300 text-xs">
                                          • {toolName}
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}

                                <div className="flex items-center space-x-2 mt-3">
                                  <button
                                    onClick={() => {
                                      if (window.confirm(`Delete MCP server '${name}'? This action cannot be undone.`)) {
                                        deleteMcpServer(name);
                                      }
                                    }}
                                    className="px-3 py-2 text-sm font-mono border border-red-400/50 bg-red-400/10 text-red-400 hover:bg-red-400/20 transition-colors min-h-[36px] touch-manipulation"
                                    disabled={loading}
                                  >
                                    [DELETE]
                                  </button>
                                </div>

                                {server.last_error && (
                                  <div className="text-red-300 text-xs mt-2">
                                    Error: {server.last_error}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* No User Servers */}
                      {Object.keys(mcpServers.user_servers).length === 0 && (
                        <div className="bg-gray-900/50 border border-gray-700/50 p-4 text-center">
                          <div className="text-gray-400 font-mono text-sm">
                            No user servers configured. Use [MCP+] to import custom servers.
                          </div>
                        </div>
                      )}

                      {/* Summary */}
                      <div className="bg-gray-900/80 border border-gray-600 p-3 font-mono text-xs">
                        <div className="text-cyan-300 mb-2">SERVER SUMMARY:</div>
                        <div className="grid grid-cols-2 gap-4 text-gray-400">
                          <div>Total Servers: {mcpServers.total_servers}</div>
                          <div>Connected: {mcpServers.connected_count}</div>
                          <div>Failed: {mcpServers.failed_count}</div>
                          <div>System: {Object.keys(mcpServers.system_servers).length}</div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Loading State */}
                  {!mcpServers && (
                    <div className="bg-gray-900/50 border border-gray-700/50 p-4 text-center">
                      <div className="text-gray-400 font-mono text-sm animate-pulse">
                        Loading server status...
                      </div>
                    </div>
                  )}

                  {/* Action Buttons for Manage Mode */}
                  <div className="flex flex-col gap-3 pt-4 border-t border-gray-700/50">
                    <div className="flex flex-col sm:flex-row gap-3">
                      <button
                        onClick={loadMcpServers}
                        className="border border-cyan-400/50 bg-cyan-400/10 text-cyan-400 hover:bg-cyan-400/20 px-4 py-3 font-mono text-sm transition-colors min-h-[44px] touch-manipulation"
                        disabled={loading}
                      >
                        [REFRESH]
                      </button>
                      
                      {/* CLEAR ALL button - solo mostrar si hay servidores de usuario */}
                      {mcpServers && Object.keys(mcpServers.user_servers).length > 0 && (
                        <button
                          onClick={() => {
                            if (window.confirm(`Clear ALL user MCP servers? This will remove ${Object.keys(mcpServers.user_servers).length} server(s). This action cannot be undone.`)) {
                              clearAllUserMcps();
                            }
                          }}
                          className="border border-red-400/50 bg-red-400/10 text-red-400 hover:bg-red-400/20 px-4 py-3 font-mono text-sm transition-colors min-h-[44px] touch-manipulation"
                          disabled={loading}
                        >
                          [CLEAR ALL USER]
                        </button>
                      )}
                    </div>
                    
                    <div className="flex flex-col sm:flex-row gap-3">
                      <button
                        onClick={() => {
                          setMcpModalMode('import');
                        }}
                        className="border border-purple-400/50 bg-purple-400/10 text-purple-400 hover:bg-purple-400/20 px-4 py-3 font-mono text-sm transition-colors min-h-[44px] touch-manipulation"
                      >
                        [IMPORT NEW]
                      </button>
                      
                      <button
                        onClick={() => {
                          setShowMcpModal(false);
                        }}
                        className="border border-gray-500 bg-gray-500/10 text-gray-400 hover:bg-gray-500/20 px-4 py-3 font-mono text-sm transition-colors min-h-[44px] touch-manipulation"
                      >
                        [CLOSE]
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      <input
        ref={mcpFileInputRef}
        type="file"
        accept=".json"
        className="hidden"
        onChange={handleMcpFileUpload}
      />

      {/* Shell Config Modal */}
      {showShellConfigModal && (
        <ShellConfigModal
          onConfirm={handleShellConfigConfirm}
          onCancel={handleShellConfigCancel}
          apiBaseUrl={API_BASE_URL}
        />
      )}

        <footer className="border-t border-green-400/40 bg-black/95 backdrop-blur-sm shadow-2xl shadow-green-500/10 flex-shrink-0">
          <div className="w-full p-2">
            <div className="space-y-2">
              {/* Command Line Interface */}
              <div className="relative border border-green-400/30 bg-green-400/5">
                <div className="bg-gray-900/80 px-2 py-1 border-b border-green-400/30">
                  <div className="flex items-center justify-between font-mono text-xs">
                    <div className="flex items-center space-x-2">
                      <span className="text-green-400">
                        [user@terminal:~]$
                      </span>
                      {loading && (
                        <div className="flex items-center space-x-1">
                          <span className="text-orange-400 animate-pulse">EXEC</span>
                          <div className="flex space-x-1">
                            <div className="w-1 h-1 bg-orange-400 rounded-full animate-bounce"></div>
                            <div className="w-1 h-1 bg-orange-400 rounded-full animate-bounce" style={{animationDelay: '0.1s'}}></div>
                            <div className="w-1 h-1 bg-orange-400 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
                          </div>
                        </div>
                      )}
                    </div>
                    <div className="flex items-center space-x-2 text-gray-500">
                      <span className="hidden sm:inline">[{input.length}/10K]</span>
                      {pentestingMode && (
                        <span className="text-red-400 animate-pulse">[PENTESTING]</span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="relative">
                  <textarea
                    ref={textareaRef}
                    className="w-full bg-black/90 text-green-300 p-2 pr-14 font-mono text-sm resize-none focus:outline-none focus:ring-1 focus:ring-green-400/50 transition-all placeholder-green-600/50 leading-tight min-h-[50px] max-h-[200px]"
                    rows={1}
                    placeholder="# Enter cybersecurity query here..."
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    disabled={isHeaderDisabled}
                  />

                  <button
                    onClick={() => sendMessage()}
                    disabled={isHeaderDisabled || !input.trim()}
                    className={`absolute top-1/2 transform -translate-y-1/2 right-2 px-2 py-1 border font-mono text-xs min-h-[30px] transition-all touch-manipulation ${
                      loading
                        ? "border-orange-400/70 bg-orange-400/10 text-orange-400 cursor-not-allowed animate-pulse"
                        : (isHeaderDisabled || !input.trim())
                        ? "border-gray-600 bg-gray-900/50 text-gray-500 cursor-not-allowed"
                        : "border-green-400/70 bg-green-400/10 text-green-400 hover:bg-green-400/20 hover:border-green-400"
                    }`}
                  >
                    {loading ? "[EXEC]" : "[SEND]"}
                  </button>
                </div>
              </div>

              {/* Status Bar - Solo en desktop */}
              <div className="hidden sm:flex justify-between items-center px-2 font-mono text-xs">
                <div className="flex items-center gap-3 text-gray-500">
                  <span className="flex items-center space-x-1">
                    <span className="text-green-400">●</span>
                    <span>ONLINE</span>
                  </span>
                  <span>SESSION: {input.length}/10K</span>
                  {pentestingMode && (
                    <span className="flex items-center space-x-1">
                      <span className="text-red-400 animate-pulse">●</span>
                      <span className="text-red-400">PENTESTING MODE</span>
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 text-gray-600">
                  <span>Unburden@pentestingAssistant</span>
                  <span>|</span>
                  <span>v1.0.0</span>
                  <span>|</span>
                  <span>READY</span>
                </div>
              </div>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default App;