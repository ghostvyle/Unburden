import { useState, useEffect } from "react";

interface Chat {
  id: string;
  title: string;
  target: string;
  updatedAt: string;
}

interface ChatSidebarProps {
  currentChatId: string | null;
  onSelectChat: (chatId: string) => void;
  onNewChat: (title?: string, target?: string) => void;
  onDeleteChat: (chatId: string) => void;
  onRenameChat: (chatId: string, newTitle: string) => void;
  onUpdateTarget: (chatId: string, newTarget: string) => void;
  chats: Chat[];
  targets: string[];
  apiBaseUrl: string;
  disabled?: boolean;
}

const ChatSidebar = ({
  currentChatId,
  onSelectChat,
  onNewChat,
  onDeleteChat,
  onRenameChat,
  onUpdateTarget,
  chats,
  targets,
  disabled = false,
}: ChatSidebarProps) => {
  const [selectedTarget, setSelectedTarget] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [editingChatId, setEditingChatId] = useState<string | null>(null);
  const [editingTitle, setEditingTitle] = useState("");
  const [editingTargetChatId, setEditingTargetChatId] = useState<string | null>(null);
  const [editingTargetValue, setEditingTargetValue] = useState("");
  const [contextMenuChatId, setContextMenuChatId] = useState<string | null>(null);
  const [contextMenuPosition, setContextMenuPosition] = useState<{ x: number; y: number } | null>(null);
  const [showNewChatModal, setShowNewChatModal] = useState(false);
  const [newChatTitle, setNewChatTitle] = useState("");
  const [newChatTarget, setNewChatTarget] = useState("");
  const [isCreatingTarget, setIsCreatingTarget] = useState(false);

  // Filtrar chats por target y búsqueda
  const filteredChats = chats.filter((chat) => {
    const matchesTarget = !selectedTarget || chat.target === selectedTarget;
    const matchesSearch = !searchTerm ||
      chat.title.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesTarget && matchesSearch;
  });

  // Cerrar menú contextual al hacer click fuera
  useEffect(() => {
    const handleClickOutside = () => {
      setContextMenuChatId(null);
      setContextMenuPosition(null);
    };

    if (contextMenuChatId) {
      document.addEventListener("click", handleClickOutside);
      return () => document.removeEventListener("click", handleClickOutside);
    }
  }, [contextMenuChatId]);

  const handleContextMenu = (e: React.MouseEvent, chatId: string) => {
    e.preventDefault();
    setContextMenuChatId(chatId);
    setContextMenuPosition({ x: e.clientX, y: e.clientY });
  };

  const handleRenameClick = (chat: Chat) => {
    setEditingChatId(chat.id);
    setEditingTitle(chat.title);
    setContextMenuChatId(null);
  };

  const handleRenameSubmit = () => {
    if (editingChatId && editingTitle.trim()) {
      onRenameChat(editingChatId, editingTitle.trim());
    }
    setEditingChatId(null);
    setEditingTitle("");
  };

  const handleDeleteClick = (chatId: string) => {
    if (window.confirm("¿Estás seguro de que quieres eliminar este chat?")) {
      onDeleteChat(chatId);
    }
    setContextMenuChatId(null);
  };

  const handleEditTargetClick = (chat: Chat) => {
    setEditingTargetChatId(chat.id);
    setEditingTargetValue(chat.target);
    setContextMenuChatId(null);
  };

  const handleUpdateTargetSubmit = () => {
    if (editingTargetChatId && editingTargetValue.trim()) {
      onUpdateTarget(editingTargetChatId, editingTargetValue.trim());
    }
    setEditingTargetChatId(null);
    setEditingTargetValue("");
  };

  const handleDeleteTarget = async () => {
    if (!selectedTarget) return;

    const confirmed = window.confirm(
      `¿Eliminar la target "${selectedTarget}"?\n\nLos chats con esta target quedarán sin target asignada.`
    );

    if (!confirmed) return;

    try {
      const response = await fetch(`${apiBaseUrl}/targets/${encodeURIComponent(selectedTarget)}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Error al eliminar target');
      }

      const result = await response.json();

      // Resetear la selección de target
      setSelectedTarget(null);

      // Recargar la página o actualizar el estado
      window.location.reload();
    } catch (error) {
      console.error('Error deleting target:', error);
      alert('Error al eliminar la target');
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return "Ahora";
    if (diffMins < 60) return `${diffMins}m`;
    if (diffHours < 24) return `${diffHours}h`;
    if (diffDays < 7) return `${diffDays}d`;
    return date.toLocaleDateString();
  };

  const handleCreateNewChat = () => {
    setNewChatTitle("");
    setNewChatTarget("");
    setIsCreatingTarget(false);
    setShowNewChatModal(true);
  };

  const handleConfirmNewChat = () => {
    onNewChat(newChatTitle || "Nueva conversación", newChatTarget);
    setShowNewChatModal(false);
  };

  return (
    <div className="flex flex-col h-full bg-gray-900 border-r border-green-500/30">
      {/* Header */}
      <div className="p-4 border-b border-green-500/30">
        <button
          onClick={handleCreateNewChat}
          disabled={disabled}
          className={`w-full font-mono px-4 py-2 rounded transition-colors ${
            disabled
              ? "bg-gray-600 text-gray-400 cursor-not-allowed opacity-50"
              : "bg-green-600 hover:bg-green-700 text-white"
          }`}
        >
          [NEW CHAT]
        </button>
      </div>

      {/* Búsqueda */}
      <div className="p-4">
        <input
          type="text"
          placeholder="Buscar chats..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full bg-gray-800 text-green-400 border border-green-500/30 rounded px-3 py-2 font-mono text-sm focus:outline-none focus:border-green-500"
        />
      </div>

      {/* Filtro de targets con botón de eliminar */}
      <div className="px-2 sm:px-4 pb-2">
        <div className="flex gap-1 sm:gap-2">
          <select
            value={selectedTarget || ""}
            onChange={(e) => setSelectedTarget(e.target.value || null)}
            className="flex-1 min-w-0 bg-gray-800 text-green-400 border border-green-500/30 rounded px-2 sm:px-3 py-2 font-mono text-xs sm:text-sm focus:outline-none focus:border-green-500 truncate"
          >
            <option value="">Todos los targets</option>
            {targets.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
          {selectedTarget && selectedTarget !== "" && (
            <button
              onClick={handleDeleteTarget}
              className="flex-shrink-0 px-2 sm:px-3 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 rounded font-mono text-xs transition-colors whitespace-nowrap"
              title={`Eliminar target "${selectedTarget}"`}
            >
              [DEL]
            </button>
          )}
        </div>
      </div>

      {/* Lista de chats */}
      <div className="flex-1 overflow-y-auto">
        {filteredChats.length === 0 ? (
          <div className="p-4 text-center text-gray-500 font-mono text-sm">
            No hay chats
          </div>
        ) : (
          <div className="space-y-1 p-2">
            {filteredChats.map((chat) => (
              <div
                key={chat.id}
                className={`relative group rounded p-3 transition-colors ${
                  disabled
                    ? "opacity-50 cursor-not-allowed"
                    : "cursor-pointer"
                } ${
                  currentChatId === chat.id
                    ? "bg-green-600/20 border border-green-500/50"
                    : disabled
                      ? "border border-transparent"
                      : "hover:bg-gray-800 border border-transparent"
                }`}
                onClick={() => !disabled && onSelectChat(chat.id)}
                onContextMenu={(e) => !disabled && handleContextMenu(e, chat.id)}
              >
                {editingChatId === chat.id ? (
                  <input
                    type="text"
                    value={editingTitle}
                    onChange={(e) => setEditingTitle(e.target.value)}
                    onBlur={handleRenameSubmit}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") handleRenameSubmit();
                      if (e.key === "Escape") setEditingChatId(null);
                    }}
                    className="w-full bg-gray-700 text-green-400 border border-green-500 rounded px-2 py-1 font-mono text-sm focus:outline-none"
                    autoFocus
                    onClick={(e) => e.stopPropagation()}
                  />
                ) : (
                  <>
                    <div className="flex items-start justify-between mb-1">
                      <h3 className="text-green-400 font-mono text-sm font-semibold truncate flex-1">
                        {chat.title}
                      </h3>
                      <span className="text-gray-500 text-xs font-mono ml-2">
                        {formatDate(chat.updatedAt)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      {editingTargetChatId === chat.id ? (
                        <input
                          type="text"
                          value={editingTargetValue}
                          onChange={(e) => setEditingTargetValue(e.target.value)}
                          onBlur={handleUpdateTargetSubmit}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") handleUpdateTargetSubmit();
                            if (e.key === "Escape") setEditingTargetChatId(null);
                          }}
                          className="flex-1 bg-gray-700 text-purple-400 border border-purple-500 rounded px-2 py-1 font-mono text-xs focus:outline-none mr-2"
                          placeholder="Target (ej: 192.168.1.1)"
                          autoFocus
                          onClick={(e) => e.stopPropagation()}
                        />
                      ) : (
                        <span
                          className="text-purple-400 text-xs font-mono cursor-pointer hover:text-purple-300 transition-colors"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleEditTargetClick(chat);
                          }}
                          title="Click para editar target"
                        >
                          {chat.target || "[Sin target]"}
                        </span>
                      )}
                    </div>
                  </>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Menú contextual */}
      {contextMenuChatId && contextMenuPosition && (
        <div
          className="fixed bg-gray-800 border border-green-500/30 rounded shadow-lg py-1 z-50"
          style={{
            left: `${contextMenuPosition.x}px`,
            top: `${contextMenuPosition.y}px`,
          }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            onClick={() => {
              const chat = chats.find((c) => c.id === contextMenuChatId);
              if (chat) handleRenameClick(chat);
            }}
            className="w-full text-left px-4 py-2 text-green-400 hover:bg-gray-700 font-mono text-sm"
          >
            [RENAME]
          </button>
          <button
            onClick={() => {
              const chat = chats.find((c) => c.id === contextMenuChatId);
              if (chat) handleEditTargetClick(chat);
            }}
            className="w-full text-left px-4 py-2 text-purple-400 hover:bg-gray-700 font-mono text-sm"
          >
            [EDIT TARGET]
          </button>
          <button
            onClick={() => handleDeleteClick(contextMenuChatId)}
            className="w-full text-left px-4 py-2 text-red-400 hover:bg-gray-700 font-mono text-sm"
          >
            [DELETE]
          </button>
        </div>
      )}

      {/* Modal de nuevo chat */}
      {showNewChatModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-green-500/30 rounded-lg p-6 max-w-md w-full">
            <h3 className="text-green-400 font-mono text-lg mb-4">[NEW CHAT]</h3>

            {/* Título */}
            <div className="mb-4">
              <label className="text-gray-400 font-mono text-sm block mb-2">Título:</label>
              <input
                type="text"
                value={newChatTitle}
                onChange={(e) => setNewChatTitle(e.target.value)}
                placeholder="Nueva conversación"
                className="w-full bg-gray-800 text-green-400 border border-green-500/30 rounded px-3 py-2 font-mono text-sm focus:outline-none focus:border-green-500"
                autoFocus
              />
            </div>

            {/* Target */}
            <div className="mb-6">
              <label className="text-gray-400 font-mono text-sm block mb-2">Target:</label>

              {!isCreatingTarget ? (
                <div className="flex gap-2">
                  <select
                    value={newChatTarget}
                    onChange={(e) => setNewChatTarget(e.target.value)}
                    className="flex-1 bg-gray-800 text-green-400 border border-green-500/30 rounded px-3 py-2 font-mono text-sm focus:outline-none focus:border-green-500"
                  >
                    <option value="">Sin target</option>
                    {targets.map((cat) => (
                      <option key={cat} value={cat}>
                        {cat}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={() => setIsCreatingTarget(true)}
                    className="px-3 py-2 border border-purple-400/50 bg-purple-400/10 text-purple-400 hover:bg-purple-400/20 font-mono text-sm rounded transition-colors"
                    title="Crear nueva target"
                  >
                    [+]
                  </button>
                </div>
              ) : (
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={newChatTarget}
                    onChange={(e) => setNewChatTarget(e.target.value)}
                    placeholder="Nueva target"
                    className="flex-1 bg-gray-800 text-green-400 border border-green-500/30 rounded px-3 py-2 font-mono text-sm focus:outline-none focus:border-green-500"
                  />
                  <button
                    onClick={() => {
                      setIsCreatingTarget(false);
                      setNewChatTarget("");
                    }}
                    className="px-3 py-2 border border-gray-500/50 bg-gray-500/10 text-gray-400 hover:bg-gray-500/20 font-mono text-sm rounded transition-colors"
                  >
                    [X]
                  </button>
                </div>
              )}
            </div>

            {/* Botones */}
            <div className="flex gap-3">
              <button
                onClick={() => setShowNewChatModal(false)}
                className="flex-1 px-4 py-2 border border-gray-500/50 bg-gray-500/10 text-gray-400 hover:bg-gray-500/20 font-mono text-sm rounded transition-colors"
              >
                [CANCEL]
              </button>
              <button
                onClick={handleConfirmNewChat}
                className="flex-1 px-4 py-2 border border-green-500/50 bg-green-500/10 text-green-400 hover:bg-green-500/20 font-mono text-sm rounded transition-colors"
              >
                [CREATE]
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ChatSidebar;
