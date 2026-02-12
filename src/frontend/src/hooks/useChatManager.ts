import { useState, useCallback, useEffect } from "react";

interface Chat {
  id: string;
  title: string;
  target: string;
  messageCount: number;
  lastMessage: string;
  createdAt: string;
  updatedAt: string;
  messages: Message[];
}

interface Message {
  role: string;
  content: string;
  timestamp: string;
}

interface UseChatManagerResult {
  chats: Chat[];
  targets: string[];
  currentChat: Chat | null;
  loading: boolean;
  loadChats: () => Promise<void>;
  createChat: (title?: string, target?: string) => Promise<string | null>;
  loadChat: (chatId: string) => Promise<Chat | null>;
  deleteChat: (chatId: string) => Promise<boolean>;
  renameChat: (chatId: string, newTitle: string) => Promise<boolean>;
  updateTarget: (chatId: string, newTarget: string) => Promise<boolean>;
}

export const useChatManager = (apiBaseUrl: string): UseChatManagerResult => {
  const [chats, setChats] = useState<Chat[]>([]);
  const [targets, setCategories] = useState<string[]>([]);
  const [currentChat, setCurrentChat] = useState<Chat | null>(null);
  const [loading, setLoading] = useState(false);

  // Cargar lista de chats
  const loadChats = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch(`${apiBaseUrl}/chats`);
      if (!response.ok) {
        throw new Error("Failed to load chats");
      }

      const data = await response.json();
      setChats(data.chats || []);
      setCategories(data.targets || []);
    } catch (error) {
      console.error("Error loading chats:", error);
    } finally {
      setLoading(false);
    }
  }, [apiBaseUrl]);

  // Crear nuevo chat
  const createChat = useCallback(
    async (title: string = "Nueva conversación", target: string = ""): Promise<string | null> => {
      try {
        const response = await fetch(`${apiBaseUrl}/chats`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ title, target }),
        });

        if (!response.ok) {
          throw new Error("Failed to create chat");
        }

        const newChat = await response.json();
        await loadChats(); // Recargar lista
        return newChat.id;
      } catch (error) {
        console.error("Error creating chat:", error);
        return null;
      }
    },
    [apiBaseUrl, loadChats]
  );

  // Cargar un chat específico
  const loadChat = useCallback(
    async (chatId: string): Promise<Chat | null> => {
      try {
        setLoading(true);
        const response = await fetch(`${apiBaseUrl}/chats/${chatId}`);

        if (!response.ok) {
          throw new Error("Failed to load chat");
        }

        const chat = await response.json();
        setCurrentChat(chat);
        return chat;
      } catch (error) {
        console.error("Error loading chat:", error);
        return null;
      } finally {
        setLoading(false);
      }
    },
    [apiBaseUrl]
  );

  // Eliminar chat
  const deleteChat = useCallback(
    async (chatId: string): Promise<boolean> => {
      try {
        const response = await fetch(`${apiBaseUrl}/chats/${chatId}`, {
          method: "DELETE",
        });

        if (!response.ok) {
          throw new Error("Failed to delete chat");
        }

        // Si el chat eliminado era el actual, limpiarlo
        if (currentChat?.id === chatId) {
          setCurrentChat(null);
        }

        await loadChats(); // Recargar lista
        return true;
      } catch (error) {
        console.error("Error deleting chat:", error);
        return false;
      }
    },
    [apiBaseUrl, currentChat, loadChats]
  );

  // Renombrar chat
  const renameChat = useCallback(
    async (chatId: string, newTitle: string): Promise<boolean> => {
      try {
        const response = await fetch(`${apiBaseUrl}/chats/${chatId}/title`, {
          method: "PATCH",  // Corregido: usar PATCH en lugar de PUT
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ title: newTitle }),
        });

        if (!response.ok) {
          throw new Error("Failed to rename chat");
        }

        // Actualizar chat actual si es el que se renombró
        if (currentChat?.id === chatId) {
          setCurrentChat({ ...currentChat, title: newTitle });
        }

        await loadChats(); // Recargar lista
        return true;
      } catch (error) {
        console.error("Error renaming chat:", error);
        return false;
      }
    },
    [apiBaseUrl, currentChat, loadChats]
  );

  // Actualizar target (no usado en el sistema actual, pero mantenemos compatibilidad)
  const updateTarget = useCallback(
    async (chatId: string, newTarget: string): Promise<boolean> => {
      try {
        const response = await fetch(`${apiBaseUrl}/chats/${chatId}/target`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target: newTarget }),
        });

        if (!response.ok) {
          throw new Error("Failed to update target");
        }

        // Recargar la lista de chats después de actualizar
        await loadChats();
        return true;
      } catch (error) {
        console.error("Error updating target:", error);
        return false;
      }
    },
    [apiBaseUrl, loadChats]
  );

  // Cargar chats al montar el componente
  useEffect(() => {
    loadChats();
  }, [loadChats]);

  return {
    chats,
    targets,
    currentChat,
    loading,
    loadChats,
    createChat,
    loadChat,
    deleteChat,
    renameChat,
    updateTarget,
  };
};
