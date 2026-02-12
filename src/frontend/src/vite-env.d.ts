/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL: string
  readonly VITE_LLM_MODEL: string
  readonly VITE_MAX_MESSAGE_LENGTH: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}