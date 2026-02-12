import { useState } from 'react';
import MarkdownRenderer from './MarkdownRenderer';

interface MarkdownEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
  title: string;
  fileType: string;
  onSave: () => void;
  onCancel: () => void;
  isProcessing?: boolean;
}

const MarkdownEditor: React.FC<MarkdownEditorProps> = ({
  value,
  onChange,
  placeholder,
  disabled = false,
  title,
  fileType,
  onSave,
  onCancel,
  isProcessing = false
}) => {
  const [isPreviewMode, setIsPreviewMode] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);

  // Componente de vista en pantalla completa
  const FullscreenView = () => (
    <div className="fixed inset-0 z-50 bg-black/95 backdrop-blur-sm">
      {/* Header de pantalla completa */}
      <div className={`border-b p-3 font-mono ${
        fileType === 'report' 
          ? 'border-blue-400/30 bg-blue-400/5' 
          : 'border-purple-400/30 bg-purple-400/5'
      }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <span className={`text-sm font-bold ${
              fileType === 'report' ? 'text-blue-400' : 'text-purple-400'
            }`}>
              [DOCUMENT:A4]$ {fileType === 'report' ? 'pentesting_report.md' : 'session.log'}
            </span>
            <div className="text-xs text-gray-500">
              FULLSCREEN | {value.split('\n').length} LINES | {value.length} CHARS
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setIsPreviewMode(!isPreviewMode)}
              className={`px-3 py-2 border text-xs font-mono transition-colors ${
                isPreviewMode
                  ? 'border-green-400/50 bg-green-400/10 text-green-400'
                  : 'border-gray-500/50 bg-gray-500/10 text-gray-400 hover:border-gray-400'
              }`}
              disabled={disabled}
            >
              {isPreviewMode ? '[EDIT]' : '[PREVIEW]'}
            </button>
            <button
              onClick={onSave}
              className={`border px-3 py-2 font-mono text-xs transition-colors disabled:opacity-50 ${
                fileType === 'report'
                  ? 'border-green-400/50 bg-green-400/10 text-green-400 hover:bg-green-400/20'
                  : 'border-purple-400/50 bg-purple-400/10 text-purple-400 hover:bg-purple-400/20'
              }`}
              disabled={disabled}
            >
              [SAVE]
            </button>
            <button
              onClick={() => setIsFullscreen(false)}
              className="border border-red-400/50 bg-red-400/10 text-red-400 hover:bg-red-400/20 px-3 py-2 font-mono text-xs transition-colors"
            >
              [EXIT FS]
            </button>
          </div>
        </div>
      </div>

      {/* Contenido con estética del chat */}
      <div className="h-[calc(100vh-60px)] overflow-y-auto p-4 bg-black/95">
        <div className="w-full max-w-4xl mx-auto bg-black border border-green-400/30 shadow-2xl shadow-green-500/20" style={{
          minHeight: '297mm', // A4 height
          width: '210mm', // A4 width
          maxWidth: '210mm'
        }}>
          {isPreviewMode ? (
            <div className={`p-8 h-full ${
              fileType === 'report' ? 'text-blue-200' : 'text-purple-200'
            }`}>
              <MarkdownRenderer 
                content={value}
                className="prose-invert max-w-none leading-relaxed"
                isA4View={false}
              />
            </div>
          ) : (
            <textarea
              className={`w-full h-full bg-black/90 p-8 font-mono text-sm resize-none focus:outline-none transition-all leading-relaxed border-none ${
                fileType === 'report' 
                  ? 'text-green-300 focus:ring-1 focus:ring-blue-400' 
                  : 'text-purple-300 focus:ring-1 focus:ring-purple-400'
              }`}
              style={{
                minHeight: '297mm'
              }}
              value={value}
              onChange={(e) => onChange(e.target.value)}
              placeholder={placeholder}
              disabled={disabled}
            />
          )}
        </div>
      </div>
    </div>
  );

  if (isFullscreen) {
    return <FullscreenView />;
  }

  return (
    <div className="w-full px-2 sm:px-4 space-y-4">
      {/* Terminal Header */}
      <div className={`border p-2 sm:p-3 font-mono ${
        fileType === 'report' 
          ? 'border-blue-400/30 bg-blue-400/5' 
          : 'border-purple-400/30 bg-purple-400/5'
      }`}>
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center space-x-2">
            <span className={`text-xs sm:text-sm font-bold ${
              fileType === 'report' ? 'text-blue-400' : 'text-purple-400'
            }`}>
              {title}
            </span>
            {isProcessing && (
              <span className={`text-xs animate-pulse ${
                fileType === 'report' ? 'text-blue-400' : 'text-purple-400'
              }`}>
                [PROCESSING...]
              </span>
            )}
          </div>
          <div className="flex items-center space-x-2">
            <div className="text-xs text-gray-500 font-mono">
              LINES: {value.split('\n').length} | CHARS: {value.length}
            </div>
            <button
              onClick={() => setIsPreviewMode(!isPreviewMode)}
              className={`px-2 py-1 border text-xs font-mono transition-colors ${
                isPreviewMode
                  ? 'border-green-400/50 bg-green-400/10 text-green-400'
                  : 'border-gray-500/50 bg-gray-500/10 text-gray-400 hover:border-gray-400'
              }`}
              disabled={disabled}
            >
              {isPreviewMode ? '[EDIT]' : '[PREVIEW]'}
            </button>
            <button
              onClick={() => setIsFullscreen(true)}
              className="px-2 py-1 border border-orange-400/50 bg-orange-400/10 text-orange-400 hover:bg-orange-400/20 text-xs font-mono transition-colors"
              disabled={disabled}
            >
              [FULLSCREEN]
            </button>
          </div>
        </div>
      </div>

      {/* Editor/Preview - Aumentado el tamaño */}
      <div className="border border-gray-600 bg-black/90 overflow-hidden">
        <div className="bg-gray-900/80 px-3 py-1 border-b border-gray-600">
          <span className="text-xs text-gray-400 font-mono">
            {isPreviewMode 
              ? 'MARKDOWN PREVIEW | Rendered output' 
              : fileType === 'report' 
                ? 'CYBER SECURITY AUDIT REPORT EDITOR v1.0 | ESC to exit, CTRL+S to save'
                : 'CHAT HISTORY EDITOR v1.0 | Session logs and communication records'
            }
          </span>
        </div>
        
        {isPreviewMode ? (
          <div className={`h-96 sm:h-[500px] lg:h-[600px] overflow-y-auto p-3 sm:p-4 ${
            fileType === 'report' ? 'text-blue-200' : 'text-purple-200'
          }`}>
            <MarkdownRenderer 
              content={value} 
              className="prose-invert max-w-none"
            />
          </div>
        ) : (
          <textarea
            className={`w-full h-96 sm:h-[500px] lg:h-[600px] bg-black/90 p-3 sm:p-4 font-mono text-xs sm:text-sm resize-none focus:outline-none transition-all leading-relaxed ${
              fileType === 'report' 
                ? 'text-green-300 focus:ring-1 focus:ring-blue-400' 
                : 'text-purple-300 focus:ring-1 focus:ring-purple-400'
            }`}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={placeholder}
            disabled={disabled}
          />
        )}
        
        <div className="bg-gray-900/80 px-3 py-1 border-t border-gray-600">
          <span className="text-xs text-gray-400 font-mono">
            {isPreviewMode 
              ? `Preview Mode | ${value.split('\n').length} lines rendered`
              : `Line ${value.split('\n').length} | Markdown Format | Ready`
            }
          </span>
        </div>
      </div>

      {/* Controls */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
        <div className="text-xs text-gray-500 font-mono">
          <span>[FILE] {fileType === 'report' ? 'pentesting_report.md' : 'session.log'}</span>
          <span className="ml-4">[FORMAT] Markdown</span>
          <span className="ml-4">[STATUS] Modified</span>
        </div>
        <div className="flex space-x-2">
          <button
            onClick={onSave}
            className={`border px-3 sm:px-4 py-2 font-mono text-xs sm:text-sm transition-colors disabled:opacity-50 ${
              fileType === 'report'
                ? 'border-green-400/50 bg-green-400/10 text-green-400 hover:bg-green-400/20'
                : 'border-purple-400/50 bg-purple-400/10 text-purple-400 hover:bg-purple-400/20'
            }`}
            disabled={disabled}
          >
            [CTRL+S] SAVE
          </button>
          <button
            onClick={onCancel}
            className="border border-gray-500 bg-gray-500/10 text-gray-400 hover:bg-gray-500/20 px-3 sm:px-4 py-2 font-mono text-xs sm:text-sm transition-colors"
          >
            [ESC] EXIT
          </button>
        </div>
      </div>
    </div>
  );
};

export default MarkdownEditor;