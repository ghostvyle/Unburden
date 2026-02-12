import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeHighlight from 'rehype-highlight';
import rehypeRaw from 'rehype-raw';
import { ReactNode } from 'react';

interface MarkdownRendererProps {
  content: string;
  className?: string;
  isA4View?: boolean;
}

const MarkdownRenderer: React.FC<MarkdownRendererProps> = ({ content, className = '', isA4View = false }) => {
  const handleLinkClick = (href: string) => {
    // Abrir enlaces en el navegador predeterminado
    if (href.startsWith('http://') || href.startsWith('https://')) {
      window.open(href, '_blank', 'noopener,noreferrer');
    }
  };

  const customComponents = {
    // Componente personalizado para enlaces
    a: ({ href, children, ...props }: any) => {
      const isExternalLink = href && (href.startsWith('http://') || href.startsWith('https://'));
      
      return (
        <span
          className={`underline cursor-pointer transition-colors inline-flex items-center gap-1 px-1 py-0.5 rounded ${
            isA4View 
              ? 'text-blue-600 hover:text-blue-800 hover:bg-blue-50' 
              : 'text-cyan-400 hover:text-cyan-300 hover:bg-cyan-400/10'
          }`}
          onClick={(e) => {
            e.preventDefault();
            if (isExternalLink && href) {
              handleLinkClick(href);
            }
          }}
          title={isExternalLink ? `Open ${href} in browser` : href}
          {...props}
        >
          {children}
          {isExternalLink && (
            <span className="text-xs opacity-60">🔗</span>
          )}
        </span>
      );
    },

    // Componente personalizado para código inline
    code: ({ inline, className, children, ...props }: any) => {
      if (inline) {
        return (
          <code 
            className={`px-1 py-0.5 rounded text-sm font-mono border ${
              isA4View 
                ? 'bg-gray-100 text-gray-800 border-gray-300' 
                : 'bg-gray-800/50 text-green-300 border-gray-700/50'
            }`}
            {...props}
          >
            {children}
          </code>
        );
      }
      
      return (
        <code 
          className={`font-mono text-sm ${className || ''}`}
          {...props}
        >
          {children}
        </code>
      );
    },

    // Componente personalizado para bloques de código
    pre: ({ children, ...props }: any) => (
      <pre 
        className={`p-3 rounded border overflow-x-auto font-mono text-sm my-2 ${
          isA4View 
            ? 'bg-gray-50 text-gray-800 border-gray-300' 
            : 'bg-gray-900/80 text-green-300 border-gray-700/50'
        }`}
        {...props}
      >
        {children}
      </pre>
    ),

    // Componente personalizado para encabezados
    h1: ({ children, ...props }: any) => (
      <h1 className={`text-xl font-bold mt-4 mb-2 ${
        isA4View ? 'text-gray-900' : 'text-green-400 font-mono'
      }`} {...props}>
        {children}
      </h1>
    ),
    h2: ({ children, ...props }: any) => (
      <h2 className={`text-lg font-bold mt-3 mb-2 ${
        isA4View ? 'text-gray-900' : 'text-green-400 font-mono'
      }`} {...props}>
        {children}
      </h2>
    ),
    h3: ({ children, ...props }: any) => (
      <h3 className={`text-base font-bold mt-2 mb-1 ${
        isA4View ? 'text-gray-900' : 'text-green-400 font-mono'
      }`} {...props}>
        {children}
      </h3>
    ),

    // Componente personalizado para listas
    ul: ({ children, ...props }: any) => (
      <ul className="list-disc list-inside space-y-1 my-2 ml-4" {...props}>
        {children}
      </ul>
    ),
    ol: ({ children, ...props }: any) => (
      <ol className="list-decimal list-inside space-y-1 my-2 ml-4" {...props}>
        {children}
      </ol>
    ),
    li: ({ children, ...props }: any) => (
      <li className="text-inherit" {...props}>
        {children}
      </li>
    ),

    // Componente personalizado para texto en negrita y cursiva
    strong: ({ children, ...props }: any) => (
      <strong className="font-bold text-inherit" {...props}>
        {children}
      </strong>
    ),
    em: ({ children, ...props }: any) => (
      <em className="italic text-inherit" {...props}>
        {children}
      </em>
    ),

    // Componente personalizado para citas
    blockquote: ({ children, ...props }: any) => (
      <blockquote 
        className={`border-l-4 pl-4 py-2 my-2 italic ${
          isA4View 
            ? 'border-gray-400 bg-gray-50 text-gray-700' 
            : 'border-gray-600 bg-gray-900/30 text-gray-300'
        }`}
        {...props}
      >
        {children}
      </blockquote>
    ),

    // Componente personalizado para tablas
    table: ({ children, ...props }: any) => (
      <div className="overflow-x-auto my-2">
        <table 
          className={`min-w-full border-collapse border ${
            isA4View 
              ? 'border-gray-300 bg-white' 
              : 'border-gray-600 bg-gray-900/50'
          }`}
          {...props}
        >
          {children}
        </table>
      </div>
    ),
    th: ({ children, ...props }: any) => (
      <th 
        className={`border px-3 py-2 text-left font-bold ${
          isA4View 
            ? 'border-gray-300 bg-gray-100 text-gray-900' 
            : 'border-gray-600 bg-gray-800 text-green-400 font-mono'
        }`}
        {...props}
      >
        {children}
      </th>
    ),
    td: ({ children, ...props }: any) => (
      <td 
        className={`border px-3 py-2 text-inherit ${
          isA4View ? 'border-gray-300' : 'border-gray-600'
        }`}
        {...props}
      >
        {children}
      </td>
    ),

    // Componente personalizado para líneas horizontales
    hr: (props: any) => (
      <hr className={`my-4 ${isA4View ? 'border-gray-400' : 'border-gray-600'}`} {...props} />
    ),

    // Componente personalizado para párrafos
    p: ({ children, ...props }: any) => (
      <p className="mb-2 leading-relaxed" {...props}>
        {children}
      </p>
    ),
  };

  return (
    <div className={`markdown-content ${className}`}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeHighlight, rehypeRaw]}
        components={customComponents}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
};

export default MarkdownRenderer;