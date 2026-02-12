import { useState } from 'react';

interface ShellConfig {
  lhost: string;
  lport: number;
  os_type: string;
}

interface ShellConfigModalProps {
  onConfirm: (config: ShellConfig) => void;
  onCancel: () => void;
  apiBaseUrl: string;
}

const ShellConfigModal = ({ onConfirm, onCancel, apiBaseUrl }: ShellConfigModalProps) => {
  const [config, setConfig] = useState<ShellConfig>({
    lhost: '',
    lport: 4445,
    os_type: ''
  });

  const [showOsDetection, setShowOsDetection] = useState(false);
  const [targetIp, setTargetIp] = useState('');
  const [detecting, setDetecting] = useState(false);
  const [detectionError, setDetectionError] = useState('');

  const handleDetectOS = async () => {
    if (!targetIp.trim()) {
      setDetectionError('Por favor ingresa una IP válida');
      return;
    }

    setDetecting(true);
    setDetectionError('');

    try {
      const response = await fetch(`${apiBaseUrl}/detect-os`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetIp })
      });

      const result = await response.json();

      if (result.success && result.osType !== 'unknown') {
        setConfig({ ...config, os_type: result.osType });
        setShowOsDetection(false);
        setDetectionError('');
        alert(`✅ SO detectado: ${result.osType.toUpperCase()} (TTL=${result.ttl})`);
      } else {
        setDetectionError(`No se pudo detectar el SO. TTL recibido: ${result.ttl}. Por favor selecciona manualmente.`);
      }
    } catch (error) {
      setDetectionError('Error de conexión al detectar SO');
      console.error('Error detecting OS:', error);
    } finally {
      setDetecting(false);
    }
  };

  const handleConfirm = () => {
    // Validación básica
    if (!config.lhost || !config.os_type) {
      alert('Por favor completa todos los campos requeridos');
      return;
    }

    onConfirm(config);
  };

  const isFormValid = config.lhost.trim() !== '' && config.os_type !== '';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto border border-red-400/30 bg-black/95 backdrop-blur-sm rounded-lg">
        {/* Header */}
        <div className="border-b border-red-400/30 bg-red-400/5 p-4 font-mono sticky top-0 z-10">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="text-red-400 text-sm font-bold">
                [SHELL:CONFIG]$ configure_reverse_shell.sh
              </span>
            </div>
            <button
              onClick={onCancel}
              className="text-gray-400 hover:text-gray-300 transition-colors px-2 py-1 border border-gray-500/50 min-w-[40px]"
              title="Cancelar"
            >
              [X]
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-4 space-y-4">
          {/* Warning */}
          <div className="bg-yellow-900/20 border border-yellow-400/30 p-3 font-mono text-xs sm:text-sm">
            <div className="text-yellow-400 font-bold mb-2">⚠️ ADVERTENCIA:</div>
            <div className="text-yellow-200 space-y-1">
              <div>• Necesitas una sesión Meterpreter o shell activa previa</div>
              <div>• Esta debe haber sido ejecutada mediante un exploit en una instrucción anterior</div>
              <div>• El listener se creará en una sesión tmux en background</div>
            </div>
          </div>

          {/* Instructions */}
          <div className="bg-gray-900/50 border border-gray-700/50 p-3 font-mono text-xs sm:text-sm">
            <div className="text-cyan-300 mb-2">🎯 CONFIGURACIÓN DE REVERSE SHELL:</div>
            <div className="text-gray-400 space-y-1">
              <div>1. Especifica tu IP (LHOST) donde recibirás la conexión</div>
              <div>2. Configura el puerto del listener (LPORT)</div>
              <div>3. Selecciona el sistema operativo de la víctima</div>
              <div>4. O usa detección automática por ping TTL</div>
            </div>
          </div>

          {/* Form Fields */}
          <div className="space-y-4">
            {/* LHOST */}
            <div>
              <label className="block text-sm font-mono text-green-400 mb-2">
                Tu IP (LHOST): <span className="text-red-400">*</span>
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={config.lhost}
                  onChange={(e) => setConfig({ ...config, lhost: e.target.value })}
                  placeholder="192.168.56.1"
                  className="flex-1 bg-black/90 text-green-300 p-2 border border-green-400/30 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-green-400/50 placeholder-green-600/50"
                />
                <button
                  onClick={() => {
                    const hint = "Usa el comando 'ip addr' o 'ifconfig' para ver tus interfaces de red";
                    alert(hint);
                  }}
                  className="px-3 py-2 border border-cyan-400/50 bg-cyan-400/10 text-cyan-400 hover:bg-cyan-400/20 font-mono text-sm transition-colors"
                  title="Ayuda"
                >
                  [?]
                </button>
              </div>
            </div>

            {/* LPORT */}
            <div>
              <label className="block text-sm font-mono text-green-400 mb-2">
                Puerto Listener (LPORT): <span className="text-red-400">*</span>
              </label>
              <input
                type="number"
                value={config.lport}
                onChange={(e) => setConfig({ ...config, lport: parseInt(e.target.value) || 4445 })}
                placeholder="4445"
                min="1"
                max="65535"
                className="w-full bg-black/90 text-green-300 p-2 border border-green-400/30 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-green-400/50 placeholder-green-600/50"
              />
            </div>

            {/* OS Type */}
            <div>
              <label className="block text-sm font-mono text-green-400 mb-2">
                Sistema Operativo Víctima: <span className="text-red-400">*</span>
              </label>
              <select
                value={config.os_type}
                onChange={(e) => setConfig({ ...config, os_type: e.target.value })}
                className="w-full bg-black/90 text-green-300 p-2 border border-green-400/30 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-green-400/50"
              >
                <option value="">-- Seleccionar SO --</option>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
              </select>
            </div>

            {/* OS Detection Toggle */}
            <div className="border-t border-gray-700/50 pt-4">
              <button
                onClick={() => setShowOsDetection(!showOsDetection)}
                className="w-full px-4 py-2 border border-purple-400/50 bg-purple-400/10 text-purple-400 hover:bg-purple-400/20 font-mono text-sm transition-colors"
              >
                {showOsDetection ? '[-] Ocultar Detección de SO' : '[+] No conozco el SO → Detectar por TTL'}
              </button>
            </div>

            {/* OS Detection Panel */}
            {showOsDetection && (
              <div className="bg-purple-900/20 border border-purple-400/30 p-4 space-y-3">
                <div className="text-purple-300 font-mono text-sm font-bold">
                  🔍 DETECCIÓN DE SO POR PING TTL
                </div>
                <div className="text-gray-400 font-mono text-xs space-y-1">
                  <div>• Windows típicamente usa TTL=128 (rango 120-130)</div>
                  <div>• Linux típicamente usa TTL=64 (rango 60-65)</div>
                  <div>• Requiere que la víctima responda a ICMP</div>
                </div>

                <div>
                  <label className="block text-sm font-mono text-purple-300 mb-2">
                    IP Víctima a Analizar:
                  </label>
                  <input
                    type="text"
                    value={targetIp}
                    onChange={(e) => setTargetIp(e.target.value)}
                    placeholder="192.168.56.6"
                    className="w-full bg-black/90 text-purple-300 p-2 border border-purple-400/30 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-purple-400/50 placeholder-purple-600/50"
                  />
                </div>

                {detectionError && (
                  <div className="text-yellow-400 font-mono text-xs bg-yellow-900/20 border border-yellow-400/30 p-2">
                    ⚠️ {detectionError}
                  </div>
                )}

                <button
                  onClick={handleDetectOS}
                  disabled={!targetIp.trim() || detecting}
                  className="w-full px-4 py-2 border border-purple-400/50 bg-purple-400/10 text-purple-400 hover:bg-purple-400/20 font-mono text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {detecting ? '[DETECTANDO...]' : '[DETECTAR SO]'}
                </button>
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row justify-end gap-3 pt-4 border-t border-gray-700/50">
            <button
              onClick={onCancel}
              className="px-4 py-3 border border-gray-500 bg-gray-500/10 text-gray-400 hover:bg-gray-500/20 font-mono text-sm transition-colors min-h-[44px]"
            >
              [CANCELAR]
            </button>
            <button
              onClick={handleConfirm}
              disabled={!isFormValid}
              className="px-4 py-3 border border-green-400/50 bg-green-400/10 text-green-400 hover:bg-green-400/20 font-mono text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed min-h-[44px]"
            >
              [CONFIGURAR Y EJECUTAR]
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ShellConfigModal;
