import { useState, useEffect, useRef, useCallback } from "react";
import { createPortal } from "react-dom";

interface ModelProfile {
    id: string;
    name: string;
    model: string;
    description: string;
    size_gb: number;
    thinking: boolean;
    temperature: number;
    num_predict: number;
    is_downloaded: boolean;
    is_loaded: boolean;
    is_active: boolean;
}

interface ModelsResponse {
    models: ModelProfile[];
    active_profile: string;
}

interface ModelSelectorProps {
    apiBaseUrl: string;
    disabled?: boolean;
    onModelChanged?: (model: string) => void;
}

export default function ModelSelector({
    apiBaseUrl,
    disabled = false,
    onModelChanged,
}: ModelSelectorProps) {
    const [open, setOpen] = useState(false);
    const [models, setModels] = useState<ModelProfile[]>([]);
    const [activeProfile, setActiveProfile] = useState<string>("");
    const [loading, setLoading] = useState(false);
    const [switching, setSwitching] = useState(false);
    const [switchingId, setSwitchingId] = useState<string>("");
    const [error, setError] = useState<string | null>(null);
    const [dropdownPos, setDropdownPos] = useState({ top: 0, right: 0 });

    const [pullConfirm, setPullConfirm] = useState<{ profile: ModelProfile } | null>(null);

    const buttonRef = useRef<HTMLButtonElement>(null);

    const fetchModels = useCallback(async () => {
        setLoading(true);
        try {
            const res = await fetch(`${apiBaseUrl}/llm/models`);
            if (!res.ok) throw new Error("Failed to fetch models");
            const data: ModelsResponse = await res.json();
            setModels(data.models);
            setActiveProfile(data.active_profile);
        } catch (e) {
            console.error("Error fetching LLM models:", e);
        } finally {
            setLoading(false);
        }
    }, [apiBaseUrl]);

    useEffect(() => {
        fetchModels();
    }, [fetchModels]);

    // Close on outside click
    useEffect(() => {
        if (!open) return;
        const handleClickOutside = (e: MouseEvent) => {
            if (buttonRef.current && !buttonRef.current.contains(e.target as Node)) {
                // Check if click is inside the portal dropdown
                const portal = document.getElementById("model-selector-portal");
                if (portal && portal.contains(e.target as Node)) return;
                setOpen(false);
            }
        };
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, [open]);

    const handleToggle = () => {
        if (!open) {
            // Calculate position from button
            if (buttonRef.current) {
                const rect = buttonRef.current.getBoundingClientRect();
                setDropdownPos({
                    top: rect.bottom + window.scrollY + 8,
                    right: window.innerWidth - rect.right,
                });
            }
            fetchModels();
        }
        setOpen((v) => !v);
    };

    const doSwitch = async (profile: ModelProfile, confirmPull = false) => {
        setError(null);
        setSwitching(true);
        setSwitchingId(profile.id);
        try {
            const res = await fetch(`${apiBaseUrl}/llm/switch`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    profile_id: profile.id,
                    confirm_pull: confirmPull,
                }),
            });

            const data = await res.json();

            if (res.status === 202 && data.needs_pull) {
                setPullConfirm({ profile });
                return;
            }

            if (!res.ok) throw new Error(data.detail || `Error ${res.status}`);

            setActiveProfile(data.profile);
            await fetchModels();
            setOpen(false);
            onModelChanged?.(data.model);
        } catch (e) {
            const msg = e instanceof Error ? e.message : "Error desconocido";
            console.error("Error switching model:", msg);
            setError(msg);
        } finally {
            setSwitching(false);
            setSwitchingId("");
        }
    };

    const handleConfirmPull = async () => {
        if (!pullConfirm) return;
        const profile = pullConfirm.profile;
        setPullConfirm(null);
        await doSwitch(profile, true);
    };

    const activeModel = models.find((m) => m.is_active);
    const displayName = activeModel?.name ?? activeProfile ?? "—";

    return (
        <>
            {/* ── Trigger button ───────────────────────────────────── */}
            <button
                ref={buttonRef}
                onClick={handleToggle}
                disabled={switching}
                title="Cambiar modelo LLM"
                className={`
                    flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium
                    border transition-all duration-200 select-none
                    ${switching
                        ? "opacity-50 cursor-not-allowed border-gray-700 bg-gray-900 text-gray-500"
                        : disabled
                            ? "border-gray-700/60 bg-gray-900/60 text-gray-400 hover:border-cyan-600 hover:text-cyan-400 cursor-pointer"
                            : "border-gray-600 bg-gray-900 text-gray-200 hover:border-cyan-500 hover:text-cyan-400 hover:bg-gray-800 cursor-pointer"
                    }
                `}
            >
                <svg
                    className={`w-4 h-4 flex-shrink-0 ${switching ? "animate-spin text-cyan-400" : ""}`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                >
                    {switching ? (
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                            d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    ) : (
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                            d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" />
                    )}
                </svg>
                <span className="max-w-[120px] truncate">
                    {switching ? "Cargando..." : displayName}
                </span>
                <svg
                    className={`w-3 h-3 transition-transform duration-200 ${open ? "rotate-180" : ""}`}
                    fill="none" stroke="currentColor" viewBox="0 0 24 24"
                >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
            </button>

            {/* ── Dropdown — rendered via Portal at body level ──────── */}
            {open && createPortal(
                <div
                    id="model-selector-portal"
                    style={{
                        position: "fixed",
                        top: dropdownPos.top,
                        right: dropdownPos.right,
                        zIndex: 9999,
                        width: "320px",
                    }}
                >
                    <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl overflow-hidden">
                        {/* Header */}
                        <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
                            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                                Modelos disponibles
                            </span>
                            {loading && (
                                <svg className="w-3.5 h-3.5 animate-spin text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                        d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                </svg>
                            )}
                        </div>

                        {/* Error banner */}
                        {error && (
                            <div className="px-4 py-2 bg-red-950/60 border-b border-red-800/50 flex items-start gap-2">
                                <span className="text-red-400 text-xs mt-0.5 flex-shrink-0">✕</span>
                                <span className="text-red-300 text-xs leading-snug">{error}</span>
                                <button onClick={() => setError(null)} className="ml-auto text-red-400 hover:text-red-200 text-xs flex-shrink-0">✕</button>
                            </div>
                        )}

                        {/* Model list */}
                        <div className="max-h-96 overflow-y-auto divide-y divide-gray-800">
                            {models.length === 0 && !loading && (
                                <div className="px-4 py-6 text-center text-sm text-gray-500">
                                    No hay perfiles de modelos configurados
                                </div>
                            )}

                            {models.map((m) => {
                                const isSwitchingThis = switching && switchingId === m.id;
                                return (
                                    <button
                                        key={m.id}
                                        onClick={() => !m.is_active && !switching && doSwitch(m)}
                                        disabled={m.is_active || switching}
                                        className={`
                                            w-full text-left px-4 py-3 transition-all duration-150
                                            ${m.is_active
                                                ? "bg-cyan-950/40 cursor-default"
                                                : switching
                                                    ? "opacity-50 cursor-not-allowed"
                                                    : "hover:bg-gray-800 cursor-pointer"
                                            }
                                        `}
                                    >
                                        <div className="flex items-start justify-between gap-2">
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2 mb-0.5">
                                                    <span className={`text-sm font-semibold truncate ${m.is_active ? "text-cyan-400" : "text-gray-200"}`}>
                                                        {m.name}
                                                    </span>
                                                    {m.is_active && (
                                                        <span className="flex-shrink-0 text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                                                            ACTIVO
                                                        </span>
                                                    )}
                                                    {isSwitchingThis && (
                                                        <svg className="w-3.5 h-3.5 animate-spin text-cyan-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                                                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                                        </svg>
                                                    )}
                                                </div>
                                                <div className="text-[11px] text-gray-500 font-mono mb-1 truncate">{m.model}</div>
                                                <div className="text-xs text-gray-400 leading-snug">{m.description}</div>
                                            </div>
                                            <div className="flex flex-col items-end gap-1 flex-shrink-0 ml-2">
                                                <span className="text-[11px] text-gray-500">{m.size_gb} GB</span>
                                                {m.is_downloaded ? (
                                                    m.is_loaded ? (
                                                        <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-400 border border-green-500/25">En RAM</span>
                                                    ) : (
                                                        <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-blue-500/15 text-blue-400 border border-blue-500/25">Descargado</span>
                                                    )
                                                ) : (
                                                    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-gray-700/60 text-gray-500 border border-gray-600/40">No descargado</span>
                                                )}
                                                {m.thinking && (
                                                    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-purple-500/15 text-purple-400 border border-purple-500/25">Thinking</span>
                                                )}
                                            </div>
                                        </div>
                                    </button>
                                );
                            })}
                        </div>
                    </div>
                </div>,
                document.body
            )}

            {/* ── Pull confirmation modal — also via Portal ─────────── */}
            {pullConfirm && createPortal(
                <div className="fixed inset-0 z-[10000] flex items-center justify-center bg-black/70 backdrop-blur-sm">
                    <div className="bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl max-w-sm w-full mx-4 p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <div className="w-10 h-10 rounded-full bg-amber-500/20 flex items-center justify-center flex-shrink-0">
                                <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                        d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                </svg>
                            </div>
                            <div>
                                <h3 className="text-sm font-semibold text-gray-100">Descargar modelo</h3>
                                <p className="text-xs text-gray-400">{pullConfirm.profile.name}</p>
                            </div>
                        </div>
                        <p className="text-sm text-gray-300 mb-6 leading-relaxed">
                            Este modelo <span className="font-semibold text-gray-100">no está descargado</span> localmente.
                            Ocupará aproximadamente <span className="font-semibold text-amber-400">{pullConfirm.profile.size_gb} GB</span>. ¿Descargar ahora?
                        </p>
                        <div className="text-xs text-gray-500 font-mono bg-gray-800/60 rounded-lg px-3 py-2 mb-5">
                            ollama pull {pullConfirm.profile.model}
                        </div>
                        <div className="flex gap-3">
                            <button
                                onClick={() => setPullConfirm(null)}
                                className="flex-1 px-4 py-2 rounded-lg border border-gray-600 text-sm text-gray-300 hover:bg-gray-800 transition-colors"
                            >
                                Cancelar
                            </button>
                            <button
                                onClick={handleConfirmPull}
                                className="flex-1 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-sm font-semibold text-white transition-colors"
                            >
                                Descargar y cambiar
                            </button>
                        </div>
                    </div>
                </div>,
                document.body
            )}
        </>
    );
}
