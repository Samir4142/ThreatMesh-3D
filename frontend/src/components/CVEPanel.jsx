const SEVERITY_COLORS = {
    CRITICAL: 'text-red-500 bg-red-500/10 border-red-500/30',
    HIGH: 'text-orange-500 bg-orange-500/10 border-orange-500/30',
    MEDIUM: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30',
    LOW: 'text-green-500 bg-green-500/10 border-green-500/30',
    UNKNOWN: 'text-neutral-500 bg-neutral-500/10 border-neutral-500/30',
}

const CONFIDENCE_COLORS = {
    High: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    Medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    Low: 'text-red-400 bg-red-500/10 border-red-500/20',
}

const EVIDENCE_COLORS = {
    Direct: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    Inferred: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
}

export default function CVEPanel({ cve, onClose }) {
    const severityClass = SEVERITY_COLORS[cve.severity] || SEVERITY_COLORS.UNKNOWN

    return (
        <div className="h-full bg-neutral-950 flex flex-col">

            {/* Panel Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-neutral-800">
                <span className="text-xs text-neutral-500 font-mono uppercase tracking-widest">
                    Cve Detail
                </span>
                <button
                    onClick={onClose}
                    className="text-neutral-500 hover:text-white text-lg leading-none"
                >
                    ✕
                </button>
            </div>

            {/* Panel Content */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">

                {/* Cve Id */}
                <div>
                    <p className="text-xs text-neutral-500 mb-1">Cve Id</p>
                    <p className="text-emerald-400 font-mono text-sm font-bold">
                        {cve.id}
                    </p>
                </div>

                {/* Severity Plus Score */}
                <div className="flex gap-3">
                    <div className="flex-1">
                        <p className="text-xs text-neutral-500 mb-1">Severity</p>
                        <span className={`text-xs font-bold px-2 py-1 rounded border ${severityClass}`}>
                            {cve.severity}
                        </span>
                    </div>
                    <div className="flex-1">
                        <p className="text-xs text-neutral-500 mb-1">Cvss Score</p>
                        <p className="text-white font-mono text-sm font-bold">
                            {cve.score || 'N/A'}
                        </p>
                    </div>
                </div>

                {/* Published Date */}
                <div>
                    <p className="text-xs text-neutral-500 mb-1">Published</p>
                    <p className="text-neutral-300 text-xs font-mono">
                        {cve.published && cve.published !== 'Unknown'
                            ? new Date(cve.published).toLocaleDateString('en-US', {
                                year: 'numeric', month: 'long', day: 'numeric'
                            })
                            : 'Unknown'}
                    </p>
                </div>

                {/* Description Text */}
                <div>
                    <p className="text-xs text-neutral-500 mb-1">Description</p>
                    <p className="text-neutral-300 text-xs leading-relaxed">
                        {cve.description}
                    </p>
                </div>

                {/* Extracted Attack Vector Facts */}
                {cve.attack_vector && (
                    <div>
                        <p className="text-xs text-neutral-500 mb-1">Attack Vector</p>
                        <p className="text-neutral-300 text-xs">
                            {cve.attack_vector}
                        </p>
                    </div>
                )}

                {/* Mitigation Recommendation */}
                {cve.mitigation && (
                    <div>
                        <p className="text-xs text-neutral-500 mb-1">Mitigation</p>
                        <p className="text-neutral-300 text-xs">
                            {cve.mitigation}
                        </p>
                    </div>
                )}

                {/* Vendor And Product Component Stacks */}
                <div className="flex gap-3">
                    <div className="flex-1">
                        <p className="text-xs text-neutral-500 mb-1">Vendor Provider</p>
                        <p className="text-neutral-300 text-xs font-mono capitalize">
                            {cve.vendor || 'Unknown'}
                        </p>
                    </div>
                    <div className="flex-1">
                        <p className="text-xs text-neutral-500 mb-1">Product Component</p>
                        <p className="text-neutral-300 text-xs font-mono capitalize">
                            {cve.product || 'Unknown'}
                        </p>
                    </div>
                </div>

                {/* Multi-Technique Attack Chain Block */}
                {cve.all_techniques && cve.all_techniques.length > 0 ? (
                    <div className="space-y-3 border-t border-neutral-800 pt-3 mt-3">

                        <div className="flex items-center justify-between">
                            <p className="text-xs text-neutral-500 mb-1 font-mono uppercase tracking-widest">
                                Attack Chain
                            </p>

                            {cve.verified && (
                                <span
                                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${cve.verification_verdict === 'revise'
                                        ? 'text-orange-400 bg-orange-500/10 border-orange-500/20'
                                        : 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20'
                                        }`}
                                >
                                    {cve.verification_verdict === 'revise'
                                        ? 'Revised By Verifier'
                                        : 'Verifier Confirmed'}
                                </span>
                            )}
                        </div>

                        {cve.all_techniques.map((tech, idx) => (
                            <div
                                key={idx}
                                className="bg-neutral-900/50 p-3 rounded border border-neutral-800"
                            >
                                <div className="flex justify-between items-start mb-2">
                                    <span className="text-emerald-400 font-mono text-xs font-bold">
                                        {tech.technique_id}
                                    </span>

                                    {/* Confidence Plus Evidence Type — Both Halves Of needs_verification() Visible */}
                                    <div className="flex gap-1">
                                        <span
                                            className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${CONFIDENCE_COLORS[tech.confidence] || 'text-neutral-400 bg-neutral-500/10 border-neutral-500/20'
                                                }`}
                                        >
                                            {tech.confidence || "Unknown"}
                                        </span>

                                        <span
                                            className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${EVIDENCE_COLORS[tech.evidence_type] || 'text-neutral-400 bg-neutral-500/10 border-neutral-500/20'
                                                }`}
                                        >
                                            {tech.evidence_type || "Unknown"}
                                        </span>
                                    </div>
                                </div>

                                <p className="text-neutral-300 text-xs mb-2 font-bold">
                                    {tech.technique_name}
                                </p>

                                <p className="text-neutral-400 text-xs italic">
                                    "{tech.evidence}"
                                </p>
                            </div>
                        ))}
                    </div>
                ) : (
                    // Fallback Block For Unverified Items
                    <div className="space-y-3 border-t border-neutral-800 pt-3 mt-3">
                        <p className="text-xs text-neutral-500 mb-1 font-mono uppercase tracking-widest">
                            Att&ck Mapping
                        </p>
                        <p className="text-neutral-400 text-xs italic">
                            {cve.evidence || "Insufficient Data To Confidently Map Att&ck Behavior"}
                        </p>
                    </div>
                )}


            </div>
        </div>
    )
}
