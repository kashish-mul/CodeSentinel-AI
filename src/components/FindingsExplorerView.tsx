import React, { useState } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Sparkles, 
  FileCode, 
  Check, 
  Copy, 
  Filter, 
  Search,
  ExternalLink,
  ShieldCheck
} from 'lucide-react';
import { Scan, Finding, Severity, Category } from '../types';

interface FindingsExplorerViewProps {
  activeScan: Scan | null;
  onOpenAIRemediation: (finding: Finding) => void;
}

export const FindingsExplorerView: React.FC<FindingsExplorerViewProps> = ({
  activeScan,
  onOpenAIRemediation,
}) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const findings = activeScan?.findings || [];
  const [activeFindingId, setActiveFindingId] = useState<string>(findings[0]?.id || '');

  // Filter findings
  const filteredFindings = findings.filter((f) => {
    if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;
    if (selectedCategory !== 'ALL' && f.category !== selectedCategory) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.filePath.toLowerCase().includes(q) ||
        f.codeSnippet.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const activeFinding = findings.find(f => f.id === activeFindingId) || filteredFindings[0];

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/30';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30';
      case 'LOW':
        return 'bg-slate-700/30 text-slate-300 border-slate-700/50';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">Security & Quality Findings</h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              {activeScan?.repositoryName || 'Active Scan'}
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Showing {filteredFindings.length} of {findings.length} total findings detected across codebase.
          </p>
        </div>

        {/* Search Bar */}
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search findings, files, lines..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-xs text-white focus:outline-none focus:border-emerald-500 font-mono"
          />
        </div>
      </div>

      {/* Filter Chips Bar */}
      <div className="flex flex-wrap gap-2 items-center p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-xs">
        <span className="text-slate-500 flex items-center gap-1 text-[11px] font-mono mr-1">
          <Filter className="w-3.5 h-3.5" /> Filter:
        </span>

        {/* Severity filter pills */}
        {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => (
          <button
            key={sev}
            onClick={() => setSelectedSeverity(sev)}
            className={`px-2.5 py-1 rounded-lg font-mono text-[11px] transition-all cursor-pointer ${
              selectedSeverity === sev
                ? 'bg-slate-800 text-white font-bold border border-slate-700 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {sev}
          </button>
        ))}

        <div className="h-4 w-px bg-slate-800 mx-1 hidden sm:block" />

        {/* Category filter pills */}
        {(['ALL', 'SECURITY', 'CODE_QUALITY', 'MAINTAINABILITY', 'DOCUMENTATION'] as const).map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-2.5 py-1 rounded-lg font-mono text-[11px] transition-all cursor-pointer ${
              selectedCategory === cat
                ? 'bg-slate-800 text-emerald-400 font-bold border border-slate-700 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {cat.replace('_', ' ')}
          </button>
        ))}
      </div>

      {/* Two Column Layout: Findings List & Deep Inspection Panel */}
      {filteredFindings.length === 0 ? (
        <div className="p-12 text-center rounded-2xl bg-slate-900/60 border border-slate-800">
          <ShieldCheck className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
          <h3 className="text-sm font-bold text-white">No Findings Match Your Filter Criteria</h3>
          <p className="text-xs text-slate-400 mt-1">Try broadening your severity or category filter.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Findings Items List */}
          <div className="lg:col-span-5 space-y-2.5 max-h-[720px] overflow-y-auto pr-1">
            {filteredFindings.map((f) => {
              const isSelected = activeFinding?.id === f.id;
              return (
                <div
                  key={f.id}
                  onClick={() => setActiveFindingId(f.id)}
                  className={`p-3.5 rounded-xl border text-left cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-slate-800/90 border-emerald-500 shadow-lg shadow-emerald-950/20 ring-1 ring-emerald-500/20'
                      : 'bg-slate-900/70 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${getSeverityBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400 uppercase">
                      {f.category.replace('_', ' ')}
                    </span>
                  </div>

                  <h4 className="text-xs font-bold text-white mt-2 leading-snug">{f.title}</h4>
                  <p className="text-[11px] text-slate-400 font-mono mt-1 truncate">
                    {f.filePath}:{f.lineNumber}
                  </p>
                </div>
              );
            })}
          </div>

          {/* Right: Detailed Finding Inspection */}
          {activeFinding && (
            <div className="lg:col-span-7 rounded-2xl bg-slate-900/90 border border-slate-800 p-6 space-y-6 flex flex-col justify-between">
              <div className="space-y-4">
                {/* Header with Severity, Category & Actions */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-mono px-2.5 py-1 rounded font-bold border ${getSeverityBadge(activeFinding.severity)}`}>
                        {activeFinding.severity}
                      </span>
                      {activeFinding.cwe && (
                        <span className="text-[11px] font-mono text-slate-400">
                          {activeFinding.cwe.split(':')[0]}
                        </span>
                      )}
                    </div>
                    <h2 className="text-base sm:text-lg font-bold text-white mt-1">{activeFinding.title}</h2>
                  </div>

                  <button
                    id="explain-with-ai-btn"
                    onClick={() => onOpenAIRemediation(activeFinding)}
                    className="flex items-center justify-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-indigo-600 to-emerald-600 hover:from-indigo-500 hover:to-emerald-500 text-white text-xs font-bold shadow-lg shadow-indigo-950/40 transition-all cursor-pointer shrink-0"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Explain with AI</span>
                  </button>
                </div>

                {/* Location Bar */}
                <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs">
                  <div className="flex items-center gap-2 text-slate-300 truncate">
                    <FileCode className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span className="font-semibold text-white">{activeFinding.filePath}</span>
                    <span className="text-slate-500">at Line {activeFinding.lineNumber}</span>
                  </div>
                  <button
                    onClick={() => handleCopy(`${activeFinding.filePath}:${activeFinding.lineNumber}`, 'loc')}
                    className="text-slate-400 hover:text-white transition-colors"
                    title="Copy location"
                  >
                    {copiedId === 'loc' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>

                {/* Code Snippet Box */}
                <div>
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5 font-mono">
                    <span>Vulnerable Code Snippet</span>
                    <button
                      onClick={() => handleCopy(activeFinding.codeSnippet, 'snippet')}
                      className="flex items-center gap-1 hover:text-white transition-colors"
                    >
                      {copiedId === 'snippet' ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy code</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-4 rounded-xl bg-slate-950 border border-rose-900/30 font-mono text-xs text-rose-200/90 overflow-x-auto border-l-4 border-l-rose-500">
                    <code>{activeFinding.codeSnippet}</code>
                  </pre>
                </div>

                {/* Problem Description & Why It Matters */}
                <div className="space-y-3 pt-2">
                  <div>
                    <h4 className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wider">Problem Summary</h4>
                    <p className="text-xs text-slate-300 mt-1 leading-relaxed">{activeFinding.description}</p>
                  </div>

                  {activeFinding.owaspCategory && (
                    <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                      <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">OWASP Standard Mapping</span>
                      <p className="text-xs font-semibold text-slate-200 mt-0.5">{activeFinding.owaspCategory}</p>
                    </div>
                  )}

                  <div>
                    <h4 className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wider">Static Recommendation</h4>
                    <p className="text-xs text-emerald-400/90 mt-1 leading-relaxed bg-emerald-950/20 p-3 rounded-xl border border-emerald-900/30">
                      {activeFinding.recommendation}
                    </p>
                  </div>
                </div>
              </div>

              {/* Bottom Quick AI Action */}
              <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-slate-500 font-mono">
                  Engine: Static Rule + Gemini 3.8 Flash
                </span>
                <button
                  onClick={() => onOpenAIRemediation(activeFinding)}
                  className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 flex items-center gap-1 cursor-pointer"
                >
                  <span>Generate Full AI Remediation & Secure Patch</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
