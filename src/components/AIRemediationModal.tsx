import React, { useState, useEffect } from 'react';
import { 
  X, 
  Sparkles, 
  ShieldAlert, 
  Check, 
  Copy, 
  Loader2, 
  AlertTriangle, 
  ArrowRight,
  Code2
} from 'lucide-react';
import { Finding, AIRemediation } from '../types';

interface AIRemediationModalProps {
  finding: Finding | null;
  isOpen: boolean;
  onClose: () => void;
}

export const AIRemediationModal: React.FC<AIRemediationModalProps> = ({
  finding,
  isOpen,
  onClose,
}) => {
  const [remediation, setRemediation] = useState<AIRemediation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedPatch, setCopiedPatch] = useState(false);

  useEffect(() => {
    if (isOpen && finding) {
      fetchRemediation(finding);
    } else {
      setRemediation(null);
      setError(null);
    }
  }, [isOpen, finding]);

  const fetchRemediation = async (f: Finding) => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch('/api/ai/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding: f }),
      });

      if (!resp.ok) {
        throw new Error('Failed to generate AI remediation');
      }

      const data: AIRemediation = await resp.json();
      setRemediation(data);
    } catch (err: any) {
      setError(err?.message || 'Could not contact Gemini AI service.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyPatch = () => {
    if (!remediation) return;
    navigator.clipboard.writeText(remediation.remediatedCode);
    setCopiedPatch(true);
    setTimeout(() => setCopiedPatch(false), 2000);
  };

  if (!isOpen || !finding) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div 
        id="ai-remediation-dialog"
        className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl p-6 sm:p-8 space-y-6"
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 to-emerald-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
              <Sparkles className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base sm:text-lg font-bold text-white">AI Security Remediation</h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                  Gemini 3.8 Flash
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5 truncate max-w-md">
                {finding.title} • {finding.filePath}:{finding.lineNumber}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Loading State */}
        {loading && (
          <div className="py-16 text-center space-y-3">
            <Loader2 className="w-8 h-8 text-emerald-400 animate-spin mx-auto" />
            <h3 className="text-sm font-semibold text-white">Generating Context-Aware Remediation...</h3>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              Analyzing code context, CWE classification, and synthesizing a production-ready patch.
            </p>
          </div>
        )}

        {/* Error State */}
        {error && !loading && (
          <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 flex items-center gap-3 text-xs text-rose-300">
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Content Body */}
        {remediation && !loading && (
          <div className="space-y-6">
            {/* 1. What is wrong? */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <span className="text-[11px] font-mono uppercase tracking-wider text-indigo-400 font-semibold block">
                1. Root Cause & Problem Explanation
              </span>
              <p className="text-xs text-slate-200 leading-relaxed font-sans">
                {remediation.problemExplanation}
              </p>
            </div>

            {/* 2. Why is it dangerous? */}
            <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-900/30 space-y-1.5">
              <div className="flex items-center gap-1.5 text-rose-400 text-xs font-semibold">
                <ShieldAlert className="w-4 h-4" />
                <span>2. Security Impact & Threat Vector</span>
              </div>
              <p className="text-xs text-rose-200/90 leading-relaxed">
                {remediation.securityImpact}
              </p>
            </div>

            {/* 3. How to fix it (Step by Step) */}
            <div className="space-y-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold block">
                3. Step-by-Step Remediation Plan
              </span>
              <div className="space-y-2">
                {remediation.stepByStepFix.map((step, idx) => (
                  <div key={idx} className="flex items-start gap-2.5 text-xs text-slate-300">
                    <span className="w-5 h-5 rounded-full bg-slate-800 text-emerald-400 border border-slate-700 flex items-center justify-center text-[10px] font-mono shrink-0 mt-0.5">
                      {idx + 1}
                    </span>
                    <span className="leading-relaxed">{step}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* 4. Before vs After Code Diff */}
            <div className="space-y-3 pt-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
                  <Code2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>4. Before vs. Remediated Code</span>
                </span>
                <button
                  onClick={handleCopyPatch}
                  className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 text-xs font-medium border border-emerald-500/30 transition-all cursor-pointer"
                >
                  {copiedPatch ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>Copied Patch</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy Remediated Code</span>
                    </>
                  )}
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {/* Before (Vulnerable) */}
                <div className="space-y-1">
                  <span className="text-[10px] font-mono text-rose-400 uppercase tracking-wide">
                    Original Vulnerable Snippet
                  </span>
                  <pre className="p-3.5 rounded-xl bg-slate-950 border border-rose-900/40 text-[11px] font-mono text-rose-300 overflow-x-auto h-36">
                    <code>{finding.codeSnippet}</code>
                  </pre>
                </div>

                {/* After (Remediated) */}
                <div className="space-y-1">
                  <span className="text-[10px] font-mono text-emerald-400 uppercase tracking-wide">
                    Remediated Secure Approach
                  </span>
                  <pre className="p-3.5 rounded-xl bg-slate-950 border border-emerald-900/40 text-[11px] font-mono text-emerald-300 overflow-x-auto h-36">
                    <code>{remediation.remediatedCode}</code>
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Footer Actions */}
        <div className="pt-4 border-t border-slate-800 flex justify-between items-center text-xs">
          <span className="text-slate-500 font-mono text-[11px]">
            Model: {remediation?.modelUsed || 'gemini-3.8-flash'}
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
