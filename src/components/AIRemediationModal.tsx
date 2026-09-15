import React, { useState, useEffect } from 'react';
import { 
  X, 
  Sparkles, 
  ShieldAlert, 
  Check, 
  Copy, 
  Loader2, 
  AlertTriangle, 
  Code2,
  GitCompare,
  Terminal,
  Cpu,
  Send,
  MessageSquare,
  Bot,
  User as UserIcon
} from 'lucide-react';
import { Finding, AIRemediation, CopilotMessage } from '../types';

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
  const [copiedDiff, setCopiedDiff] = useState(false);
  const [diffViewMode, setDiffViewMode] = useState<'side-by-side' | 'unified'>('side-by-side');
  const [activeTab, setActiveTab] = useState<'remediation' | 'copilot'>('remediation');

  // Copilot state
  const [copilotMessages, setCopilotMessages] = useState<CopilotMessage[]>([]);
  const [copilotInput, setCopilotInput] = useState('');
  const [copilotLoading, setCopilotLoading] = useState(false);

  useEffect(() => {
    if (isOpen && finding) {
      fetchRemediation(finding);
      setCopilotMessages([
        {
          id: 'welcome',
          role: 'assistant',
          content: `Hello! I'm CodeSentinel Security Copilot. I'm ready to answer any questions about "${finding.title}" at ${finding.filePath}:${finding.lineNumber}. How can I assist you with this vulnerability?`,
          timestamp: new Date().toISOString(),
        }
      ]);
      setActiveTab('remediation');
    } else {
      setRemediation(null);
      setError(null);
      setCopilotMessages([]);
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
      setError(err?.message || 'Could not contact remediation service.');
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

  const handleCopyDiff = () => {
    if (!remediation?.diffSnippet) return;
    navigator.clipboard.writeText(remediation.diffSnippet);
    setCopiedDiff(true);
    setTimeout(() => setCopiedDiff(false), 2000);
  };

  const handleSendCopilotQuestion = async (customQuestion?: string) => {
    const q = (customQuestion || copilotInput).trim();
    if (!q || !finding || copilotLoading) return;

    const userMsg: CopilotMessage = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: q,
      timestamp: new Date().toISOString(),
    };

    setCopilotMessages(prev => [...prev, userMsg]);
    setCopilotInput('');
    setCopilotLoading(true);

    try {
      const resp = await fetch('/api/copilot/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding,
          question: q,
          history: copilotMessages.map(m => ({ role: m.role, content: m.content })),
        }),
      });

      if (!resp.ok) {
        throw new Error('Copilot could not process request.');
      }

      const data = await resp.json();
      const assistantMsg: CopilotMessage = {
        id: `resp-${Date.now()}`,
        role: 'assistant',
        content: data.answer || 'No answer returned.',
        timestamp: new Date().toISOString(),
      };

      setCopilotMessages(prev => [...prev, assistantMsg]);
    } catch (err: any) {
      const errorMsg: CopilotMessage = {
        id: `err-${Date.now()}`,
        role: 'assistant',
        content: `Error contacting Security Copilot: ${err.message}`,
        timestamp: new Date().toISOString(),
      };
      setCopilotMessages(prev => [...prev, errorMsg]);
    } finally {
      setCopilotLoading(false);
    }
  };

  if (!isOpen || !finding) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-sm animate-in fade-in duration-200">
      <div 
        id="ai-remediation-dialog"
        className="relative w-full max-w-4xl max-h-[92vh] overflow-y-auto rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl p-6 sm:p-8 space-y-6"
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 to-emerald-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
              <Sparkles className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-base sm:text-lg font-bold text-white">AI Remediation Guidance</h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                  Gemini-Assisted
                </span>
                {finding.astNodeType && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 flex items-center gap-1">
                    <Cpu className="w-3 h-3" />
                    AST: {finding.astNodeType}
                  </span>
                )}
                {finding.dependencyInfo && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">
                    SCA: {finding.dependencyInfo.cve}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5 truncate max-w-lg">
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

        {/* Tab Switcher */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
          <button
            onClick={() => setActiveTab('remediation')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              activeTab === 'remediation'
                ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Remediation & Code Patch</span>
          </button>
          <button
            onClick={() => setActiveTab('copilot')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              activeTab === 'copilot'
                ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <MessageSquare className="w-3.5 h-3.5" />
            <span>Security Copilot Chat</span>
            {copilotMessages.length > 1 && (
              <span className="w-4 h-4 rounded-full bg-indigo-500 text-[10px] flex items-center justify-center text-white">
                {copilotMessages.length - 1}
              </span>
            )}
          </button>
        </div>

        {/* TAB 1: Remediation & Code Diff */}
        {activeTab === 'remediation' && (
          <>
            {/* Loading State */}
            {loading && (
              <div className="py-16 text-center space-y-3">
                <Loader2 className="w-8 h-8 text-emerald-400 animate-spin mx-auto" />
                <h3 className="text-sm font-semibold text-white">Analyzing Static Context & Synthesizing Fix...</h3>
                <p className="text-xs text-slate-400 max-w-sm mx-auto">
                  Evaluating AST boundaries, CWE rules, and synthesizing an automated secure code patch.
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
                    1. Root Cause & Technical Breakdown
                  </span>
                  <p className="text-xs text-slate-200 leading-relaxed font-sans">
                    {remediation.problemExplanation}
                  </p>
                </div>

                {/* 2. Security Impact */}
                <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-900/30 space-y-1.5">
                  <div className="flex items-center gap-1.5 text-rose-400 text-xs font-semibold">
                    <ShieldAlert className="w-4 h-4" />
                    <span>2. Security Impact & Threat Assessment</span>
                  </div>
                  <p className="text-xs text-rose-200/90 leading-relaxed">
                    {remediation.securityImpact}
                  </p>
                </div>

                {/* 3. Remediation steps */}
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

                {/* 4. Before vs After Code Diff Viewer */}
                <div className="space-y-3 pt-2">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-2">
                    <div className="flex items-center gap-3">
                      <span className="text-[11px] font-mono uppercase tracking-wider text-slate-300 font-semibold flex items-center gap-1.5">
                        <Code2 className="w-4 h-4 text-emerald-400" />
                        <span>4. Before vs. After Code Comparison</span>
                      </span>

                      {/* View Mode Toggle */}
                      <div className="flex items-center rounded-lg bg-slate-800/80 p-0.5 border border-slate-700/60">
                        <button
                          onClick={() => setDiffViewMode('side-by-side')}
                          className={`px-2 py-0.5 text-[10px] font-medium rounded transition-colors cursor-pointer ${
                            diffViewMode === 'side-by-side' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          Side-by-Side
                        </button>
                        <button
                          onClick={() => setDiffViewMode('unified')}
                          className={`px-2 py-0.5 text-[10px] font-medium rounded transition-colors cursor-pointer ${
                            diffViewMode === 'unified' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          Unified Diff
                        </button>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      {remediation.diffSnippet && (
                        <button
                          onClick={handleCopyDiff}
                          className="flex items-center gap-1 px-2 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-all cursor-pointer"
                        >
                          {copiedDiff ? <Check className="w-3 h-3 text-emerald-400" /> : <GitCompare className="w-3 h-3" />}
                          <span>{copiedDiff ? 'Copied Diff' : 'Copy Diff'}</span>
                        </button>
                      )}
                      <button
                        onClick={handleCopyPatch}
                        className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 text-xs font-medium border border-emerald-500/30 transition-all cursor-pointer"
                      >
                        {copiedPatch ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedPatch ? 'Copied Code' : 'Copy Remediated Code'}</span>
                      </button>
                    </div>
                  </div>

                  {diffViewMode === 'side-by-side' ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {/* Before (Vulnerable) */}
                      <div className="space-y-1">
                        <div className="flex items-center justify-between px-1">
                          <span className="text-[10px] font-mono text-rose-400 uppercase tracking-wide flex items-center gap-1">
                            <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                            Original Vulnerable Code (Line {finding.lineNumber})
                          </span>
                        </div>
                        <pre className="p-3.5 rounded-xl bg-rose-950/20 border border-rose-900/40 text-[11px] font-mono text-rose-300 overflow-x-auto min-h-[120px]">
                          <code>{finding.codeSnippet}</code>
                        </pre>
                      </div>

                      {/* After (Remediated) */}
                      <div className="space-y-1">
                        <div className="flex items-center justify-between px-1">
                          <span className="text-[10px] font-mono text-emerald-400 uppercase tracking-wide flex items-center gap-1">
                            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                            Secure Remediated Pattern
                          </span>
                        </div>
                        <pre className="p-3.5 rounded-xl bg-emerald-950/20 border border-emerald-900/40 text-[11px] font-mono text-emerald-300 overflow-x-auto min-h-[120px]">
                          <code>{remediation.remediatedCode}</code>
                        </pre>
                      </div>
                    </div>
                  ) : (
                    /* Unified Diff View */
                    <div className="space-y-1">
                      <div className="flex items-center justify-between px-1">
                        <span className="text-[10px] font-mono text-indigo-400 uppercase tracking-wide flex items-center gap-1">
                          <Terminal className="w-3 h-3" />
                          Git Unified Patch format ({finding.filePath})
                        </span>
                      </div>
                      <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono overflow-x-auto min-h-[140px] leading-relaxed">
                        <code>
                          {(remediation.diffSnippet || AIServiceDiffFallback(finding.codeSnippet, remediation.remediatedCode, finding.filePath))
                            .split('\n')
                            .map((line, idx) => {
                              let lineStyle = 'text-slate-400';
                              if (line.startsWith('+')) lineStyle = 'text-emerald-400 bg-emerald-950/30 px-1 rounded';
                              if (line.startsWith('-')) lineStyle = 'text-rose-400 bg-rose-950/30 px-1 rounded';
                              if (line.startsWith('@@')) lineStyle = 'text-cyan-400';
                              return (
                                <div key={idx} className={lineStyle}>
                                  {line}
                                </div>
                              );
                            })}
                        </code>
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            )}
          </>
        )}

        {/* TAB 2: Interactive Security Copilot */}
        {activeTab === 'copilot' && (
          <div className="space-y-4">
            {/* Quick Prompts */}
            <div className="space-y-1.5">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold block">
                Suggested Security Inquiries:
              </span>
              <div className="flex flex-wrap gap-2">
                {[
                  'Why is this code pattern dangerous?',
                  'How can an attacker exploit this vulnerability?',
                  'Could this be a false positive?',
                  'Show how to fix this with parameterized statements',
                ].map((promptText, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSendCopilotQuestion(promptText)}
                    disabled={copilotLoading}
                    className="text-xs px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-indigo-300 border border-slate-700/80 transition-all text-left cursor-pointer disabled:opacity-50"
                  >
                    💬 {promptText}
                  </button>
                ))}
              </div>
            </div>

            {/* Conversation Log */}
            <div className="space-y-3 max-h-[380px] overflow-y-auto p-4 rounded-xl bg-slate-950 border border-slate-800">
              {copilotMessages.map(msg => (
                <div
                  key={msg.id}
                  className={`flex gap-3 text-xs ${
                    msg.role === 'user' ? 'justify-end' : 'justify-start'
                  }`}
                >
                  {msg.role === 'assistant' && (
                    <div className="w-6 h-6 rounded-lg bg-gradient-to-tr from-indigo-600 to-emerald-600 flex items-center justify-center shrink-0 mt-1">
                      <Bot className="w-3.5 h-3.5 text-white" />
                    </div>
                  )}
                  <div
                    className={`max-w-[85%] p-3 rounded-xl leading-relaxed ${
                      msg.role === 'user'
                        ? 'bg-indigo-600 text-white'
                        : 'bg-slate-900 border border-slate-800 text-slate-200'
                    }`}
                  >
                    <div className="whitespace-pre-wrap font-sans">{msg.content}</div>
                    <span className="text-[9px] opacity-60 block mt-1">
                      {new Date(msg.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  {msg.role === 'user' && (
                    <div className="w-6 h-6 rounded-lg bg-slate-700 flex items-center justify-center shrink-0 mt-1">
                      <UserIcon className="w-3.5 h-3.5 text-slate-300" />
                    </div>
                  )}
                </div>
              ))}

              {copilotLoading && (
                <div className="flex items-center gap-2 text-xs text-indigo-400 p-2">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Security Copilot is analyzing contextual AST & CWE rules...</span>
                </div>
              )}
            </div>

            {/* Prompt Input Box */}
            <form
              onSubmit={e => {
                e.preventDefault();
                handleSendCopilotQuestion();
              }}
              className="flex items-center gap-2"
            >
              <input
                type="text"
                value={copilotInput}
                onChange={e => setCopilotInput(e.target.value)}
                placeholder="Ask about this finding (e.g., 'How do I test if this is exploitable?')..."
                className="flex-1 px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                disabled={copilotLoading}
              />
              <button
                type="submit"
                disabled={copilotLoading || !copilotInput.trim()}
                className="px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Send</span>
              </button>
            </form>
          </div>
        )}

        {/* Footer Actions */}
        <div className="pt-4 border-t border-slate-800 flex flex-wrap justify-between items-center gap-2 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 text-[11px]">
              Engine: <span className="text-slate-300 font-mono">{remediation?.modelUsed || 'CodeSentinel AST & Gemini'}</span>
            </span>
            <span className="text-slate-600">•</span>
            <span className="text-slate-500 text-[11px]">
              Guidance only; inspect and verify patches prior to production merge.
            </span>
          </div>
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

function AIServiceDiffFallback(original: string, remediated: string, filePath: string): string {
  const origLines = original.trim().split('\n').map(l => `- ${l}`).join('\n');
  const fixLines = remediated.trim().split('\n').map(l => `+ ${l}`).join('\n');
  return `--- a/${filePath}\n+++ b/${filePath}\n@@ -1 +1 @@\n${origLines}\n${fixLines}`;
}
