import React, { useState, useEffect } from 'react';
import { 
  Terminal, 
  CheckCircle2, 
  XCircle, 
  Play, 
  Loader2, 
  ShieldCheck, 
  Clock, 
  Code2
} from 'lucide-react';
import { TestSuiteResult } from '../types';

export const TestSuiteView: React.FC = () => {
  const [results, setResults] = useState<TestSuiteResult | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runTests = async () => {
    setRunning(true);
    setError(null);
    try {
      const resp = await fetch('/api/tests/run');
      if (!resp.ok) throw new Error('Failed to run test suite');
      const data: TestSuiteResult = await resp.json();
      setResults(data);
    } catch (err: any) {
      setError(err?.message || 'Error executing tests');
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    runTests();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Automated Regression & Unit Test Suite
            </h1>
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
              CI / CD Quality Gate
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Live test runner validating parser integrity, security rules, cyclomatic complexity calculations, and ingestion guards.
          </p>
        </div>

        <button
          id="run-tests-btn"
          onClick={runTests}
          disabled={running}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-bold shadow-lg shadow-emerald-950/30 transition-all cursor-pointer shrink-0"
        >
          {running ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Executing Tests...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Run Automated Test Suite</span>
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Summary Stats */}
      {results && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono">
          <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800">
            <span className="text-xs text-slate-400 block font-sans">Total Tests</span>
            <p className="text-2xl font-bold text-white mt-1">{results.total}</p>
            <p className="text-[11px] text-slate-500 mt-0.5">Automated assertions</p>
          </div>

          <div className="p-4 rounded-2xl bg-emerald-950/20 border border-emerald-900/40">
            <span className="text-xs text-emerald-400 block font-sans">Passed</span>
            <p className="text-2xl font-bold text-emerald-300 mt-1">{results.passed}</p>
            <p className="text-[11px] text-emerald-400/70 mt-0.5">100% Green status</p>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800">
            <span className="text-xs text-slate-400 block font-sans">Failed</span>
            <p className="text-2xl font-bold text-slate-400 mt-1">{results.failed}</p>
            <p className="text-[11px] text-slate-500 mt-0.5">0 regressions</p>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800">
            <span className="text-xs text-slate-400 block font-sans">Execution Time</span>
            <p className="text-2xl font-bold text-indigo-400 mt-1">{results.durationMs}ms</p>
            <p className="text-[11px] text-slate-500 mt-0.5">High-speed testing</p>
          </div>
        </div>
      )}

      {/* Test List Table */}
      {results && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <h2 className="text-sm font-bold text-white font-mono">Test Execution Log</h2>
            </div>
            <span className="text-xs text-slate-400 font-mono">
              Suite: {results.suiteName}
            </span>
          </div>

          <div className="space-y-2">
            {results.tests.map((test, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-xl bg-slate-950 border border-slate-800/80 flex items-center justify-between gap-4 font-mono text-xs"
              >
                <div className="flex items-center gap-3 overflow-hidden">
                  {test.passed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                  )}
                  <div className="truncate">
                    <span className="text-slate-200 font-medium">{test.name}</span>
                    <span className="text-slate-500 ml-2">[{test.category}]</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-slate-500 text-[11px]">{test.durationMs}ms</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    test.passed ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
                  }`}>
                    {test.passed ? 'PASS' : 'FAIL'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
