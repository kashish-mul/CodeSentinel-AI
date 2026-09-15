import React, { useState, useEffect } from 'react';
import { 
  Award, 
  CheckCircle2, 
  AlertCircle, 
  RotateCcw, 
  Loader2, 
  HelpCircle,
  FileCode2,
  TrendingUp,
  Percent
} from 'lucide-react';
import { BenchmarkResult } from '../types';

export const BenchmarkView: React.FC = () => {
  const [data, setData] = useState<BenchmarkResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchBenchmark = async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch('/api/evaluation/benchmark');
      if (!resp.ok) throw new Error('Failed to run benchmark suite');
      const res: BenchmarkResult = await resp.json();
      setData(res);
    } catch (err: any) {
      setError(err?.message || 'Error executing benchmark evaluation');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBenchmark();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Evaluation & Detection Benchmarks
            </h1>
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
              Stage 26 Evaluation
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Empirical scientific testing of the static analysis engine against labeled vulnerable and safe code samples.
          </p>
        </div>

        <button
          id="rerun-benchmark-btn"
          onClick={fetchBenchmark}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-semibold border border-slate-700 transition-all cursor-pointer shrink-0"
        >
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCcw className="w-3.5 h-3.5" />}
          <span>Re-run Benchmark Suite</span>
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Metrics Highlights Cards */}
      {data && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Precision */}
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Precision</span>
              <Award className="w-4 h-4 text-emerald-400" />
            </div>
            <p className="text-3xl font-extrabold text-emerald-400 font-mono">
              {(data.precision * 100).toFixed(1)}%
            </p>
            <p className="text-[11px] text-slate-500 font-mono">TP / (TP + FP)</p>
          </div>

          {/* Recall */}
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Recall</span>
              <TrendingUp className="w-4 h-4 text-emerald-400" />
            </div>
            <p className="text-3xl font-extrabold text-emerald-400 font-mono">
              {(data.recall * 100).toFixed(1)}%
            </p>
            <p className="text-[11px] text-slate-500 font-mono">TP / (TP + FN)</p>
          </div>

          {/* F1 Score */}
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>F1 Score</span>
              <Percent className="w-4 h-4 text-indigo-400" />
            </div>
            <p className="text-3xl font-extrabold text-indigo-400 font-mono">
              {data.f1Score.toFixed(3)}
            </p>
            <p className="text-[11px] text-slate-500 font-mono">Harmonic mean P & R</p>
          </div>

          {/* Accuracy */}
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Overall Accuracy</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            </div>
            <p className="text-3xl font-extrabold text-white font-mono">
              {(data.accuracy * 100).toFixed(1)}%
            </p>
            <p className="text-[11px] text-slate-500 font-mono">
              {data.truePositives + data.trueNegatives} / {data.totalSamples} correct
            </p>
          </div>
        </div>
      )}

      {/* Confusion Matrix Breakdown */}
      {data && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-white">Empirical Confusion Matrix</h2>
              <p className="text-xs text-slate-400">Classification outcomes across vulnerable and safe ground truth samples</p>
            </div>
            <span className="text-xs font-mono text-slate-400">{data.totalSamples} Labeled Test Cases</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center font-mono">
            <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-900/40">
              <span className="text-xs text-emerald-400 font-semibold block">True Positives (TP)</span>
              <p className="text-2xl font-bold text-emerald-300 mt-1">{data.truePositives}</p>
              <p className="text-[10px] text-slate-400 mt-0.5">Vulnerable code detected</p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-xs text-emerald-400 font-semibold block">True Negatives (TN)</span>
              <p className="text-2xl font-bold text-emerald-300 mt-1">{data.trueNegatives}</p>
              <p className="text-[10px] text-slate-400 mt-0.5">Safe code correctly passed</p>
            </div>

            <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-900/40">
              <span className="text-xs text-rose-400 font-semibold block">False Positives (FP)</span>
              <p className="text-2xl font-bold text-rose-400 mt-1">{data.falsePositives}</p>
              <p className="text-[10px] text-slate-400 mt-0.5">Safe code falsely flagged</p>
            </div>

            <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-900/40">
              <span className="text-xs text-rose-400 font-semibold block">False Negatives (FN)</span>
              <p className="text-2xl font-bold text-rose-400 mt-1">{data.falseNegatives}</p>
              <p className="text-[10px] text-slate-400 mt-0.5">Missed vulnerabilities</p>
            </div>
          </div>
        </div>
      )}

      {/* Detailed Benchmark Dataset Table */}
      {data && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-white">Curated Evaluation Test Cases</h2>
            <span className="text-xs text-slate-400 font-mono">Python, JavaScript & TypeScript</span>
          </div>

          <div className="space-y-3">
            {data.detailedResults.map((sample) => (
              <div 
                key={sample.id}
                className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-2.5"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                      sample.status === 'CORRECT' 
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' 
                        : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                    }`}>
                      {sample.status}
                    </span>
                    <h3 className="text-xs font-bold text-white">{sample.name}</h3>
                    <span className="text-[11px] font-mono text-slate-400">({sample.language})</span>
                  </div>

                  <div className="flex items-center gap-2 text-[11px] font-mono">
                    <span className="text-slate-400">Ground Truth:</span>
                    <span className={sample.groundTruth === 'VULNERABLE' ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                      {sample.groundTruth}
                    </span>
                    <span className="text-slate-600">|</span>
                    <span className="text-slate-400">Predicted:</span>
                    <span className={sample.predicted === 'VULNERABLE' ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                      {sample.predicted}
                    </span>
                  </div>
                </div>

                <pre className="p-3 rounded-lg bg-slate-900/90 border border-slate-800/60 font-mono text-[11px] text-slate-300 overflow-x-auto">
                  <code>{sample.snippet}</code>
                </pre>

                {sample.detectedVulnerabilities.length > 0 && (
                  <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span>Flagged Rule: {sample.detectedVulnerabilities.join(', ')}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
