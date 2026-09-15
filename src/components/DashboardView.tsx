import React from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  ArrowUpRight, 
  FileCode2, 
  Sparkles, 
  Play, 
  TrendingUp,
  Clock,
  Layers
} from 'lucide-react';
import { Scan, Finding } from '../types';

interface DashboardViewProps {
  scans: Scan[];
  activeScan: Scan | null;
  onSelectScan: (scan: Scan) => void;
  onStartNewScan: () => void;
  onOpenFindingRemediation: (finding: Finding) => void;
  onOpenReportModal: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  scans,
  activeScan,
  onSelectScan,
  onStartNewScan,
  onOpenFindingRemediation,
  onOpenReportModal,
}) => {
  const currentScan = activeScan || scans[0];

  // Aggregate statistics across all scans
  const totalScans = scans.length;
  const uniqueRepos = new Set(scans.map(s => s.repositoryName)).size;
  const totalCriticalIssues = scans.reduce((acc, s) => acc + (s.severityCounts?.critical || 0), 0);
  const totalHighIssues = scans.reduce((acc, s) => acc + (s.severityCounts?.high || 0), 0);
  const averageScore = scans.length > 0 
    ? Math.round(scans.reduce((acc, s) => acc + (s.scores?.overall || 0), 0) / scans.length) 
    : 85;

  const scores = currentScan?.scores || {
    overall: 82,
    security: 75,
    quality: 88,
    maintainability: 84,
    documentation: 70,
  };

  const counts = currentScan?.severityCounts || {
    critical: 1,
    high: 3,
    medium: 7,
    low: 12,
    info: 2,
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
    if (score >= 60) return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
    return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
  };

  const getScoreBar = (score: number) => {
    if (score >= 80) return 'bg-emerald-500';
    if (score >= 60) return 'bg-amber-500';
    return 'bg-rose-500';
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Hero Summary */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-indigo-950/40 border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">Security & Quality Control Center</h1>
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-medium border border-emerald-500/30">
              Active Monitoring
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Real-time static code analysis, vulnerability correlation, and AI-driven remediation pipeline.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            id="quick-new-scan-btn"
            onClick={onStartNewScan}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-lg shadow-emerald-900/20 transition-all cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Analyze Repository</span>
          </button>
          <button
            id="dashboard-export-report-btn"
            onClick={onOpenReportModal}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-all cursor-pointer"
          >
            <ArrowUpRight className="w-3.5 h-3.5" />
            <span>Download Audit Report</span>
          </button>
        </div>
      </div>

      {/* Aggregate Stat Metrics Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div id="metric-repositories" className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/90">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Repositories</span>
            <Layers className="w-4 h-4 text-indigo-400" />
          </div>
          <p className="text-2xl font-bold text-white font-mono mt-2">{uniqueRepos}</p>
          <p className="text-[11px] text-slate-500 mt-1">Tracked codebases</p>
        </div>

        <div id="metric-total-scans" className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/90">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Total Scans</span>
            <TrendingUp className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold text-white font-mono mt-2">{totalScans}</p>
          <p className="text-[11px] text-slate-500 mt-1">Automated AST & rule passes</p>
        </div>

        <div id="metric-critical-issues" className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/90">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Critical Issues</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <p className="text-2xl font-bold text-rose-400 font-mono mt-2">{totalCriticalIssues}</p>
          <p className="text-[11px] text-rose-500/80 mt-1">Immediate action required</p>
        </div>

        <div id="metric-average-score" className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/90">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Average Health</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold text-white font-mono mt-2">{averageScore}<span className="text-xs text-slate-500 font-sans">/100</span></p>
          <p className="text-[11px] text-emerald-500/80 mt-1">Weighted composite score</p>
        </div>
      </div>

      {/* Active Scan Health & Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Overall Score Dial / Card */}
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Target Repository</span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                {currentScan?.sourceType || 'SAMPLE'}
              </span>
            </div>
            <h2 className="text-lg font-bold text-white mt-1 truncate">{currentScan?.repositoryName || 'ecommerce-backend-api'}</h2>
            <p className="text-xs text-slate-400 flex items-center gap-1.5 mt-1 font-mono">
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              <span>Scanned {currentScan ? new Date(currentScan.startedAt).toLocaleTimeString() : 'Recently'}</span>
              <span>•</span>
              <span>{currentScan?.totalFilesAnalyzed || 0} files</span>
            </p>
          </div>

          <div className="my-6 flex items-center justify-center">
            <div className={`relative w-36 h-36 rounded-full border-4 flex flex-col items-center justify-center shadow-2xl ${getScoreColor(scores.overall)}`}>
              <span className="text-4xl font-extrabold font-mono leading-none tracking-tight">{scores.overall}</span>
              <span className="text-xs text-slate-400 font-medium mt-1">/ 100</span>
              <span className="text-[10px] uppercase font-mono tracking-widest text-slate-300 mt-1">Overall Health</span>
            </div>
          </div>

          {/* Sub Score Bars */}
          <div className="space-y-2.5 pt-2 border-t border-slate-800/80">
            <div>
              <div className="flex justify-between text-xs text-slate-300 mb-1 font-mono">
                <span>Security (40%)</span>
                <span className="font-bold">{scores.security}/100</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all ${getScoreBar(scores.security)}`} style={{ width: `${scores.security}%` }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs text-slate-300 mb-1 font-mono">
                <span>Code Quality (30%)</span>
                <span className="font-bold">{scores.quality}/100</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all ${getScoreBar(scores.quality)}`} style={{ width: `${scores.quality}%` }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs text-slate-300 mb-1 font-mono">
                <span>Maintainability (20%)</span>
                <span className="font-bold">{scores.maintainability}/100</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all ${getScoreBar(scores.maintainability)}`} style={{ width: `${scores.maintainability}%` }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs text-slate-300 mb-1 font-mono">
                <span>Documentation (10%)</span>
                <span className="font-bold">{scores.documentation}/100</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all ${getScoreBar(scores.documentation)}`} style={{ width: `${scores.documentation}%` }} />
              </div>
            </div>
          </div>
        </div>

        {/* Severity Distribution & Findings Breakdown */}
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 lg:col-span-2 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-base font-bold text-white">Vulnerability & Risk Distribution</h2>
                <p className="text-xs text-slate-400">Classified using OWASP Top 10 and CWE standards</p>
              </div>
              <span className="text-xs font-mono text-slate-400">
                {currentScan?.findings?.length || 0} Total Findings
              </span>
            </div>

            {/* Severity Badges Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
              <div className="p-3 rounded-xl bg-rose-950/30 border border-rose-900/40">
                <div className="flex items-center justify-between text-rose-400 text-xs font-semibold">
                  <span>CRITICAL</span>
                  <AlertTriangle className="w-3.5 h-3.5" />
                </div>
                <p className="text-2xl font-bold text-rose-400 font-mono mt-1">{counts.critical}</p>
                <p className="text-[10px] text-rose-400/70">Remote exploits, keys</p>
              </div>

              <div className="p-3 rounded-xl bg-amber-950/30 border border-amber-900/40">
                <div className="flex items-center justify-between text-amber-400 text-xs font-semibold">
                  <span>HIGH</span>
                  <ShieldAlert className="w-3.5 h-3.5" />
                </div>
                <p className="text-2xl font-bold text-amber-400 font-mono mt-1">{counts.high}</p>
                <p className="text-[10px] text-amber-400/70">SQLi, eval, auth flaws</p>
              </div>

              <div className="p-3 rounded-xl bg-indigo-950/30 border border-indigo-900/40">
                <div className="flex items-center justify-between text-indigo-400 text-xs font-semibold">
                  <span>MEDIUM</span>
                  <FileCode2 className="w-3.5 h-3.5" />
                </div>
                <p className="text-2xl font-bold text-indigo-300 font-mono mt-1">{counts.medium}</p>
                <p className="text-[10px] text-indigo-400/70">Weak crypto, complexity</p>
              </div>

              <div className="p-3 rounded-xl bg-slate-800/40 border border-slate-700/50">
                <div className="flex items-center justify-between text-slate-400 text-xs font-semibold">
                  <span>LOW / INFO</span>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                </div>
                <p className="text-2xl font-bold text-slate-300 font-mono mt-1">{counts.low + counts.info}</p>
                <p className="text-[10px] text-slate-400/70">Code smells, docs</p>
              </div>
            </div>

            {/* Top Findings List in Active Scan */}
            <div className="space-y-2">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">High-Priority Findings</span>
              {currentScan?.findings?.slice(0, 3).map((f) => (
                <div
                  key={f.id}
                  className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start justify-between gap-3 hover:border-slate-700 transition-colors"
                >
                  <div className="space-y-1 overflow-hidden">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                        f.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                        f.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                        'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                      }`}>
                        {f.severity}
                      </span>
                      <h4 className="text-xs font-semibold text-white truncate">{f.title}</h4>
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono truncate">
                      {f.filePath}:{f.lineNumber}
                    </p>
                  </div>

                  <button
                    onClick={() => onOpenFindingRemediation(f)}
                    className="shrink-0 flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 text-xs font-medium border border-indigo-500/30 transition-all cursor-pointer"
                  >
                    <Sparkles className="w-3 h-3 text-indigo-400" />
                    <span>Explain with AI</span>
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex justify-end">
            <button
              onClick={() => onSelectScan(currentScan)}
              className="text-xs text-emerald-400 hover:text-emerald-300 font-medium flex items-center gap-1 cursor-pointer"
            >
              <span>Explore all {currentScan?.findings?.length || 0} findings in detail</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-bold text-white">Scan History & Repositories</h3>
            <p className="text-xs text-slate-400">Previous security scans with recorded scores and regression history</p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="pb-3 font-medium">Repository Name</th>
                <th className="pb-3 font-medium">Source Type</th>
                <th className="pb-3 font-medium">Overall Score</th>
                <th className="pb-3 font-medium">Critical / High</th>
                <th className="pb-3 font-medium">Files</th>
                <th className="pb-3 font-medium">Scan Time</th>
                <th className="pb-3 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {scans.map((scan) => {
                const isCurrent = currentScan?.id === scan.id;
                return (
                  <tr 
                    key={scan.id} 
                    className={`hover:bg-slate-800/40 transition-colors ${isCurrent ? 'bg-slate-800/20' : ''}`}
                  >
                    <td className="py-3.5 font-sans font-semibold text-slate-200">
                      <div className="flex items-center gap-2">
                        <span>{scan.repositoryName}</span>
                        {isCurrent && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            Active
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 text-slate-400">{scan.sourceType}</td>
                    <td className="py-3.5">
                      <span className={`px-2 py-0.5 rounded font-bold ${
                        scan.scores.overall >= 80 ? 'text-emerald-400 bg-emerald-500/10' :
                        scan.scores.overall >= 60 ? 'text-amber-400 bg-amber-500/10' : 'text-rose-400 bg-rose-500/10'
                      }`}>
                        {scan.scores.overall}/100
                      </span>
                    </td>
                    <td className="py-3.5">
                      <span className="text-rose-400 font-bold">{scan.severityCounts.critical}</span>
                      <span className="text-slate-500 mx-1">/</span>
                      <span className="text-amber-400 font-bold">{scan.severityCounts.high}</span>
                    </td>
                    <td className="py-3.5 text-slate-400">{scan.totalFilesAnalyzed}</td>
                    <td className="py-3.5 text-slate-400">{new Date(scan.startedAt).toLocaleTimeString()}</td>
                    <td className="py-3.5 text-right">
                      <button
                        onClick={() => onSelectScan(scan)}
                        className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-sans transition-colors cursor-pointer"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
