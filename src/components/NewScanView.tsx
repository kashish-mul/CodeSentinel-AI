import React, { useState } from 'react';
import { 
  GitBranch, 
  UploadCloud, 
  FileCode, 
  Play, 
  CheckCircle2, 
  Loader2, 
  AlertCircle,
  FileText,
  ShieldAlert,
  Sparkles
} from 'lucide-react';
import JSZip from 'jszip';
import { Scan } from '../types';

interface NewScanViewProps {
  onScanCompleted: (scan: Scan) => void;
}

type IngestionMode = 'SAMPLE' | 'GITHUB' | 'ZIP' | 'SNIPPET';

export const NewScanView: React.FC<NewScanViewProps> = ({ onScanCompleted }) => {
  const [mode, setMode] = useState<IngestionMode>('SAMPLE');
  const [githubUrl, setGithubUrl] = useState('https://github.com/pallets/flask');
  const [sampleId, setSampleId] = useState('ecommerce-api-vulnerable');
  const [snippetName, setSnippetName] = useState('auth_controller.py');
  const [snippetContent, setSnippetContent] = useState(`import sqlite3
import os

def login_handler(username, password):
    # Potential SQL Injection vulnerability
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    
    # Sensitive hardcoded token
    ADMIN_TOKEN = "sk_live_998811223344"
    
    # Command execution
    os.system("echo User " + username + " logged in >> /var/log/audit.log")
    
    return cursor.fetchone()
`);

  const [uploadedFiles, setUploadedFiles] = useState<{ path: string; content: string }[]>([]);
  const [zipFileName, setZipFileName] = useState<string | null>(null);

  // Scan progress state
  const [isScanning, setIsScanning] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const steps = [
    { title: 'Repository Ingestion', desc: 'Downloading files & applying path traversal bounds' },
    { title: 'Security Static Analysis', desc: 'Scanning for SQLi, hard-coded secrets, eval, & command injection' },
    { title: 'Code Quality & Complexity', desc: 'Computing cyclomatic complexity, code smells, & documentation density' },
    { title: 'Scoring & AI Engine', desc: 'Synthesizing health score & preparing Gemini remediation' },
  ];

  // Handle ZIP file upload safely with JSZip
  const handleZipUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setZipFileName(file.name);
    setErrorMessage(null);

    try {
      const zip = new JSZip();
      const contents = await zip.loadAsync(file);
      const parsed: { path: string; content: string }[] = [];

      const allowedExts = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.sql', '.json', '.env', '.md'];

      for (const [relativePath, zipEntry] of Object.entries(contents.files)) {
        if (zipEntry.dir) continue;
        // Check extension
        const isAllowed = allowedExts.some(ext => relativePath.endsWith(ext));
        if (!isAllowed) continue;

        // Path traversal guard
        if (relativePath.includes('..') || relativePath.startsWith('/')) continue;

        const text = await zipEntry.async('string');
        parsed.push({ path: relativePath, content: text });
      }

      if (parsed.length === 0) {
        setErrorMessage('No supported source files (.py, .js, .ts, .sql, .env) found in ZIP archive.');
        return;
      }

      setUploadedFiles(parsed);
    } catch (err: any) {
      setErrorMessage(`Failed to read ZIP archive: ${err?.message || 'Invalid format'}`);
    }
  };

  const handleStartScan = async () => {
    setIsScanning(true);
    setErrorMessage(null);
    setCurrentStep(0);

    // Step 0 -> Step 1 -> Step 2 transition for visual UX
    const stepInterval = setInterval(() => {
      setCurrentStep(prev => {
        if (prev < steps.length - 1) return prev + 1;
        return prev;
      });
    }, 450);

    try {
      let payload: any = {};

      if (mode === 'SAMPLE') {
        payload = {
          sourceType: 'SAMPLE_REPO',
          sampleRepoId: sampleId,
        };
      } else if (mode === 'GITHUB') {
        if (!githubUrl.trim()) {
          throw new Error('Please provide a valid GitHub repository URL.');
        }
        payload = {
          sourceType: 'GITHUB',
          githubUrl: githubUrl.trim(),
        };
      } else if (mode === 'ZIP') {
        if (uploadedFiles.length === 0) {
          throw new Error('Please select a valid ZIP archive containing source files.');
        }
        payload = {
          sourceType: 'ZIP_UPLOAD',
          repoName: zipFileName?.replace('.zip', '') || 'uploaded-project',
          files: uploadedFiles,
        };
      } else if (mode === 'SNIPPET') {
        if (!snippetContent.trim()) {
          throw new Error('Please input code content to analyze.');
        }
        payload = {
          sourceType: 'CODE_SNIPPET',
          repoName: 'snippet-evaluation',
          files: [{ path: snippetName, content: snippetContent }],
        };
      }

      const response = await fetch('/api/scans/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Scan analysis failed (HTTP ${response.status})`);
      }

      const scanResult: Scan = await response.json();

      clearInterval(stepInterval);
      setCurrentStep(steps.length - 1);

      setTimeout(() => {
        setIsScanning(false);
        onScanCompleted(scanResult);
      }, 500);
    } catch (err: any) {
      clearInterval(stepInterval);
      setIsScanning(false);
      setErrorMessage(err?.message || 'An unexpected error occurred during scan.');
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">Initiate Code Intelligence Scan</h1>
        <p className="text-sm text-slate-400 mt-1">
          Inspect source code for security vulnerabilities, secrets, cyclomatic complexity, and architecture risks.
        </p>
      </div>

      {/* Ingestion Mode Selector */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <button
          type="button"
          onClick={() => setMode('SAMPLE')}
          className={`p-3.5 rounded-xl border text-left flex flex-col justify-between transition-all cursor-pointer ${
            mode === 'SAMPLE'
              ? 'bg-slate-800/90 border-emerald-500 text-white shadow-md shadow-emerald-950/20'
              : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold">Preset Repos</span>
            <Sparkles className={`w-4 h-4 ${mode === 'SAMPLE' ? 'text-emerald-400' : 'text-slate-500'}`} />
          </div>
          <span className="text-[11px] text-slate-400 mt-2">Curated vulnerable & secure samples</span>
        </button>

        <button
          type="button"
          onClick={() => setMode('GITHUB')}
          className={`p-3.5 rounded-xl border text-left flex flex-col justify-between transition-all cursor-pointer ${
            mode === 'GITHUB'
              ? 'bg-slate-800/90 border-emerald-500 text-white shadow-md shadow-emerald-950/20'
              : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold">GitHub URL</span>
            <GitBranch className={`w-4 h-4 ${mode === 'GITHUB' ? 'text-emerald-400' : 'text-slate-500'}`} />
          </div>
          <span className="text-[11px] text-slate-400 mt-2">Public repository ingestion</span>
        </button>

        <button
          type="button"
          onClick={() => setMode('ZIP')}
          className={`p-3.5 rounded-xl border text-left flex flex-col justify-between transition-all cursor-pointer ${
            mode === 'ZIP'
              ? 'bg-slate-800/90 border-emerald-500 text-white shadow-md shadow-emerald-950/20'
              : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold">Upload ZIP</span>
            <UploadCloud className={`w-4 h-4 ${mode === 'ZIP' ? 'text-emerald-400' : 'text-slate-500'}`} />
          </div>
          <span className="text-[11px] text-slate-400 mt-2">Local project archive</span>
        </button>

        <button
          type="button"
          onClick={() => setMode('SNIPPET')}
          className={`p-3.5 rounded-xl border text-left flex flex-col justify-between transition-all cursor-pointer ${
            mode === 'SNIPPET'
              ? 'bg-slate-800/90 border-emerald-500 text-white shadow-md shadow-emerald-950/20'
              : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold">Code Snippet</span>
            <FileCode className={`w-4 h-4 ${mode === 'SNIPPET' ? 'text-emerald-400' : 'text-slate-500'}`} />
          </div>
          <span className="text-[11px] text-slate-400 mt-2">Direct scratchpad paste</span>
        </button>
      </div>

      {/* Form Input Area */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
        {mode === 'SAMPLE' && (
          <div className="space-y-3">
            <label className="text-xs font-medium text-slate-300 block">
              Select Sample Benchmark Codebase
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <label 
                className={`p-4 rounded-xl border cursor-pointer transition-all flex items-start gap-3 ${
                  sampleId === 'ecommerce-api-vulnerable'
                    ? 'bg-rose-950/20 border-rose-600/60 text-white'
                    : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                }`}
              >
                <input
                  type="radio"
                  name="sampleRepo"
                  value="ecommerce-api-vulnerable"
                  checked={sampleId === 'ecommerce-api-vulnerable'}
                  onChange={(e) => setSampleId(e.target.value)}
                  className="mt-1 accent-rose-500"
                />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-200">ecommerce-backend-api</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                      High Risk
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    Contains raw SQL interpolation, hardcoded AWS keys, MD5 hashing, and system shell execution.
                  </p>
                </div>
              </label>

              <label 
                className={`p-4 rounded-xl border cursor-pointer transition-all flex items-start gap-3 ${
                  sampleId === 'secure-microservice'
                    ? 'bg-emerald-950/20 border-emerald-600/60 text-white'
                    : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                }`}
              >
                <input
                  type="radio"
                  name="sampleRepo"
                  value="secure-microservice"
                  checked={sampleId === 'secure-microservice'}
                  onChange={(e) => setSampleId(e.target.value)}
                  className="mt-1 accent-emerald-500"
                />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-200">secure-auth-service</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      Hardened
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    OWASP-compliant TypeScript microservice with parameterized queries, Argon2id, and environment guards.
                  </p>
                </div>
              </label>
            </div>
          </div>
        )}

        {mode === 'GITHUB' && (
          <div className="space-y-2">
            <label className="text-xs font-medium text-slate-300 block">
              Public GitHub Repository URL
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={githubUrl}
                onChange={(e) => setGithubUrl(e.target.value)}
                placeholder="https://github.com/expressjs/express"
                className="flex-1 px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-emerald-500 font-mono"
              />
            </div>
            <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              <span>Scans repository recursively via GitHub Git Trees API. Code is never executed. For private repos or rate limits, upload as a ZIP archive.</span>
            </div>
          </div>
        )}

        {mode === 'ZIP' && (
          <div className="space-y-3">
            <label className="text-xs font-medium text-slate-300 block">
              Upload Project ZIP Archive
            </label>
            <div className="border-2 border-dashed border-slate-800 hover:border-slate-700 rounded-xl p-6 text-center bg-slate-950/50 transition-colors">
              <UploadCloud className="w-8 h-8 text-slate-500 mx-auto mb-2" />
              <p className="text-xs text-slate-300 font-medium">Click to select or drag and drop a ZIP archive</p>
              <p className="text-[11px] text-slate-500 mt-1">Accepts Python, JavaScript, TypeScript, and SQL codebases</p>
              <input
                type="file"
                accept=".zip"
                onChange={handleZipUpload}
                className="hidden"
                id="zip-file-input"
              />
              <label
                htmlFor="zip-file-input"
                className="mt-3 inline-block px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 cursor-pointer"
              >
                Browse Files
              </label>

              {zipFileName && (
                <div className="mt-3 flex items-center justify-center gap-2 text-xs font-mono text-emerald-400">
                  <FileText className="w-3.5 h-3.5" />
                  <span>{zipFileName} ({uploadedFiles.length} files extracted safely)</span>
                </div>
              )}
            </div>
          </div>
        )}

        {mode === 'SNIPPET' && (
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <label className="text-xs font-medium text-slate-300">File Name & Code Snippet</label>
              <input
                type="text"
                value={snippetName}
                onChange={(e) => setSnippetName(e.target.value)}
                className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 w-48"
                placeholder="filename.py"
              />
            </div>
            <textarea
              value={snippetContent}
              onChange={(e) => setSnippetContent(e.target.value)}
              rows={9}
              className="w-full p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 focus:outline-none focus:border-emerald-500 resize-none leading-relaxed"
            />
          </div>
        )}

        {errorMessage && (
          <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-800/60 flex items-center gap-2 text-xs text-rose-300">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Action Button */}
        <div className="pt-2 flex justify-end">
          <button
            id="start-analysis-btn"
            type="button"
            disabled={isScanning}
            onClick={handleStartScan}
            className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-500 text-white text-xs font-bold shadow-lg shadow-emerald-950/30 transition-all cursor-pointer"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Running Scan Pipeline...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Start Security & Quality Scan</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Scan Progress State Visualizer */}
      {isScanning && (
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl space-y-4 animate-in fade-in duration-300">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-emerald-400 animate-pulse" />
              <h3 className="text-sm font-bold text-white">Analyzing Repository Pipeline...</h3>
            </div>
            <span className="text-xs font-mono text-slate-400">Step {currentStep + 1} of {steps.length}</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {steps.map((step, idx) => {
              const isDone = idx < currentStep;
              const isCurrent = idx === currentStep;
              return (
                <div
                  key={step.title}
                  className={`p-3 rounded-xl border flex items-start gap-3 transition-all ${
                    isDone
                      ? 'bg-emerald-950/20 border-emerald-800/40 text-slate-300'
                      : isCurrent
                      ? 'bg-slate-800/90 border-emerald-500 text-white ring-1 ring-emerald-500/20'
                      : 'bg-slate-950/40 border-slate-900 text-slate-600'
                  }`}
                >
                  <div className="mt-0.5">
                    {isDone ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : isCurrent ? (
                      <Loader2 className="w-4 h-4 text-emerald-400 animate-spin" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-slate-700 flex items-center justify-center text-[10px]">
                        {idx + 1}
                      </div>
                    )}
                  </div>
                  <div>
                    <h4 className="text-xs font-semibold">{step.title}</h4>
                    <p className="text-[11px] text-slate-400 mt-0.5">{step.desc}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
