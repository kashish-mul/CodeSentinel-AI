import React, { useState } from 'react';
import { 
  X, 
  Download, 
  FileText, 
  Printer, 
  Check, 
  Copy,
  ShieldCheck,
  Award
} from 'lucide-react';
import { Scan } from '../types';

interface ReportExportModalProps {
  scan: Scan | null;
  isOpen: boolean;
  onClose: () => void;
}

export const ReportExportModal: React.FC<ReportExportModalProps> = ({
  scan,
  isOpen,
  onClose,
}) => {
  const [format, setFormat] = useState<'MARKDOWN' | 'JSON'>('MARKDOWN');
  const [copied, setCopied] = useState(false);

  if (!isOpen || !scan) return null;

  const generateMarkdownReport = (): string => {
    return `# CodeSentinel AI Security & Code Intelligence Audit Report

**Repository:** \`${scan.repositoryName}\`  
**Scan Date:** ${new Date(scan.startedAt).toUTCString()}  
**Overall Health Score:** ${scan.scores.overall}/100  
**Status:** ${scan.status}  
**Files Analyzed:** ${scan.totalFilesAnalyzed} | **Lines of Code:** ${scan.totalLinesOfCode}  

---

## 1. Executive Summary & Health Scores

| Category | Score | Weight | Health Status |
| :--- | :--- | :--- | :--- |
| **Security** | ${scan.scores.security}/100 | 40% | ${scan.scores.security >= 80 ? 'STRONG' : scan.scores.security >= 60 ? 'MODERATE' : 'CRITICAL'} |
| **Code Quality** | ${scan.scores.quality}/100 | 30% | ${scan.scores.quality >= 80 ? 'STRONG' : 'NEEDS IMPROVEMENT'} |
| **Maintainability** | ${scan.scores.maintainability}/100 | 20% | ${scan.scores.maintainability >= 80 ? 'OPTIMAL' : 'REFACTOR RECOMMENDED'} |
| **Documentation** | ${scan.scores.documentation}/100 | 10% | ${scan.scores.documentation >= 80 ? 'DOCUMENTED' : 'SPARSE'} |

### Vulnerability Breakdown by Severity
- **CRITICAL:** ${scan.severityCounts.critical}
- **HIGH:** ${scan.severityCounts.high}
- **MEDIUM:** ${scan.severityCounts.medium}
- **LOW / INFO:** ${scan.severityCounts.low + scan.severityCounts.info}

---

## 2. Key Findings & Remediation Guidance

${scan.findings.map((f, i) => `### Finding #${i + 1}: [${f.severity}] ${f.title}
- **Location:** \`${f.filePath}:${f.lineNumber}\`
- **Category:** ${f.category}
- **OWASP / CWE:** ${f.cwe || 'N/A'} - ${f.owaspCategory || 'N/A'}
- **Description:** ${f.description}

\`\`\`
${f.codeSnippet}
\`\`\`

**Static Recommendation:**  
${f.recommendation}

---`).join('\n\n')}

*Generated automatically by CodeSentinel AI.*
`;
  };

  const generateJsonReport = (): string => {
    return JSON.stringify(scan, null, 2);
  };

  const reportText = format === 'MARKDOWN' ? generateMarkdownReport() : generateJsonReport();

  const handleDownload = () => {
    const filename = `${scan.repositoryName}-audit-report.${format === 'MARKDOWN' ? 'md' : 'json'}`;
    const blob = new Blob([reportText], { type: format === 'MARKDOWN' ? 'text/markdown' : 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl p-6 sm:p-8 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center justify-center">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-white">Export Audit & Compliance Report</h2>
              <p className="text-xs text-slate-400 font-mono">
                {scan.repositoryName} • {scan.findings.length} findings • Score: {scan.scores.overall}/100
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

        {/* Format Selector & Actions */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex gap-2">
            <button
              onClick={() => setFormat('MARKDOWN')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors cursor-pointer ${
                format === 'MARKDOWN'
                  ? 'bg-slate-800 text-emerald-400 border border-slate-700'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Markdown Report (.md)
            </button>
            <button
              onClick={() => setFormat('JSON')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors cursor-pointer ${
                format === 'JSON'
                  ? 'bg-slate-800 text-emerald-400 border border-slate-700'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Raw Scan JSON (.json)
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700 transition-colors cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / PDF</span>
            </button>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700 transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy Text'}</span>
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white transition-colors cursor-pointer shadow-md"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download File</span>
            </button>
          </div>
        </div>

        {/* Report Preview Box */}
        <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 font-mono text-xs text-slate-300 overflow-x-auto max-h-[380px] leading-relaxed select-all">
          <code>{reportText}</code>
        </pre>

        {/* Footer */}
        <div className="pt-2 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors cursor-pointer"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
