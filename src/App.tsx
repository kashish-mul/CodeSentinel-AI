import React, { useState, useEffect } from 'react';
import { Navbar, ActiveTab } from './components/Navbar';
import { DashboardView } from './components/DashboardView';
import { NewScanView } from './components/NewScanView';
import { FindingsExplorerView } from './components/FindingsExplorerView';
import { BenchmarkView } from './components/BenchmarkView';
import { TestSuiteView } from './components/TestSuiteView';
import { ArchitectureView } from './components/ArchitectureView';
import { AIRemediationModal } from './components/AIRemediationModal';
import { ReportExportModal } from './components/ReportExportModal';
import { Scan, Finding, User } from './types';
import { Loader2 } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [scans, setScans] = useState<Scan[]>([]);
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [selectedFindingForAI, setSelectedFindingForAI] = useState<Finding | null>(null);
  const [isAIModalOpen, setIsAIModalOpen] = useState(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [geminiActive, setGeminiActive] = useState<boolean>(false);
  const [initialLoading, setInitialLoading] = useState(true);

  // Load initial scans and system health
  useEffect(() => {
    async function init() {
      try {
        const [scansRes, healthRes, userRes] = await Promise.all([
          fetch('/api/scans').then(r => r.json()),
          fetch('/api/health').then(r => r.json()),
          fetch('/api/auth/me').then(r => r.json()),
        ]);

        if (Array.isArray(scansRes) && scansRes.length > 0) {
          setScans(scansRes);
          setActiveScan(scansRes[0]);
        }

        if (healthRes?.geminiConfigured) {
          setGeminiActive(true);
        }

        if (userRes?.user) {
          setCurrentUser(userRes.user);
        }
      } catch (err) {
        console.warn('Initial data load error:', err);
      } finally {
        setInitialLoading(false);
      }
    }
    init();
  }, []);

  const handleScanCompleted = (newScan: Scan) => {
    setScans(prev => [newScan, ...prev.filter(s => s.id !== newScan.id)]);
    setActiveScan(newScan);
    setActiveTab('dashboard');
  };

  const handleOpenFindingRemediation = (finding: Finding) => {
    setSelectedFindingForAI(finding);
    setIsAIModalOpen(true);
  };

  if (initialLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center space-y-4">
        <Loader2 className="w-8 h-8 text-emerald-400 animate-spin" />
        <p className="text-xs font-mono text-slate-400">Booting CodeSentinel AI Static Analysis Engine...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-emerald-500 selection:text-white font-sans antialiased">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        currentUser={currentUser}
        geminiActive={geminiActive}
        totalScansCount={scans.length}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
        {activeTab === 'dashboard' && (
          <DashboardView
            scans={scans}
            activeScan={activeScan}
            onSelectScan={(scan) => {
              setActiveScan(scan);
              setActiveTab('findings');
            }}
            onStartNewScan={() => setActiveTab('new-scan')}
            onOpenFindingRemediation={handleOpenFindingRemediation}
            onOpenReportModal={() => setIsReportModalOpen(true)}
          />
        )}

        {activeTab === 'new-scan' && (
          <NewScanView onScanCompleted={handleScanCompleted} />
        )}

        {activeTab === 'findings' && (
          <FindingsExplorerView
            activeScan={activeScan}
            onOpenAIRemediation={handleOpenFindingRemediation}
          />
        )}

        {activeTab === 'benchmarks' && (
          <BenchmarkView />
        )}

        {activeTab === 'tests' && (
          <TestSuiteView />
        )}

        {activeTab === 'architecture' && (
          <ArchitectureView />
        )}
      </main>

      {/* AI Remediation Modal */}
      <AIRemediationModal
        finding={selectedFindingForAI}
        isOpen={isAIModalOpen}
        onClose={() => {
          setIsAIModalOpen(false);
          setSelectedFindingForAI(null);
        }}
      />

      {/* Audit Report Export Dialog */}
      <ReportExportModal
        scan={activeScan}
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs font-mono text-slate-400">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>CodeSentinel AI • Developer Security & Code Intelligence Platform</span>
          <span className="text-slate-400">AST Static Analysis • OWASP & CWE Correlation • Gemini 3.8 Flash</span>
        </div>
      </footer>
    </div>
  );
}
