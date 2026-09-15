import React from 'react';
import { Shield, ShieldAlert, Cpu, Award, PlayCircle, Layers, Terminal, Sparkles } from 'lucide-react';
import { User } from '../types';

export type ActiveTab = 'dashboard' | 'new-scan' | 'findings' | 'benchmarks' | 'tests' | 'architecture';

interface NavbarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  currentUser: User | null;
  geminiActive: boolean;
  totalScansCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  currentUser,
  geminiActive,
  totalScansCount,
}) => {
  const navItems: { id: ActiveTab; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: Shield },
    { id: 'new-scan', label: 'New Scan', icon: PlayCircle },
    { id: 'findings', label: 'Findings Explorer', icon: ShieldAlert },
    { id: 'benchmarks', label: 'Evaluation Benchmarks', icon: Award },
    { id: 'tests', label: 'Automated Tests', icon: Terminal },
    { id: 'architecture', label: 'Architecture & CI/CD', icon: Layers },
  ];

  return (
    <header className="sticky top-0 z-30 w-full border-b border-slate-800 bg-slate-950/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo */}
          <div 
            id="brand-logo"
            onClick={() => setActiveTab('dashboard')} 
            className="flex items-center gap-3 cursor-pointer group"
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-emerald-600 to-indigo-600 p-0.5 shadow-lg shadow-indigo-500/20">
              <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center group-hover:bg-slate-900 transition-colors">
                <Shield className="w-5 h-5 text-emerald-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-tight text-white font-sans">CodeSentinel</span>
                <span className="text-xs font-semibold px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 flex items-center gap-1">
                  <Sparkles className="w-3 h-3" /> AI
                </span>
              </div>
              <p className="text-[11px] text-slate-400 tracking-wide font-mono">SecOps & Code Intelligence</p>
            </div>
          </div>

          {/* Desktop Navigation Tabs */}
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  id={`nav-tab-${item.id}`}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-slate-800 text-emerald-400 border border-slate-700/80 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-emerald-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Right Header Status Pill */}
          <div className="flex items-center gap-3">
            <div 
              id="gemini-status-indicator"
              className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-mono bg-slate-900 border border-slate-800"
              title={geminiActive ? 'Gemini 3.8 Flash Active' : 'Fallback Rule Engine Active'}
            >
              <div className={`w-2 h-2 rounded-full ${geminiActive ? 'bg-emerald-400 animate-pulse' : 'bg-indigo-400'}`} />
              <span className="text-slate-300 text-[11px]">
                {geminiActive ? 'Gemini 3.8 Flash' : 'AI Engine Ready'}
              </span>
            </div>

            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800">
              <div className="w-7 h-7 rounded-full bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center text-xs font-semibold text-emerald-400">
                {currentUser?.name?.charAt(0) || 'D'}
              </div>
              <div className="hidden lg:block text-left">
                <p className="text-xs font-medium text-slate-200 leading-none">{currentUser?.name || 'Developer'}</p>
                <p className="text-[10px] text-slate-400 font-mono mt-0.5">{currentUser?.role || 'Security Eng'}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Mobile Navigation bar */}
        <div className="flex md:hidden overflow-x-auto py-2 gap-1.5 border-t border-slate-900 scrollbar-none">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                id={`mobile-nav-tab-${item.id}`}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-slate-800 text-emerald-400 border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
