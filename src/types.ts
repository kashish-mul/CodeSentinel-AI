export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Category = 'SECURITY' | 'CODE_QUALITY' | 'MAINTAINABILITY' | 'DOCUMENTATION' | 'DEPENDENCY';

export interface Finding {
  id: string;
  scanId: string;
  category: Category;
  severity: Severity;
  title: string;
  description: string;
  filePath: string;
  lineNumber: number;
  codeSnippet: string;
  recommendation: string;
  cwe?: string;
  owaspCategory?: string;
  astNodeType?: string;
  analysisMethod?: 'AST' | 'SCA' | 'HEURISTIC';
  dependencyInfo?: {
    packageName: string;
    installedVersion: string;
    fixedVersion: string;
    cve: string;
  };
  aiExplanation?: AIRemediation;
}

export interface AIRemediation {
  problemExplanation: string;
  securityImpact: string;
  stepByStepFix: string[];
  remediatedCode: string;
  saferAlternativeSnippet: string;
  diffSnippet?: string;
  modelUsed: string;
  generatedAt: string;
}

export interface ScanScores {
  overall: number;
  security: number;
  quality: number;
  maintainability: number;
  documentation: number;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Scan {
  id: string;
  userId?: string;
  repositoryName: string;
  sourceType: 'GITHUB' | 'ZIP_UPLOAD' | 'CODE_SNIPPET' | 'SAMPLE_REPO';
  sourceUrl?: string;
  status: 'QUEUED' | 'ANALYZING' | 'COMPLETED' | 'FAILED';
  scores: ScanScores;
  severityCounts: SeverityCounts;
  totalFilesAnalyzed: number;
  totalLinesOfCode: number;
  startedAt: string;
  completedAt?: string;
  findings: Finding[];
}

export interface RepositorySummary {
  id: string;
  name: string;
  sourceType: 'GITHUB' | 'ZIP_UPLOAD' | 'CODE_SNIPPET' | 'SAMPLE_REPO';
  sourceUrl?: string;
  lastScannedAt: string;
  overallScore: number;
  criticalIssues: number;
}

export interface SourceFile {
  path: string;
  content: string;
  language: string;
  size: number;
}

export interface RepositorySource {
  name: string;
  source: 'github' | 'zip' | 'snippet' | 'sample';
  files: SourceFile[];
  url?: string;
}

export interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  token?: string;
}

export interface BenchmarkItem {
  id: string;
  name: string;
  language: string;
  code: string;
  isVulnerable: boolean;
  expectedCategory: Category;
  expectedSeverity: Severity;
  expectedVulnerabilityType?: string;
}

export interface BenchmarkCategoryMetrics {
  category: string;
  total: number;
  precision: number;
  recall: number;
  f1Score: number;
}

export interface BenchmarkResult {
  totalSamples: number;
  vulnerableSamples: number;
  safeSamples: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  accuracy: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  categoryBreakdowns: BenchmarkCategoryMetrics[];
  detailedResults: {
    id: string;
    name: string;
    language: string;
    groundTruth: 'VULNERABLE' | 'SAFE';
    predicted: 'VULNERABLE' | 'SAFE';
    status: 'CORRECT' | 'FALSE_POSITIVE' | 'FALSE_NEGATIVE';
    detectedVulnerabilities: string[];
    snippet: string;
  }[];
}

export interface CopilotMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

export interface RemediationReport {
  id: string;
  scanId: string;
  repositoryName: string;
  generatedAt: string;
  executiveSummary: string;
  overallScore: number;
  scores: ScanScores;
  severityCounts: SeverityCounts;
  totalFindings: number;
  criticalFindingsCount: number;
  findings: Finding[];
}

export interface TestSuiteResult {
  suiteName: string;
  passed: number;
  failed: number;
  total: number;
  durationMs: number;
  tests: {
    name: string;
    category: string;
    passed: boolean;
    durationMs: number;
    error?: string;
  }[];
}
