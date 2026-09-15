import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { SecurityAnalyzer, FileInput } from './src/server/analysis/securityAnalyzer';
import { QualityAnalyzer } from './src/server/analysis/qualityAnalyzer';
import { ScoringEngine } from './src/server/analysis/scoringEngine';
import { runBenchmarkEvaluation } from './src/server/analysis/benchmarkData';
import { AIService } from './src/server/analysis/aiService';
import { TestRunner } from './src/server/analysis/testRunner';
import { GitHubScanner } from './src/server/analysis/githubScanner';
import { GitHubIngestion } from './src/server/ingestion/githubIngestion';
import { ZipIngestion } from './src/server/ingestion/zipIngestion';
import { SnippetIngestion } from './src/server/ingestion/snippetIngestion';
import { DependencyAnalyzer } from './src/server/analysis/dependencyAnalyzer';
import { SAMPLE_REPOSITORIES } from './src/server/sampleRepos';
import { db } from './src/server/db';
import { dbClient } from './src/server/db/client';
import { AuthService, AuthRequest } from './src/server/auth';
import { Scan, Finding, User, RemediationReport } from './src/types';

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use(AuthService.middleware);

// Seed initial scans into the database if empty
async function seedInitialDatabaseScans() {
  const existingScans = await db.getScans();
  if (existingScans.length === 0) {
    console.log('[DB] Seeding baseline sample repository scans...');
    for (const sample of SAMPLE_REPOSITORIES) {
      const scanId = `scan-${sample.id}-${Date.now().toString(36)}`;
      const findings: Finding[] = [];
      let totalLines = 0;

      for (const file of sample.files) {
        totalLines += file.content.split('\n').length;
        findings.push(...SecurityAnalyzer.analyzeFile(file, scanId));
        findings.push(...QualityAnalyzer.analyzeFile(file, scanId));
      }

      const { scores, counts } = ScoringEngine.calculateScores(findings, sample.files.length, totalLines);

      const scan: Scan = {
        id: scanId,
        repositoryName: sample.name,
        sourceType: 'SAMPLE_REPO',
        sourceUrl: sample.id,
        status: 'COMPLETED',
        scores,
        severityCounts: counts,
        totalFilesAnalyzed: sample.files.length,
        totalLinesOfCode: totalLines,
        startedAt: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
        completedAt: new Date().toISOString(),
        findings,
      };

      await db.saveScan(scan);
    }
  }
}

// --- REST API ENDPOINTS ---

// 1. Health check & Diagnostics
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'CodeSentinel Static Analysis & Security Engine',
    version: '2.0.0-ast',
    timestamp: new Date().toISOString(),
    postgresConnected: db.isPostgresConnected(),
    geminiConfigured: Boolean(process.env.GEMINI_API_KEY),
    astAnalyzers: ['TypeScript/JavaScript Compiler AST', 'Python AST Visitor', 'SCA Dependency Scanner'],
  });
});

// 2. Cryptographic Authentication (JWT + Bcrypt)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const existingUser = await db.getUserByEmail(email);
    if (!existingUser) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (existingUser.password_hash) {
      const isValid = AuthService.verifyPassword(password, existingUser.password_hash);
      if (!isValid) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
    }

    const userPayload: User = {
      id: existingUser.id,
      email: existingUser.email,
      name: existingUser.name,
      role: existingUser.role,
    };

    const token = AuthService.generateToken(userPayload);
    return res.json({ user: userPayload, token });
  } catch (err: any) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal authentication failure' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !name || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    const existing = await db.getUserByEmail(email);
    if (existing) {
      return res.status(409).json({ error: 'A user with this email already exists' });
    }

    const password_hash = AuthService.hashPassword(password);
    const newUser = await db.createUser({
      id: `usr_${Date.now().toString(36)}_${Math.random().toString(36).substr(2, 4)}`,
      email,
      name,
      role: 'Security Engineer',
      password_hash,
    });

    const userPayload: User = {
      id: newUser.id,
      email: newUser.email,
      name: newUser.name,
      role: newUser.role,
    };

    const token = AuthService.generateToken(userPayload);
    return res.status(201).json({ user: userPayload, token });
  } catch (err: any) {
    console.error('Registration error:', err);
    return res.status(500).json({ error: 'Registration failed' });
  }
});

app.get('/api/auth/me', (req: AuthRequest, res) => {
  if (req.user) {
    return res.json({ user: req.user });
  }
  // Default demo user fallback if no token provided
  return res.json({
    user: {
      id: 'usr_sec_lead_01',
      name: 'Lead AppSec Engineer',
      email: 'developer@codesentinel.io',
      role: 'Principal Security Architect',
    }
  });
});

// 3. Repositories
app.get('/api/sample-repositories', (req, res) => {
  return res.json(SAMPLE_REPOSITORIES.map(r => ({
    id: r.id,
    name: r.name,
    description: r.description,
    fileCount: r.files.length,
  })));
});

app.get('/api/repositories', async (req, res) => {
  try {
    const repos = await db.getRepositories();
    return res.json(repos);
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to retrieve repositories' });
  }
});

// 4. Scans & AST Analysis Ingestion
app.post('/api/scans/analyze', async (req: AuthRequest, res) => {
  try {
    const { sourceType, repoName, githubUrl, sampleRepoId, files, zipBase64, codeSnippet, fileName } = req.body;

    let targetFiles: FileInput[] = [];
    let targetName = repoName || 'custom-analysis';

    if (sourceType === 'SAMPLE_REPO' && sampleRepoId) {
      const sample = SAMPLE_REPOSITORIES.find(s => s.id === sampleRepoId);
      if (!sample) {
        return res.status(404).json({ error: 'Sample repository not found' });
      }
      targetFiles = sample.files;
      targetName = sample.name;
    } else if (sourceType === 'GITHUB' && githubUrl) {
      // Real recursive GitHub repository fetcher using GitHubIngestion
      try {
        console.log(`[GitHubIngestion] Fetching recursive tree for: ${githubUrl}`);
        const repoSource = await GitHubIngestion.ingest(githubUrl);
        targetFiles = repoSource.files.map(f => ({ path: f.path, content: f.content }));
        targetName = repoSource.name;
        console.log(`[GitHubIngestion] Successfully retrieved ${targetFiles.length} source files for ${targetName}`);
      } catch (err: any) {
        return res.status(422).json({
          error: `GitHub repository analysis failed: ${err.message}`
        });
      }
    } else if (sourceType === 'ZIP' && zipBase64) {
      // Decompress and process ZIP archive securely
      try {
        const repoSource = await ZipIngestion.ingestFromBase64(zipBase64, targetName);
        targetFiles = repoSource.files.map(f => ({ path: f.path, content: f.content }));
        targetName = repoSource.name;
      } catch (err: any) {
        return res.status(400).json({ error: `ZIP archive ingestion failed: ${err.message}` });
      }
    } else if (codeSnippet) {
      const repoSource = SnippetIngestion.ingest(codeSnippet, fileName || 'snippet.ts', targetName);
      targetFiles = repoSource.files.map(f => ({ path: f.path, content: f.content }));
      targetName = repoSource.name;
    } else if (Array.isArray(files) && files.length > 0) {
      // Validate paths against path traversal
      for (const f of files) {
        if (!f.path || f.path.includes('..') || f.path.startsWith('/')) {
          return res.status(400).json({ error: `Unsafe or invalid file path: ${f.path}` });
        }
      }
      targetFiles = files;
    } else {
      return res.status(400).json({ error: 'No files or source repository provided for analysis' });
    }

    const scanId = `scan-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 5)}`;
    const findings: Finding[] = [];
    let totalLines = 0;

    for (const f of targetFiles) {
      totalLines += (f.content || '').split('\n').length;
      findings.push(...SecurityAnalyzer.analyzeFile(f, scanId));
      findings.push(...QualityAnalyzer.analyzeFile(f, scanId));
    }

    const { scores, counts } = ScoringEngine.calculateScores(findings, targetFiles.length, totalLines);

    const scan: Scan = {
      id: scanId,
      userId: req.user?.id,
      repositoryName: targetName,
      sourceType: sourceType || 'CODE_SNIPPET',
      sourceUrl: githubUrl || undefined,
      status: 'COMPLETED',
      scores,
      severityCounts: counts,
      totalFilesAnalyzed: targetFiles.length,
      totalLinesOfCode: totalLines,
      startedAt: new Date(Date.now() - 1200).toISOString(),
      completedAt: new Date().toISOString(),
      findings,
    };

    await db.saveScan(scan);
    return res.status(201).json(scan);
  } catch (error: any) {
    console.error('Scan failed:', error);
    return res.status(500).json({ error: error?.message || 'Scan analysis failed' });
  }
});

app.get('/api/scans', async (req, res) => {
  try {
    const allScans = await db.getScans();
    return res.json(allScans);
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to retrieve scans' });
  }
});

app.get('/api/scans/:id', async (req, res) => {
  try {
    const scan = await db.getScanById(req.params.id);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    return res.json(scan);
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to retrieve scan' });
  }
});

app.get('/api/scans/:id/findings', async (req, res) => {
  try {
    const scan = await db.getScanById(req.params.id);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    return res.json(scan.findings);
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to retrieve scan findings' });
  }
});

// 5. AI-Assisted Remediation & Diff Synthesis
app.post('/api/ai/explain', async (req, res) => {
  try {
    const { finding } = req.body;
    if (!finding || !finding.title) {
      return res.status(400).json({ error: 'Finding payload is required' });
    }

    const remediation = await AIService.explainAndRemediate(finding);
    return res.json(remediation);
  } catch (err: any) {
    console.error('AI explanation error:', err);
    return res.status(500).json({ error: 'Failed to generate AI remediation' });
  }
});

// Interactive Security Copilot Q&A
app.post('/api/copilot/ask', async (req, res) => {
  try {
    const { finding, question, history } = req.body;
    if (!finding || !question) {
      return res.status(400).json({ error: 'Finding and question are required' });
    }

    const answer = await AIService.askCopilot(finding, question, history || []);
    return res.json({ answer });
  } catch (err: any) {
    console.error('Copilot ask error:', err);
    return res.status(500).json({ error: 'Failed to process Copilot request' });
  }
});

// Generate or Retrieve Full Remediation Report
app.get('/api/scans/:id/report', async (req, res) => {
  try {
    const scan = await db.getScanById(req.params.id);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const criticalCount = scan.findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = scan.findings.filter(f => f.severity === 'HIGH').length;

    const report: RemediationReport = {
      id: `report-${scan.id}`,
      scanId: scan.id,
      repositoryName: scan.repositoryName,
      generatedAt: new Date().toISOString(),
      overallScore: scan.scores.overall,
      executiveSummary: `CodeSentinel AST analysis evaluated ${scan.totalFilesAnalyzed} source files (${scan.totalLinesOfCode} lines of code) in ${scan.repositoryName}. A total of ${scan.findings.length} findings were identified, including ${criticalCount} critical and ${highCount} high severity risks. Key focus areas include injection mitigation, cryptographic security, and dependency updates.`,
      scores: scan.scores,
      severityCounts: scan.severityCounts,
      totalFindings: scan.findings.length,
      criticalFindingsCount: criticalCount,
      findings: scan.findings,
    };

    return res.json(report);
  } catch (err: any) {
    console.error('Report generation error:', err);
    return res.status(500).json({ error: 'Failed to generate report' });
  }
});

// 6. Empirical Benchmark Evaluation
app.get('/api/evaluation/benchmark', (req, res) => {
  const benchmarkResults = runBenchmarkEvaluation();
  return res.json(benchmarkResults);
});

// 7. Automated Test Suite Execution
app.get('/api/tests/run', (req, res) => {
  const testResults = TestRunner.runAllTests();
  return res.json(testResults);
});

// Start server with Vite middleware & DB initialization
async function startServer() {
  // Initialize Database and Seed default account
  await dbClient.initialize();
  await db.initialize();
  await AuthService.seedDefaultUser();
  await seedInitialDatabaseScans();

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`CodeSentinel AI Server running on port ${PORT}`);
  });
}

startServer();
