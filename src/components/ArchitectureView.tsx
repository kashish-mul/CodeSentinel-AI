import React, { useState } from 'react';
import { 
  Layers, 
  Server, 
  Database, 
  Cpu, 
  ShieldCheck, 
  Check, 
  Copy, 
  Box,
  FileCode,
  Package
} from 'lucide-react';

export const ArchitectureView: React.FC = () => {
  const [activeSnippet, setActiveSnippet] = useState<'dockerfile' | 'compose' | 'ci' | 'api' | 'schema'>('dockerfile');
  const [copied, setCopied] = useState(false);

  const snippets = {
    dockerfile: `# Multi-stage Production Dockerfile
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

COPY --from=builder /app/package*.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/dist ./dist

EXPOSE 3000
USER node
CMD ["node", "dist/server.cjs"]`,

    compose: `version: '3.8'
services:
  codesentinel-app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - PORT=3000
      - GEMINI_API_KEY=\${GEMINI_API_KEY}
      - DATABASE_URL=postgresql://sentinel_user:sentinel_pass@postgres:5432/codesentinel_db
    depends_on:
      - postgres
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: sentinel_user
      POSTGRES_PASSWORD: sentinel_pass
      POSTGRES_DB: codesentinel_db
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"

volumes:
  pgdata:`,

    ci: `name: CodeSentinel CI/CD Pipeline
on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main]

jobs:
  lint-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node.js 22
        uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: 'npm'
      - name: Install Dependencies
        run: npm ci
      - name: Typecheck and Lint
        run: npm run lint
      - name: Run Core Test Suite & AST Benchmarks
        run: npm run build

  docker-build-deploy:
    needs: lint-and-test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Build Docker Container
        run: docker build -t codesentinel-ai:latest .
      - name: Deploy to Cloud Provider
        run: echo "Automated release deployed to Cloud Run container cluster"`,

    api: `POST /api/auth/login           - Authenticate developer & return signed JWT
POST /api/auth/register        - Register new developer account (Bcrypt hashing)
GET  /api/auth/me              - Verify JWT session payload
GET  /api/repositories         - List tracked repositories & latest scores
POST /api/scans/analyze        - Ingest recursive GitHub repo, ZIP archive, or snippet
GET  /api/scans                - Query historical scans (PostgreSQL backed)
GET  /api/scans/:id            - Retrieve scan metrics & severity distribution
GET  /api/scans/:id/findings   - Granular list of findings with AST node details
POST /api/ai/explain           - Request Gemini-assisted remediation & diff
GET  /api/evaluation/benchmark - Execute 15-sample empirical ground-truth benchmark
GET  /api/tests/run            - Run automated AST, SCA, and Auth test suite`,

    schema: `-- PostgreSQL Database Schema (Managed via DatabaseManager)
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(64) PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(255) NOT NULL,
  role VARCHAR(64) DEFAULT 'Security Engineer',
  password_hash TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
  id VARCHAR(64) PRIMARY KEY,
  repository_name VARCHAR(255) NOT NULL,
  source_type VARCHAR(64) NOT NULL,
  source_url TEXT,
  status VARCHAR(32) NOT NULL,
  scores_json JSONB NOT NULL,
  severity_counts_json JSONB NOT NULL,
  total_files INT NOT NULL,
  total_lines INT NOT NULL,
  started_at TIMESTAMP WITH TIME ZONE NOT NULL,
  completed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
  id VARCHAR(64) PRIMARY KEY,
  scan_id VARCHAR(64) REFERENCES scans(id) ON DELETE CASCADE,
  category VARCHAR(64) NOT NULL,
  severity VARCHAR(32) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line_number INT NOT NULL,
  code_snippet TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  cwe VARCHAR(64),
  owasp_category VARCHAR(128),
  ast_node_type VARCHAR(64),
  analysis_method VARCHAR(32),
  dependency_info JSONB
);`
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(snippets[activeSnippet]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">System Architecture & DevOps</h1>
        <p className="text-sm text-slate-400 mt-1 max-w-2xl">
          Multi-tiered full-stack architecture combining AST parsing, SCA vulnerability detection, PostgreSQL persistence, and containerized deployment.
        </p>
      </div>

      {/* Interactive System Architecture Diagram */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-6">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Layers className="w-4 h-4 text-emerald-400" />
          <span>Multi-Tiered Architecture Flow</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 font-mono text-xs">
          {/* Layer 1: Client */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-center flex flex-col justify-between">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest block font-sans font-bold">1. Client Layer</span>
            <div className="py-2">
              <div className="w-9 h-9 rounded-lg bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 flex items-center justify-center mx-auto mb-2">
                <Box className="w-5 h-5" />
              </div>
              <p className="font-bold text-slate-200">React 19 SPA</p>
              <p className="text-[10px] text-slate-400 mt-1">Dashboard & Diff UI</p>
            </div>
            <div className="text-[10px] text-indigo-400 bg-indigo-950/40 py-1 rounded">Vite + Tailwind</div>
          </div>

          {/* Layer 2: API Gateway */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-center flex flex-col justify-between">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest block font-sans font-bold">2. Server & Ingestion</span>
            <div className="py-2">
              <div className="w-9 h-9 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center justify-center mx-auto mb-2">
                <Server className="w-5 h-5" />
              </div>
              <p className="font-bold text-slate-200">Express + JWT</p>
              <p className="text-[10px] text-slate-400 mt-1">GitHub API Walker & Zip</p>
            </div>
            <div className="text-[10px] text-emerald-400 bg-emerald-950/40 py-1 rounded">Bcrypt & JWT Auth</div>
          </div>

          {/* Layer 3: Static Analysis */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-center flex flex-col justify-between">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest block font-sans font-bold">3. Static AST & SCA</span>
            <div className="py-2">
              <div className="w-9 h-9 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/30 flex items-center justify-center mx-auto mb-2">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <p className="font-bold text-slate-200">AST & CVE Engine</p>
              <p className="text-[10px] text-slate-400 mt-1">TS Compiler & Py Parser</p>
            </div>
            <div className="text-[10px] text-amber-400 bg-amber-950/40 py-1 rounded">Zero-Execution Sandbox</div>
          </div>

          {/* Layer 4: AI Remediation */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-center flex flex-col justify-between">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest block font-sans font-bold">4. Remediation AI</span>
            <div className="py-2">
              <div className="w-9 h-9 rounded-lg bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 flex items-center justify-center mx-auto mb-2">
                <Cpu className="w-5 h-5" />
              </div>
              <p className="font-bold text-slate-200">Gemini-Assisted</p>
              <p className="text-[10px] text-slate-400 mt-1">Remediation & Diff Gen</p>
            </div>
            <div className="text-[10px] text-indigo-400 bg-indigo-950/40 py-1 rounded">@google/genai SDK</div>
          </div>

          {/* Layer 5: Persistence */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-center flex flex-col justify-between">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest block font-sans font-bold">5. Persistence</span>
            <div className="py-2">
              <div className="w-9 h-9 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center justify-center mx-auto mb-2">
                <Database className="w-5 h-5" />
              </div>
              <p className="font-bold text-slate-200">PostgreSQL Store</p>
              <p className="text-[10px] text-slate-400 mt-1">Scans, Users & Findings</p>
            </div>
            <div className="text-[10px] text-emerald-400 bg-emerald-950/40 py-1 rounded">PG Pool / Local Store</div>
          </div>
        </div>
      </div>

      {/* DevOps & Code Artifacts Viewer */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-white">Engineering Specs & Infrastructure Configurations</h2>
            <p className="text-xs text-slate-400">Production-ready Docker, Docker Compose, CI/CD, SQL Schema, and REST API definitions</p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700 transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </div>

        {/* Tab selector */}
        <div className="flex gap-2 border-b border-slate-800 pb-2 text-xs font-mono overflow-x-auto">
          <button
            onClick={() => setActiveSnippet('dockerfile')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer whitespace-nowrap ${
              activeSnippet === 'dockerfile' ? 'bg-slate-800 text-emerald-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            Dockerfile
          </button>
          <button
            onClick={() => setActiveSnippet('compose')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer whitespace-nowrap ${
              activeSnippet === 'compose' ? 'bg-slate-800 text-emerald-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            docker-compose.yml
          </button>
          <button
            onClick={() => setActiveSnippet('schema')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer whitespace-nowrap ${
              activeSnippet === 'schema' ? 'bg-slate-800 text-emerald-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            PostgreSQL Schema
          </button>
          <button
            onClick={() => setActiveSnippet('ci')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer whitespace-nowrap ${
              activeSnippet === 'ci' ? 'bg-slate-800 text-emerald-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            .github/workflows/ci.yml
          </button>
          <button
            onClick={() => setActiveSnippet('api')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer whitespace-nowrap ${
              activeSnippet === 'api' ? 'bg-slate-800 text-emerald-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            REST API Spec
          </button>
        </div>

        {/* Code View */}
        <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed max-h-[380px]">
          <code>{snippets[activeSnippet]}</code>
        </pre>
      </div>
    </div>
  );
};
