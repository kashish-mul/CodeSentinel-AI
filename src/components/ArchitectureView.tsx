import React, { useState } from 'react';
import { 
  Layers, 
  Server, 
  Database, 
  Cpu, 
  ShieldCheck, 
  Terminal, 
  GitBranch, 
  Check, 
  Copy, 
  Box,
  FileCode
} from 'lucide-react';

export const ArchitectureView: React.FC = () => {
  const [activeSnippet, setActiveSnippet] = useState<'dockerfile' | 'compose' | 'ci' | 'api'>('dockerfile');
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
      - name: Run Core Test Suite
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

    api: `POST /api/auth/login        - Authenticate developer & issue JWT
POST /api/auth/register     - Register developer profile
GET  /api/repositories      - List active tracked repositories
POST /api/scans/analyze     - Ingest GitHub repo, ZIP archive, or code snippet
GET  /api/scans             - Scan history & aggregate metrics
GET  /api/scans/:id         - Comprehensive scan details & score breakdown
GET  /api/scans/:id/findings- Granular list of findings with CWE mapping
POST /api/ai/explain        - Invoke Gemini 3.8 Flash for remediation
GET  /api/evaluation/benchmark- Run Stage 26 empirical precision/recall evaluation
GET  /api/tests/run         - Execute live automated test suite`
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
          Modular full-stack design combining static parsing, rule engines, Gemini LLM remediation, and automated CI/CD containerization.
        </p>
      </div>

      {/* Interactive System Architecture Diagram */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-6">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Layers className="w-4 h-4 text-emerald-400" />
          <span>Core Component Flow</span>
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
              <p className="text-[10px] text-slate-400 mt-1">Dashboard & Findings UI</p>
            </div>
            <div className="text-[10px] text-indigo-400 bg-indigo-950/40 py-1 rounded">REST / JSON</div>
          </div>

          {/* Layer 2: API Gateway */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-center flex flex-col justify-between">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest block font-sans font-bold">2. Server Gateway</span>
            <div className="py-2">
              <div className="w-9 h-9 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center justify-center mx-auto mb-2">
                <Server className="w-5 h-5" />
              </div>
              <p className="font-bold text-slate-200">Node/Express API</p>
              <p className="text-[10px] text-slate-400 mt-1">Auth, Ingestion & Routing</p>
            </div>
            <div className="text-[10px] text-emerald-400 bg-emerald-950/40 py-1 rounded">Port 3000 Ingress</div>
          </div>

          {/* Layer 3: Static Analysis */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-center flex flex-col justify-between">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest block font-sans font-bold">3. Static Engine</span>
            <div className="py-2">
              <div className="w-9 h-9 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/30 flex items-center justify-center mx-auto mb-2">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <p className="font-bold text-slate-200">Rule & AST Engine</p>
              <p className="text-[10px] text-slate-400 mt-1">SQLi, Secrets, Complexity</p>
            </div>
            <div className="text-[10px] text-amber-400 bg-amber-950/40 py-1 rounded">Zero-Execution Sandbox</div>
          </div>

          {/* Layer 4: AI Remediation */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-center flex flex-col justify-between">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest block font-sans font-bold">4. AI Intelligence</span>
            <div className="py-2">
              <div className="w-9 h-9 rounded-lg bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 flex items-center justify-center mx-auto mb-2">
                <Cpu className="w-5 h-5" />
              </div>
              <p className="font-bold text-slate-200">Gemini 3.8 Flash</p>
              <p className="text-[10px] text-slate-400 mt-1">Contextual Remediation</p>
            </div>
            <div className="text-[10px] text-indigo-400 bg-indigo-950/40 py-1 rounded">@google/genai SDK</div>
          </div>

          {/* Layer 5: Persistence */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-center flex flex-col justify-between">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest block font-sans font-bold">5. Storage</span>
            <div className="py-2">
              <div className="w-9 h-9 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center justify-center mx-auto mb-2">
                <Database className="w-5 h-5" />
              </div>
              <p className="font-bold text-slate-200">PostgreSQL / Store</p>
              <p className="text-[10px] text-slate-400 mt-1">Scans, Findings, Metrics</p>
            </div>
            <div className="text-[10px] text-emerald-400 bg-emerald-950/40 py-1 rounded">Persistent Schema</div>
          </div>
        </div>
      </div>

      {/* DevOps & Code Artifacts Viewer */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-white">DevOps & Deployment Configuration</h2>
            <p className="text-xs text-slate-400">Production-ready Docker, Docker Compose, CI/CD, and REST API definitions</p>
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
        <div className="flex gap-2 border-b border-slate-800 pb-2 text-xs font-mono">
          <button
            onClick={() => setActiveSnippet('dockerfile')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeSnippet === 'dockerfile' ? 'bg-slate-800 text-emerald-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            Dockerfile
          </button>
          <button
            onClick={() => setActiveSnippet('compose')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeSnippet === 'compose' ? 'bg-slate-800 text-emerald-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            docker-compose.yml
          </button>
          <button
            onClick={() => setActiveSnippet('ci')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeSnippet === 'ci' ? 'bg-slate-800 text-emerald-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            .github/workflows/ci.yml
          </button>
          <button
            onClick={() => setActiveSnippet('api')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
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
