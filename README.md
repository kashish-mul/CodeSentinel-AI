# CodeSentinel AI 🛡️
### *Full-Stack Developer Security, AST Static Analysis & Code Intelligence Platform*

CodeSentinel AI is an application security (AppSec) and code quality inspection platform. It analyzes source code repositories for security vulnerabilities (CWE/OWASP), dependency risks (SCA), dangerous function usage, code complexity, and maintainability issues.

It combines multi-layered static analysis (TypeScript Compiler API AST, Python AST visitor, and SCA dependency auditing) with Google Gemini (`gemini-2.5-flash`) to generate contextual remediation plans and Before vs. After code patches.

---

## 1. Core Architecture & Analysis Pipeline

CodeSentinel AI avoids surface-level regex scanning by implementing a layered static analysis architecture:

```text
                                  USER / DEVELOPER
                                         │
                                         ▼
                            ┌────────────────────────┐
                            │    React 19 Frontend   │
                            │  (Dashboard, Diffs, UI)│
                            └────────────┬───────────┘
                                         │  JWT (Bearer Authorization)
                                     REST API
                                         │
                                         ▼
                            ┌────────────────────────┐
                            │  Express / Node Engine │
                            │    (Port 3000 Host)    │
                            └────────────┬───────────┘
                                         │
          ┌──────────────────────────────┼──────────────────────────────┐
          ▼                              ▼                              ▼
  Ingestion Layer                Multi-Layer Engine             Persistence & Auth
  - Recursive GitHub Tree Walker - JsTsAstAnalyzer (TS AST)     - PostgreSQL (pg.Pool)
  - JSZip Archive Processor      - PythonAstAnalyzer (AST)      - Disk Fallback (JSON)
  - Path Traversal Guard         - DependencyScanner (SCA)      - Bcrypt Password Hashing
                                 - Heuristic Fallback           - HMAC SHA-256 JWTs
                                         │
                                         ▼
                                   Scoring Engine
                        (40% Sec, 30% Qual, 20% Maint, 10% Doc)
                                         │
                                         ▼
                                Gemini AI Remediation
                              (Unified & Side-by-Side Diffs)
```

### Analysis Layers:
1. **TypeScript / JavaScript AST Analyzer (`JsTsAstAnalyzer`):**
   - Utilizes `typescript.createSourceFile` and recursive node traversal.
   - Inspects `ts.isCallExpression`, `ts.isBinaryExpression`, and `ts.isPropertyAccessExpression` to identify SQL injection, DOM XSS (`innerHTML`), and arbitrary execution (`eval`).
   - Ignores safe patterns such as parameterized SQL queries (`$1, ?`) and `textContent` assignments to minimize false positives.
2. **Python AST Visitor (`PythonAstAnalyzer`):**
   - Traverses Python constructs (`Call`, `FunctionDef`, `Assign`, `Import`).
   - Identifies raw SQL query concatenation, dangerous OS execution (`os.system`, `subprocess`), unsafe deserialization (`pickle.loads`), and weak hashing algorithms (`hashlib.md5`).
3. **Software Composition Analysis (`DependencyScanner`):**
   - Parses manifest files (`package.json` and `requirements.txt`).
   - Correlates declared dependency version ranges against known CVE advisories (e.g., `CVE-2021-23337`, `CVE-2020-28168`, `CVE-2022-24999`).
4. **Heuristic & Secret Fallback:**
   - Detects exposed cloud credentials, high-entropy tokens, AWS keys (`AKIA...`), and private SSH keys across all text-based source files.
5. **AI Remediation Service (`AIService`):**
   - Integrates with Google Gemini via `@google/genai` to generate technical root cause explanations, threat impact assessments, step-by-step remediation plans, and unified git diffs.
   - Includes a deterministic offline fallback engine ensuring zero downtime when disconnected.

---

## 2. Ingestion & Repository Scanning

- **Recursive GitHub Tree Walker:** Ingests public repositories via `GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1`, filtering relevant source files (`.js`, `.ts`, `.py`, `.sql`, `.json`, etc.) without shell cloning.
- **Truthful Error Handling:** If a repository is private, missing, or rate-limited by GitHub's API, CodeSentinel returns clear HTTP 422 diagnostic errors and prompts the developer to use the ZIP upload workflow, eliminating mock/fake repository fallbacks.
- **ZIP Archive Processing:** Safely extracts client-uploaded ZIP archives using `JSZip` with validation protecting against directory traversal (`../`) and decompression limits.
- **Code Snippet Scratchpad:** Allows immediate ad-hoc inspection of code snippets for rapid testing.

---

## 3. Technology Stack & Dependencies

- **Frontend:** React 19, TypeScript, Tailwind CSS, Lucide Icons, Motion.
- **Backend:** Express, Node.js (v22), `typescript` compiler API, `bcryptjs`, `jsonwebtoken`, `pg`.
- **Database:** PostgreSQL 16 connection pool with automatic initialization and local JSON storage fallback.
- **AI Engine:** `@google/genai` SDK targeting `gemini-2.5-flash`.
- **DevOps:** Multi-stage `Dockerfile`, `docker-compose.yml`, and GitHub Actions CI workflow (`.github/workflows/ci.yml`).

---

## 4. Key Security & Quality Checks

| Vulnerability / Risk | Standard Mapping | Engine Layer |
| :--- | :--- | :--- |
| SQL Injection in raw query concatenation | CWE-89 / OWASP A03:2021 | TypeScript Compiler AST & Python AST |
| DOM Cross-Site Scripting (XSS via innerHTML) | CWE-79 / OWASP A03:2021 | TypeScript AST Visitor |
| Hardcoded Cloud Credentials & AWS Keys | CWE-798 / OWASP A07:2021 | Secret Scanner & Heuristics |
| Arbitrary Code Execution (`eval()`) | CWE-95 / OWASP A03:2021 | TypeScript AST CallExpression |
| Command Injection (`os.system`, `subprocess`) | CWE-78 / OWASP A03:2021 | Python AST Call Visitor |
| Known Vulnerable Dependencies (CVE) | CWE-1395 / OWASP A06:2021| Software Composition Analysis (SCA) |
| Insecure Deserialization (`pickle.loads`) | CWE-502 / OWASP A08:2021 | Python AST Import/Call Visitor |
| Outdated Cryptographic Hash (MD5, SHA-1) | CWE-328 / OWASP A02:2021 | Cryptographic Rule Engine |
| Silent Exception Suppression (Empty catch) | Quality / Clean Code | AST Statement Analyzer |
| High Cyclomatic Complexity & Function Length | Maintainability | Function Metric Engine |

---

## 5. REST API Specification

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Diagnostic status (Postgres connection, Gemini status, AST modules) |
| `POST` | `/api/auth/login` | Authenticate user credentials using Bcrypt & issue signed JWT |
| `POST` | `/api/auth/register` | Register new user account with hashed password persistence |
| `GET` | `/api/auth/me` | Verify and return active user profile from JWT payload |
| `GET` | `/api/repositories` | List tracked repositories and aggregate scan ratings |
| `POST` | `/api/scans/analyze` | Ingest and scan repository (GitHub recursive tree, ZIP, or snippet) |
| `GET` | `/api/scans` | Query scan history and vulnerability severity counts |
| `GET` | `/api/scans/:id` | Fetch detailed scan breakdown, scores, and findings |
| `GET` | `/api/scans/:id/findings`| Retrieve granular list of findings with AST node details |
| `POST` | `/api/ai/explain` | Request Gemini remediation, step-by-step guidance & code diff |
| `POST` | `/api/copilot/ask` | Interactive Security Copilot conversational Q&A for specific findings |
| `GET` | `/api/scans/:id/report` | Generate complete executive audit & remediation report |
| `GET` | `/api/evaluation/benchmark`| Execute 20-sample empirical ground-truth benchmark suite |
| `GET` | `/api/tests/run` | Execute automated AST, SCA, Crypto, and Scoring test suite |

---

## 6. Empirical Benchmark Evaluation

CodeSentinel includes a 20-sample curated ground-truth evaluation dataset spanning Python, JavaScript, TypeScript, and JSON dependency manifests.

Samples include both vulnerable patterns and defensive implementations (such as parameterized SQL queries, Argon2id password hashing, DOMPurify sanitization, and whitelist URL validation) to rigorously measure:
- **Precision:** True Positives / (True Positives + False Positives)
- **Recall:** True Positives / (True Positives + False Negatives)
- **F1 Score:** Harmonic mean of precision and recall
- **Accuracy:** (TP + TN) / (TP + TN + FP + FN)
- **False Positive Rate (FPR):** FP / (FP + TN)
- **False Negative Rate (FNR):** FN / (FN + TP)
- **Category Breakdown:** Granular metrics across Injection, XSS, SSRF, Cryptography, Auth & Secrets, and Path Traversal.

---

## 7. Local Setup & Docker Deployment

### Local Development
```bash
# 1. Install dependencies
npm install

# 2. Configure environment (optional Gemini API key & Postgres URL)
cp .env.example .env

# 3. Start development server (Port 3000)
npm run dev
```

### Docker Compose
```bash
# Start both CodeSentinel web service and PostgreSQL container
docker-compose up --build
```
Access the application at `http://localhost:3000`.

---

## 8. License
Apache-2.0
