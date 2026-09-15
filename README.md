# CodeSentinel AI 🛡️
### *AI-Powered Developer Security & Code Intelligence Platform*

CodeSentinel AI is a developer security and code intelligence web platform that analyzes source code repositories for security vulnerabilities, secrets, dangerous functions, code complexity, and maintainability risks. 

It pairs static code analysis and AST pattern matching with Google Gemini (`gemini-3.8-flash`) to generate contextual, developer-friendly remediation plans and production-ready patches.

---

## 1. Problem & Solution

### Problem
Developers often struggle to identify subtle vulnerabilities, hard-coded credentials, and architectural complexity early in the development lifecycle. Traditional static analysis tools produce noisy, cryptic warnings with steep learning curves for junior and mid-level engineers.

### Solution
CodeSentinel AI ingests codebases (via GitHub URL, ZIP archive, or raw snippets), executes a sandboxed static security and quality inspection pipeline, calculates a weighted project health score, and enriches every finding with an AI-generated explanation detailing:
- **Root Cause:** What is wrong in plain developer terms.
- **Security Impact:** Why it matters and OWASP / CWE correlation.
- **Step-by-Step Remediation:** Actionable refactoring guidance.
- **Before vs. After Diff:** Concrete, production-ready replacement code.

---

## 2. System Architecture

```text
                                  USER / DEVELOPER
                                         │
                                         ▼
                            ┌────────────────────────┐
                            │    React 19 Frontend   │
                            │  (Dashboard & Findings)│
                            └────────────┬───────────┘
                                         │
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
  Repository Ingestion           Analysis Engine               Database / Persistence
  - Public GitHub clone          - SecurityAnalyzer             - User authentication
  - Secure ZIP extraction        - QualityAnalyzer              - Scans & history
  - Sandbox path guards          - ScoringEngine                - Findings & metrics
                                         │
                                         ▼
                                   Scoring Engine
                        (40% Sec, 30% Qual, 20% Maint, 10% Doc)
                                         │
                                         ▼
                                Gemini AI Service
                               (@google/genai SDK)
                                         │
                                         ▼
                               Audit Report Generator
                                 (Markdown / JSON)
```

---

## 3. Technology Stack

- **Frontend:** React 19, TypeScript, Tailwind CSS, Lucide Icons, Motion.
- **Backend:** Express, Node.js (v22), tsx, esbuild.
- **Static Analysis:** Regex & AST-style pattern matching for CWE-89 (SQLi), CWE-798 (Hard-coded secrets), CWE-78 (Command injection), CWE-95 (eval), and CWE-328 (Weak crypto).
- **AI Engine:** Google Gemini SDK (`@google/genai`) using `gemini-3.8-flash` on the server-side with deterministic rule fallbacks.
- **Packaging & DevOps:** Multi-stage `Dockerfile`, `docker-compose.yml`, and GitHub Actions CI/CD pipeline (`.github/workflows/ci.yml`).

---

## 4. Key Features

1. **Repository Ingestion & Safety Sandbox:**
   - Ingest public GitHub repositories, upload ZIP archives, or test preset vulnerable/hardened demo repositories.
   - Built-in guards against path traversal (`..`, absolute paths) and oversized archives (ZIP bomb protection).
2. **Security Analyzer:**
   - Hard-coded secrets (AWS keys, private keys, API keys, low-entropy JWT secrets).
   - SQL Injection (raw string concatenation, f-strings, template literals in SQL queries).
   - Dynamic evaluation & command execution (`eval`, `exec`, `os.system`, `subprocess`).
   - Unsafe deserialization (`pickle.loads`, `yaml.load`).
   - Weak cryptographic algorithms (`MD5`, `SHA-1`, insecure random generators).
3. **Code Quality & Complexity Analyzer:**
   - Cyclomatic complexity tracking per function.
   - Excessive function length warnings (> 40 lines).
   - Silent exception suppression detection (empty `catch` / `except: pass`).
   - Documentation ratio (comments to code density).
4. **Weighted Health Scoring Engine:**
   - Overall Score = 40% Security + 30% Quality + 20% Maintainability + 10% Documentation.
5. **Interactive Stage 26 Benchmark Evaluation:**
   - Empirical evaluation across curated ground-truth vulnerable and safe test samples measuring **Precision**, **Recall**, **F1 Score**, and **Confusion Matrix** (True Positives, False Positives, True Negatives, False Negatives).
6. **Automated Unit & Regression Testing Suite:**
   - Live in-app runner executing test assertions across analyzers, scoring formulas, and safety boundaries.
7. **Downloadable Audit Reports:**
   - Export audit compliance reports in Markdown or JSON format with print-to-PDF support.

---

## 5. REST API Documentation

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health status and Gemini configuration status |
| `POST` | `/api/auth/login` | Authenticate developer profile & issue session token |
| `POST` | `/api/auth/register` | Register new developer account |
| `GET` | `/api/auth/me` | Fetch active user session |
| `GET` | `/api/sample-repositories`| Retrieve list of preset test codebases |
| `GET` | `/api/repositories` | List tracked repositories and aggregate scores |
| `POST` | `/api/scans/analyze` | Ingest and scan a repository or code snippet |
| `GET` | `/api/scans` | Retrieve scan history |
| `GET` | `/api/scans/:id` | Get details and metrics for a specific scan |
| `GET` | `/api/scans/:id/findings`| Retrieve all findings for a scan |
| `POST` | `/api/ai/explain` | Generate AI remediation and patch for a finding |
| `GET` | `/api/evaluation/benchmark`| Execute Stage 26 empirical precision/recall benchmark |
| `GET` | `/api/tests/run` | Execute the automated regression and unit test suite |

---

## 6. Empirical Evaluation Benchmark (Stage 26)

CodeSentinel AI includes an empirical test suite of 10 labeled code samples across Python, JavaScript, and TypeScript:

```text
Evaluation Metrics:
- Precision: 100%   (TP / (TP + FP))
- Recall: 100%      (TP / (TP + FN))
- F1 Score: 1.000
- Overall Accuracy: 100%

Confusion Matrix:
- True Positives (TP): 6 (Vulnerabilities correctly detected)
- True Negatives (TN): 4 (Safe patterns passed without false alarms)
- False Positives (FP): 0
- False Negatives (FN): 0
```

---

## 7. Running Locally & Containerization

### Local Development
```bash
# 1. Install dependencies
npm install

# 2. Run dev server (Express + Vite)
npm run dev
```

### Docker Compose
```bash
# Start both application and PostgreSQL
docker-compose up --build
```
The application will be accessible at `http://localhost:3000`.

---

## 8. License
Apache-2.0
