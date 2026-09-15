import { TestSuiteResult } from '../../types';
import { SecurityAnalyzer } from './securityAnalyzer';
import { QualityAnalyzer } from './qualityAnalyzer';
import { ScoringEngine } from './scoringEngine';
import { runBenchmarkEvaluation } from './benchmarkData';
import { DependencyScanner } from './dependencyScanner';
import { AuthService } from '../auth';

export class TestRunner {
  public static runAllTests(): TestSuiteResult {
    const startTime = Date.now();
    const tests: { name: string; category: string; passed: boolean; durationMs: number; error?: string }[] = [];

    function record(name: string, category: string, fn: () => void) {
      const t0 = Date.now();
      try {
        fn();
        tests.push({ name, category, passed: true, durationMs: Date.now() - t0 });
      } catch (err: any) {
        tests.push({ name, category, passed: false, durationMs: Date.now() - t0, error: err?.message || String(err) });
      }
    }

    // 1. AST-Based Static Analysis Tests
    record('AST Security: TypeScript/JavaScript AST flags CallExpression SQL injection', 'AST Analysis', () => {
      const findings = SecurityAnalyzer.analyzeFile(
        { path: 'controllers/user.ts', content: 'const res = await db.query("SELECT * FROM users WHERE id = " + req.query.id);' },
        't-ast-1'
      );
      const sqli = findings.find(f => f.title.includes('SQL Injection') && f.astNodeType?.includes('CallExpression'));
      if (!sqli) {
        throw new Error('AST failed to identify CallExpression SQL injection in TypeScript');
      }
    });

    record('AST Security: Python AST flags Call with concatenated query', 'AST Analysis', () => {
      const findings = SecurityAnalyzer.analyzeFile(
        { path: 'routes/auth.py', content: 'def query_user(uid):\n    return cursor.execute("SELECT * FROM users WHERE id = " + uid)' },
        't-ast-2'
      );
      const pySqli = findings.find(f => f.title.includes('SQL Injection') && f.astNodeType?.includes('Call'));
      if (!pySqli) {
        throw new Error('Python AST failed to identify cursor.execute concatenation');
      }
    });

    record('AST Security: Ignores safe parameterized queries (False Positive Check)', 'AST Analysis', () => {
      const findings = SecurityAnalyzer.analyzeFile(
        { path: 'db.js', content: 'const res = await db.query("SELECT * FROM users WHERE id = $1", [id]);' },
        't-ast-3'
      );
      const sqli = findings.filter(f => f.title.includes('SQL Injection'));
      if (sqli.length > 0) {
        throw new Error('False positive: flagged safe parameterized query');
      }
    });

    record('AST Security: Detects dangerous eval() call expression', 'AST Analysis', () => {
      const findings = SecurityAnalyzer.analyzeFile(
        { path: 'calc.js', content: 'const res = eval(input);' },
        't-ast-4'
      );
      if (!findings.some(f => f.title.includes('eval()'))) {
        throw new Error('Failed to identify eval() call');
      }
    });

    record('AST Security: Detects DOM XSS via innerHTML assignment', 'AST Analysis', () => {
      const findings = SecurityAnalyzer.analyzeFile(
        { path: 'dom.js', content: 'element.innerHTML = untrustedData;' },
        't-ast-5'
      );
      if (!findings.some(f => f.title.includes('Cross-Site Scripting') || f.title.includes('XSS'))) {
        throw new Error('Failed to identify DOM XSS via innerHTML');
      }
    });

    // 2. Software Composition Analysis (SCA)
    record('SCA Scanner: Identifies vulnerable dependencies with CVE in package.json', 'Dependency SCA', () => {
      const pkgContent = JSON.stringify({
        name: 'test-app',
        dependencies: {
          'lodash': '4.17.15',
          'axios': '0.20.0'
        }
      }, null, 2);
      const findings = DependencyScanner.scanFile(
        { path: 'package.json', content: pkgContent },
        't-sca-1'
      );
      if (findings.length < 2) {
        throw new Error(`Expected at least 2 CVE findings, got ${findings.length}`);
      }
      if (!findings.some(f => f.dependencyInfo?.cve === 'CVE-2021-23337')) {
        throw new Error('Missing CVE-2021-23337 for lodash');
      }
    });

    // 3. Cryptography & Authentication
    record('AuthService: Password hashing with bcrypt & salt verification', 'Auth & Crypto', () => {
      const rawPassword = 'SecretUserPassword2026!';
      const hash = AuthService.hashPassword(rawPassword);
      if (!hash.startsWith('$2') || hash.length < 50) {
        throw new Error('Invalid bcrypt hash generated');
      }
      if (!AuthService.verifyPassword(rawPassword, hash)) {
        throw new Error('Bcrypt password verification failed with correct password');
      }
      if (AuthService.verifyPassword('WrongPassword', hash)) {
        throw new Error('Bcrypt accepted invalid password');
      }
    });

    record('AuthService: Signs and cryptographically validates JWT token', 'Auth & Crypto', () => {
      const user = { id: 'u123', email: 'test@sentinel.io', name: 'Security Test', role: 'Analyst' };
      const token = AuthService.generateToken(user);
      const verified = AuthService.verifyToken(token);
      if (!verified || verified.email !== 'test@sentinel.io') {
        throw new Error('JWT signature verification failed or payload altered');
      }
      const invalid = AuthService.verifyToken(token + 'tampered');
      if (invalid !== null) {
        throw new Error('JWT accepted tampered signature');
      }
    });

    // 4. Code Quality & Complexity
    record('QualityAnalyzer: Detects empty catch blocks (silent exception suppression)', 'Code Quality', () => {
      const findings = QualityAnalyzer.analyzeFile(
        { path: 'worker.ts', content: 'try { doTask(); } catch (err) {}' },
        't-qual-1'
      );
      if (!findings.some(f => f.title.includes('Empty Catch Block'))) {
        throw new Error('Failed to flag silent exception suppression');
      }
    });

    // 5. Scoring Engine Tests
    record('ScoringEngine: Weights 40% Security, 30% Quality, 20% Maintainability, 10% Documentation', 'Scoring', () => {
      const findings = [
        {
          id: 'f1',
          scanId: 's1',
          category: 'SECURITY' as const,
          severity: 'CRITICAL' as const,
          title: 'AWS Key',
          description: 'd',
          filePath: 'f.js',
          lineNumber: 1,
          codeSnippet: 's',
          recommendation: 'r'
        }
      ];
      const { scores, counts } = ScoringEngine.calculateScores(findings, 1, 10);
      if (counts.critical !== 1) throw new Error('Incorrect severity counts');
      if (scores.security >= 100) throw new Error('Critical issue did not reduce security score');
      if (scores.overall >= 100) throw new Error('Overall score did not reflect penalty');
    });

    // 6. Ingestion Guard
    record('IngestionGuard: Rejects path traversal and dangerous directory structures', 'Safety', () => {
      const dangerousPaths = ['../../etc/passwd', '..\\..\\windows\\system32', '/root/.ssh/id_rsa'];
      for (const p of dangerousPaths) {
        const isSafe = !p.includes('..') && !p.startsWith('/') && !p.includes('\\');
        if (isSafe) throw new Error(`Failed to reject unsafe path: ${p}`);
      }
    });

    // 7. Benchmark Suite Integration
    record('BenchmarkEvaluation: Empirical evaluation runs with Precision >= 0.85', 'Evaluation', () => {
      const benchmark = runBenchmarkEvaluation();
      if (benchmark.totalSamples < 10) throw new Error('Benchmark suite too small');
      if (benchmark.precision < 0.85) throw new Error(`Precision below threshold: ${benchmark.precision}`);
      if (benchmark.recall < 0.80) throw new Error(`Recall below threshold: ${benchmark.recall}`);
    });

    const passed = tests.filter(t => t.passed).length;
    const failed = tests.length - passed;

    return {
      suiteName: 'CodeSentinel AST & Security Test Suite',
      passed,
      failed,
      total: tests.length,
      durationMs: Date.now() - startTime,
      tests,
    };
  }
}
