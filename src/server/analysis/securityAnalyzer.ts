import { Finding } from '../../types';
import { JsTsAstAnalyzer } from './jsTsAstAnalyzer';
import { PythonAstAnalyzer } from './pythonAstAnalyzer';
import { DependencyScanner } from './dependencyScanner';
import { JavaScriptParser } from './parsers/javascriptParser';
import { PythonParser } from './parsers/pythonParser';

export interface FileInput {
  path: string;
  content: string;
}

export class SecurityAnalyzer {
  public static analyzeFile(file: FileInput, scanId: string): Finding[] {
    const findings: Finding[] = [];
    const flaggedLines = new Set<string>(); // key: `${lineNum}:${cwe}` to prevent duplicate findings

    // Helper to record finding
    const addFinding = (f: Finding) => {
      const key = `${f.lineNumber}:${f.cwe || f.title}`;
      if (!flaggedLines.has(key)) {
        flaggedLines.add(key);
        findings.push(f);
      }
    };

    // 1. Software Composition Analysis (SCA) for dependencies
    const scaFindings = DependencyScanner.scanFile(file, scanId);
    scaFindings.forEach(addFinding);

    // 2. Abstract Syntax Tree (AST) Analysis for JS/TS
    if (/\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(file.path)) {
      const astFindings = JsTsAstAnalyzer.analyze(file, scanId);
      astFindings.forEach(addFinding);
      const parsedFindings = JavaScriptParser.parseAndAnalyze({
        filePath: file.path,
        scanId,
        sourceContent: file.content,
        language: 'JavaScript',
      });
      parsedFindings.forEach(addFinding);
    }

    // 3. Abstract Syntax Tree (AST) Analysis for Python
    if (file.path.endsWith('.py')) {
      const pyAstFindings = PythonAstAnalyzer.analyze(file, scanId);
      pyAstFindings.forEach(addFinding);
      const parsedPyFindings = PythonParser.parseAndAnalyze({
        filePath: file.path,
        scanId,
        sourceContent: file.content,
        language: 'Python',
      });
      parsedPyFindings.forEach(addFinding);
    }

    // 4. Heuristic pattern engine for universal coverage (e.g. env files, SQL scripts, YAML, additional rules)
    const lines = file.content.split('\n');

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('/*')) {
        return;
      }

      // 4a. Hardcoded Secrets detection
      const secretRegexes = [
        {
          pattern: /(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd|db[_-]?pass)\s*[:=]\s*["']([^"'\s]{8,})["']/i,
          title: 'Potential Hard-Coded Secret / API Key',
          description: 'High-entropy secret or credential appears to be hard-coded in source code instead of using environment variables.',
          severity: 'HIGH' as const,
          cwe: 'CWE-798: Use of Hard-coded Credentials',
          owaspCategory: 'A07:2021-Identification and Authentication Failures',
          recommendation: 'Store sensitive credentials in environment variables (e.g. process.env or .env) or use a dedicated secrets manager (AWS Secrets Manager, GCP Secret Manager).'
        },
        {
          pattern: /(AKIA[0-9A-Z]{16})/,
          title: 'Exposed AWS Access Key ID',
          description: 'Hardcoded AWS Access Key ID detected. If pushed to version control, cloud infrastructure may be compromised.',
          severity: 'CRITICAL' as const,
          cwe: 'CWE-798: Use of Hard-coded Credentials',
          owaspCategory: 'A07:2021-Identification and Authentication Failures',
          recommendation: 'Immediately revoke the key in AWS IAM and switch to IAM Roles or ephemeral STS credentials.'
        },
        {
          pattern: /ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,}/,
          title: 'Exposed GitHub Personal Access Token',
          description: 'A GitHub Personal Access Token was found in source code.',
          severity: 'CRITICAL' as const,
          cwe: 'CWE-798: Use of Hard-coded Credentials',
          owaspCategory: 'A07:2021-Identification and Authentication Failures',
          recommendation: 'Revoke this token immediately in GitHub settings and load it via secure environment variables.'
        },
        {
          pattern: /https:\/\/hooks\.slack\.com\/services\/T[0-9a-zA-Z_]+\/B[0-9a-zA-Z_]+\/[0-9a-zA-Z_]+/,
          title: 'Exposed Slack Webhook URL',
          description: 'Slack incoming webhook URL found hardcoded, permitting unauthorized message posting.',
          severity: 'HIGH' as const,
          cwe: 'CWE-798: Use of Hard-coded Credentials',
          owaspCategory: 'A07:2021-Identification and Authentication Failures',
          recommendation: 'Store webhook URLs in server-side secret stores.'
        },
        {
          pattern: /-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----/,
          title: 'Hardcoded Cryptographic Private Key',
          description: 'Asymmetric private key material committed directly to repository source.',
          severity: 'CRITICAL' as const,
          cwe: 'CWE-312: Cleartext Storage of Sensitive Information',
          owaspCategory: 'A02:2021-Cryptographic Failures',
          recommendation: 'Remove private keys from source control and store in encrypted key vaults.'
        }
      ];

      for (const rule of secretRegexes) {
        if (rule.pattern.test(line)) {
          addFinding({
            id: `sec-key-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: rule.severity,
            title: rule.title,
            description: rule.description,
            filePath: file.path,
            lineNumber: lineNum,
            codeSnippet: line.trim(),
            recommendation: rule.recommendation,
            cwe: rule.cwe,
            owaspCategory: rule.owaspCategory,
            analysisMethod: 'HEURISTIC'
          });
          break;
        }
      }

      // 4b. Raw SQL Injection String Concatenation
      const sqlInjectionRules = [
        {
          pattern: /(SELECT\s+.*?\s+FROM|INSERT\s+INTO|UPDATE\s+.*?\s+SET|DELETE\s+FROM)\s*.*?(\+\s*[a-zA-Z0-9_.]+|\$\{[a-zA-Z0-9_.]+\}|%s)/i,
          title: 'Potential SQL Injection Risk (Dynamic Query Concatenation)',
          description: 'SQL statement constructed dynamically by string concatenation or template literal substitution without parameter binding.',
          severity: 'CRITICAL' as const,
          cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
          owaspCategory: 'A03:2021-Injection',
          recommendation: 'Use parameterized queries / prepared statements (e.g. $1, ?, :param) or an ORM like Prisma / Drizzle / SQLAlchemy.'
        }
      ];

      for (const rule of sqlInjectionRules) {
        if (rule.pattern.test(line)) {
          // Verify it's not a safe parameterized query line
          if (!line.includes('$1') && !line.includes('?') && !line.includes(':id')) {
            addFinding({
              id: `sec-sqli-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
              scanId,
              category: 'SECURITY',
              severity: rule.severity,
              title: rule.title,
              description: rule.description,
              filePath: file.path,
              lineNumber: lineNum,
              codeSnippet: line.trim(),
              recommendation: rule.recommendation,
              cwe: rule.cwe,
              owaspCategory: rule.owaspCategory,
              analysisMethod: 'HEURISTIC'
            });
            break;
          }
        }
      }

      // 4c. Arbitrary Code Execution (eval, new Function)
      const evalRules = [
        {
          pattern: /\b(eval\s*\([^)]*|new\s+Function\s*\([^)]*|window\.eval\s*\()/i,
          title: 'Arbitrary Code Execution via eval()',
          description: 'Dynamic execution of untrusted input using eval() or new Function() allows full runtime takeover.',
          severity: 'HIGH' as const,
          cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
          owaspCategory: 'A03:2021-Injection',
          recommendation: 'Refactor to eliminate dynamic code evaluation. Use JSON.parse() for data interchange or predefined handler mappings.'
        }
      ];

      for (const rule of evalRules) {
        if (rule.pattern.test(line)) {
          addFinding({
            id: `sec-eval-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: rule.severity,
            title: rule.title,
            description: rule.description,
            filePath: file.path,
            lineNumber: lineNum,
            codeSnippet: line.trim(),
            recommendation: rule.recommendation,
            cwe: rule.cwe,
            owaspCategory: rule.owaspCategory,
            analysisMethod: 'HEURISTIC'
          });
          break;
        }
      }

      // 4d. Command Injection
      const commandExecRules = [
        {
          pattern: /(exec\s*\(\s*["'`].*?\+|child_process\.exec\s*\(|os\.system\s*\(|subprocess\.Popen\s*\(.*?shell\s*=\s*True)/i,
          title: 'Potential Command Injection Risk',
          description: 'Operating system command is executed with concatenated user arguments, allowing shell metacharacter execution (; && | `).',
          severity: 'CRITICAL' as const,
          cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
          owaspCategory: 'A03:2021-Injection',
          recommendation: 'Use execFile or subprocess with argument arrays instead of invoking an interactive shell, and validate user input strictly.'
        }
      ];

      for (const rule of commandExecRules) {
        if (rule.pattern.test(line)) {
          addFinding({
            id: `sec-cmd-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: rule.severity,
            title: rule.title,
            description: rule.description,
            filePath: file.path,
            lineNumber: lineNum,
            codeSnippet: line.trim(),
            recommendation: rule.recommendation,
            cwe: rule.cwe,
            owaspCategory: rule.owaspCategory,
            analysisMethod: 'HEURISTIC'
          });
          break;
        }
      }

      // 4e. Unsafe Deserialization
      const deserializationRules = [
        {
          pattern: /(pickle\.loads|yaml\.load\([^,)]+\)|unserialize\(|Object\.assign\(\s*\{\}\s*,\s*req\.body)/,
          title: 'Potential Unsafe Deserialization / Mass Assignment',
          description: 'Deserializing untrusted data without schema validation can lead to remote code execution or prototype pollution.',
          severity: 'HIGH' as const,
          cwe: 'CWE-502: Deserialization of Untrusted Data',
          owaspCategory: 'A08:2021-Software and Data Integrity Failures',
          recommendation: 'Use safe serialization formats (JSON) and validate inputs with schemas like Zod or Pydantic. Use yaml.safe_load().'
        }
      ];

      for (const rule of deserializationRules) {
        if (rule.pattern.test(line)) {
          addFinding({
            id: `sec-deser-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: rule.severity,
            title: rule.title,
            description: rule.description,
            filePath: file.path,
            lineNumber: lineNum,
            codeSnippet: line.trim(),
            recommendation: rule.recommendation,
            cwe: rule.cwe,
            owaspCategory: rule.owaspCategory,
            analysisMethod: 'HEURISTIC'
          });
          break;
        }
      }

      // 4f. Weak Cryptography & Insecure PRNG
      const weakCryptoRules = [
        {
          pattern: /(createHash\s*\(\s*["'](md5|sha1)["']\)|hashlib\.(md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1)["']\))/i,
          title: 'Weak Cryptographic Hash Algorithm (MD5 / SHA-1)',
          description: 'MD5 and SHA-1 have known collision and preimage attacks and must not be used for authentication or passwords.',
          severity: 'MEDIUM' as const,
          cwe: 'CWE-328: Use of Weak Hash',
          owaspCategory: 'A02:2021-Cryptographic Failures',
          recommendation: 'Use modern hash functions like SHA-256/SHA-512 for integrity, and Argon2id or bcrypt for password hashing.'
        },
        {
          pattern: /Math\.random\(\)/,
          title: 'Cryptographically Insecure Pseudorandom Generator',
          description: 'Math.random() is predictable and unsafe for security-critical tokens, password resets, or session IDs.',
          severity: 'LOW' as const,
          cwe: 'CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator',
          owaspCategory: 'A02:2021-Cryptographic Failures',
          recommendation: 'Use crypto.randomBytes() (Node.js/Python secrets) or window.crypto.getRandomValues().'
        }
      ];

      for (const rule of weakCryptoRules) {
        if (rule.pattern.test(line)) {
          addFinding({
            id: `sec-crypto-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: rule.severity,
            title: rule.title,
            description: rule.description,
            filePath: file.path,
            lineNumber: lineNum,
            codeSnippet: line.trim(),
            recommendation: rule.recommendation,
            cwe: rule.cwe,
            owaspCategory: rule.owaspCategory,
            analysisMethod: 'HEURISTIC'
          });
          break;
        }
      }

      // 4g. Cross-Site Scripting (XSS)
      const xssRules = [
        {
          pattern: /(innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)/i,
          title: 'Cross-Site Scripting (XSS) Risk',
          description: 'Directly inserting unsanitized content into the Document Object Model allows script execution.',
          severity: 'HIGH' as const,
          cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
          owaspCategory: 'A03:2021-Injection',
          recommendation: 'Use textContent, or sanitize untrusted HTML using DOMPurify before DOM insertion.'
        }
      ];

      for (const rule of xssRules) {
        if (rule.pattern.test(line)) {
          addFinding({
            id: `sec-xss-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: rule.severity,
            title: rule.title,
            description: rule.description,
            filePath: file.path,
            lineNumber: lineNum,
            codeSnippet: line.trim(),
            recommendation: rule.recommendation,
            cwe: rule.cwe,
            owaspCategory: rule.owaspCategory,
            analysisMethod: 'HEURISTIC'
          });
          break;
        }
      }

      // 4h. Insecure CORS
      const corsRules = [
        {
          pattern: /(Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"].*credentials|origin\s*:\s*['"]\*['"].*credentials\s*:\s*true)/i,
          title: 'Insecure CORS Configuration with Wildcard and Credentials',
          description: 'Allowing wildcard Access-Control-Allow-Origin with credentials allows any third-party website to make authenticated cross-origin requests.',
          severity: 'HIGH' as const,
          cwe: 'CWE-942: Permissive Cross-domain Policy with Untrusted Domains',
          owaspCategory: 'A01:2021-Broken Access Control',
          recommendation: 'Specify exact trusted origin domains and avoid wildcard configurations when credentials are supported.'
        }
      ];

      for (const rule of corsRules) {
        if (rule.pattern.test(line)) {
          addFinding({
            id: `sec-cors-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: rule.severity,
            title: rule.title,
            description: rule.description,
            filePath: file.path,
            lineNumber: lineNum,
            codeSnippet: line.trim(),
            recommendation: rule.recommendation,
            cwe: rule.cwe,
            owaspCategory: rule.owaspCategory,
            analysisMethod: 'HEURISTIC'
          });
          break;
        }
      }

      // 4i. Path Traversal & Unsafe File Reading
      const pathTraversalRules = [
        {
          pattern: /(fs\.readFileSync|fs\.readFile|open)\s*\(\s*(path\.join\(.*req\.|req\.(query|params|body)|request\.(GET|POST))/i,
          title: 'Potential Path Traversal in File Access',
          description: 'Filesystem operation directly incorporates client-controlled paths without sanitization or path.resolve containment checks.',
          severity: 'HIGH' as const,
          cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
          owaspCategory: 'A01:2021-Broken Access Control',
          recommendation: 'Sanitize file paths with path.basename() and verify that path.resolve() stays strictly within an approved base directory.'
        }
      ];

      for (const rule of pathTraversalRules) {
        if (rule.pattern.test(line)) {
          addFinding({
            id: `sec-path-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: rule.severity,
            title: rule.title,
            description: rule.description,
            filePath: file.path,
            lineNumber: lineNum,
            codeSnippet: line.trim(),
            recommendation: rule.recommendation,
            cwe: rule.cwe,
            owaspCategory: rule.owaspCategory,
            analysisMethod: 'HEURISTIC'
          });
          break;
        }
      }
    });

    return findings;
  }
}
