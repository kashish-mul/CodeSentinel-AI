import { Finding } from '../../types';

export interface FileInput {
  path: string;
  content: string;
}

export class SecurityAnalyzer {
  public static analyzeFile(file: FileInput, scanId: string): Finding[] {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('/*')) {
        // Simple skip for pure comment lines
        return;
      }

      // 1. Hardcoded Secrets detection
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
          pattern: /-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----/,
          title: 'Hardcoded Cryptographic Private Key',
          description: 'Asymmetric private key material committed directly to repository source.',
          severity: 'CRITICAL' as const,
          cwe: 'CWE-312: Cleartext Storage of Sensitive Information',
          owaspCategory: 'A02:2021-Cryptographic Failures',
          recommendation: 'Remove private keys from source control and store in encrypted key vaults.'
        },
        {
          pattern: /jwt\.sign\([^,]+,\s*["'][a-zA-Z0-9_\-!@#$%^&*]{1,16}["']\s*\)/i,
          title: 'Weak / Hardcoded JWT Secret Key',
          description: 'JSON Web Token is signed with a hardcoded, low-entropy secret string.',
          severity: 'HIGH' as const,
          cwe: 'CWE-326: Inadequate Encryption Strength',
          owaspCategory: 'A02:2021-Cryptographic Failures',
          recommendation: 'Use a cryptographically secure random string with at least 256 bits of entropy stored in process.env.JWT_SECRET.'
        }
      ];

      for (const rule of secretRegexes) {
        if (rule.pattern.test(line)) {
          findings.push({
            id: `sec-secret-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
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
            owaspCategory: rule.owaspCategory
          });
          break;
        }
      }

      // 2. SQL Injection Patterns
      const sqlInjectionRules = [
        {
          pattern: /(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+.*(\+|%s|\$|\.format\(|\$\{.*\}|f["'].*\{.*\}.*["'])/i,
          title: 'Potential SQL Injection Risk',
          description: 'SQL statement constructed dynamically using string concatenation, template literals, or formatting rather than parameterized placeholders.',
          severity: 'HIGH' as const,
          cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
          owaspCategory: 'A03:2021-Injection',
          recommendation: 'Always use parameterized queries or an Object-Relational Mapper (ORM) prepared statements (e.g. db.query("SELECT * FROM users WHERE id = $1", [userId])).'
        },
        {
          pattern: /(rawQuery|execute|cursor\.execute|db\.query)\s*\(\s*["'].*(\+|f["']|\$\{)/i,
          title: 'Unparameterized Raw Database Execution',
          description: 'Direct raw query invocation interpolating variables into raw SQL string.',
          severity: 'CRITICAL' as const,
          cwe: 'CWE-89: SQL Injection',
          owaspCategory: 'A03:2021-Injection',
          recommendation: 'Pass arguments in query parameter arrays rather than string interpolation.'
        }
      ];

      for (const rule of sqlInjectionRules) {
        if (rule.pattern.test(line)) {
          findings.push({
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
            owaspCategory: rule.owaspCategory
          });
          break;
        }
      }

      // 3. Dangerous Command Execution & Code Evaluation
      const commandExecRules = [
        {
          pattern: /\b(eval|exec|Function)\s*\(.*\)/,
          title: 'Arbitrary Code Execution via eval() / exec()',
          description: 'Use of eval() or dynamic Function constructors can allow unvalidated strings to execute with process privileges.',
          severity: 'HIGH' as const,
          cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
          owaspCategory: 'A03:2021-Injection',
          recommendation: 'Avoid dynamic code evaluation. Use safe parsing routines such as JSON.parse() or dedicated domain-specific parsers.'
        },
        {
          pattern: /(child_process\.exec|os\.system|subprocess\.Popen|subprocess\.call|Runtime\.getRuntime\(\)\.exec)\s*\(.*(\+|f["']|\$\{)/i,
          title: 'Potential Command Injection Risk',
          description: 'System command executed by interpolating untrusted parameters into shell string.',
          severity: 'CRITICAL' as const,
          cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
          owaspCategory: 'A03:2021-Injection',
          recommendation: 'Use execFile or subprocess with argument arrays instead of invoking an interactive shell, and validate user input strictly.'
        }
      ];

      for (const rule of commandExecRules) {
        if (rule.pattern.test(line)) {
          findings.push({
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
            owaspCategory: rule.owaspCategory
          });
          break;
        }
      }

      // 4. Unsafe Deserialization
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
          findings.push({
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
            owaspCategory: rule.owaspCategory
          });
          break;
        }
      }

      // 5. Weak Cryptographic Algorithms
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
          findings.push({
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
            owaspCategory: rule.owaspCategory
          });
          break;
        }
      }

      // 6. Path Traversal & Unsafe File Reading
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
          findings.push({
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
            owaspCategory: rule.owaspCategory
          });
          break;
        }
      }
    });

    return findings;
  }
}
