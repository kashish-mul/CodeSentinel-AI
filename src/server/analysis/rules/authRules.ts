import { Finding } from '../../../types';
import { SecurityRuleContext } from '../parsers/parserTypes';

export class AuthRules {
  public static evaluate(ctx: SecurityRuleContext): Finding[] {
    const findings: Finding[] = [];
    const lines = ctx.sourceContent.split('\n');

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return;

      // 1. Hardcoded JWT Secret
      if (/jwt\.sign\s*\([^,]+,\s*['"][a-zA-Z0-9_-]{3,30}['"]\s*[,)]/.test(line)) {
        findings.push({
          id: `rule-auth-jwt-hardcoded-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'CRITICAL',
          title: 'Hardcoded JWT Signing Secret',
          description: 'A static secret literal is passed to jwt.sign(). Anyone with repository access can forge signed tokens and impersonate any user.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Store JWT signing secrets in environment variables (process.env.JWT_SECRET) with at least 256 bits of entropy.',
          cwe: 'CWE-798: Use of Hard-coded Credentials',
          owaspCategory: 'A07:2021-Identification and Authentication Failures',
          astNodeType: 'CallExpression (jwt.sign)',
          analysisMethod: 'AST',
        });
      }

      // 2. Missing JWT expiration
      if (/jwt\.sign\s*\(/.test(line) && !line.includes('expiresIn') && !ctx.sourceContent.includes('expiresIn:')) {
        findings.push({
          id: `rule-auth-jwt-no-expiry-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'MEDIUM',
          title: 'JWT Issued Without Expiration Time (exp)',
          description: 'Tokens issued without an explicit expiration window remain valid indefinitely if intercepted or leaked.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Specify an explicit expiration option: { expiresIn: "1h" } or { expiresIn: "15m" }.',
          cwe: 'CWE-613: Insufficient Session Expiration',
          owaspCategory: 'A07:2021-Identification and Authentication Failures',
          astNodeType: 'CallExpression (jwt.sign)',
          analysisMethod: 'AST',
        });
      }

      // 3. Overly Permissive CORS with Wildcard
      if (/cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"]\s*,\s*credentials\s*:\s*true/i.test(line) ||
          (/Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]/i.test(line) && ctx.sourceContent.includes('Access-Control-Allow-Credentials'))) {
        findings.push({
          id: `rule-auth-cors-wildcard-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'HIGH',
          title: 'Insecure CORS Policy with Wildcard & Credentials',
          description: 'Configuring Access-Control-Allow-Origin to "*" alongside credentials allows malicious third-party websites to perform authenticated cross-origin requests.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Restrict CORS origins to a verified allowlist of trusted domains.',
          cwe: 'CWE-942: Permissive Cross-domain Policy with Untrusted Domains',
          owaspCategory: 'A01:2021-Broken Access Control',
          astNodeType: 'CallExpression (CORS Config)',
          analysisMethod: 'AST',
        });
      }

      // 4. Low Bcrypt Salt Rounds
      if (/bcrypt\.(hash|genSalt)\s*\([^,]+,\s*([1-8])\s*[,)]/.test(line)) {
        findings.push({
          id: `rule-auth-weak-salt-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'MEDIUM',
          title: 'Insufficient Password Hashing Work Factor (Low Salt Rounds)',
          description: 'Bcrypt salt rounds below 10 fail to provide adequate resistance against modern GPU/ASIC password cracking attacks.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Increase salt work factor to at least 10 or 12 rounds.',
          cwe: 'CWE-916: Use of Password Hash with Insufficient Computational Effort',
          owaspCategory: 'A02:2021-Cryptographic Failures',
          astNodeType: 'CallExpression (bcrypt.genSalt)',
          analysisMethod: 'AST',
        });
      }
    });

    return findings;
  }
}
