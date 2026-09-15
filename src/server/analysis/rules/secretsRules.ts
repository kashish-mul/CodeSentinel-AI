import { Finding } from '../../../types';
import { SecurityRuleContext } from '../parsers/parserTypes';

export class SecretsRules {
  public static evaluate(ctx: SecurityRuleContext): Finding[] {
    const findings: Finding[] = [];
    const lines = ctx.sourceContent.split('\n');

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();
      // Skip comments that describe patterns
      if (trimmed.startsWith('// example') || trimmed.startsWith('# example')) return;

      // 1. AWS Access Key ID
      if (/\bAKIA[0-9A-Z]{16}\b/.test(line)) {
        findings.push({
          id: `rule-secret-aws-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'CRITICAL',
          title: 'Hardcoded AWS Access Key ID Detected',
          description: 'A live AWS Access Key ID (AKIA...) was identified in source code. Attackers crawling public commits can compromise cloud infrastructure.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed.replace(/AKIA[0-9A-Z]{16}/, 'AKIA****************'),
          recommendation: 'Revoke this credential in AWS IAM immediately, audit CloudTrail logs, and use IAM Roles or environment variables.',
          cwe: 'CWE-798: Use of Hard-coded Credentials',
          owaspCategory: 'A07:2021-Identification and Authentication Failures',
          astNodeType: 'Literal (AWS Key)',
          analysisMethod: 'HEURISTIC',
        });
      }

      // 2. Private Cryptographic Key
      if (/-----BEGIN (RSA|OPENSSH|EC|DSA|PGP)?\s*PRIVATE KEY-----/.test(line)) {
        findings.push({
          id: `rule-secret-privkey-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'CRITICAL',
          title: 'Exposed Cryptographic Private Key',
          description: 'Plaintext private key header discovered in repository. Exposes TLS certificates, SSH servers, or signature systems to compromise.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: '-----BEGIN PRIVATE KEY----- [REDACTED]',
          recommendation: 'Remove key from version history, rotate the key pair immediately, and use secret management vaults.',
          cwe: 'CWE-312: Cleartext Storage of Sensitive Information',
          owaspCategory: 'A07:2021-Identification and Authentication Failures',
          astNodeType: 'Literal (Private Key)',
          analysisMethod: 'HEURISTIC',
        });
      }

      // 3. GitHub Personal Access Token
      if (/\bghp_[a-zA-Z0-9]{36}\b/.test(line)) {
        findings.push({
          id: `rule-secret-github-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'CRITICAL',
          title: 'Exposed GitHub Personal Access Token (PAT)',
          description: 'Active GitHub classic PAT detected. Provides write access to repositories and organizations.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed.replace(/ghp_[a-zA-Z0-9]{36}/, 'ghp_************************************'),
          recommendation: 'Revoke the token in GitHub Settings -> Developer settings -> Personal access tokens.',
          cwe: 'CWE-798: Use of Hard-coded Credentials',
          owaspCategory: 'A07:2021-Identification and Authentication Failures',
          astNodeType: 'Literal (GitHub Token)',
          analysisMethod: 'HEURISTIC',
        });
      }

      // 4. Hardcoded High-Entropy Secrets or Passwords
      if (/(password|passwd|api_key|apikey|secret_key|client_secret)\s*[:=]\s*['"][a-zA-Z0-9_!@#$%^&*-]{10,}['"]/i.test(line)) {
        // Skip obvious dummy test strings
        if (!/test|dummy|example|placeholder|todo|your_/i.test(line)) {
          findings.push({
            id: `rule-secret-hardcoded-${ctx.scanId}-${lineNum}`,
            scanId: ctx.scanId,
            category: 'SECURITY',
            severity: 'HIGH',
            title: 'Hardcoded Secret or Password Literal',
            description: 'Source code embeds high-entropy credentials or secrets directly in declaration statements.',
            filePath: ctx.filePath,
            lineNumber: lineNum,
            codeSnippet: trimmed.replace(/['"][a-zA-Z0-9_!@#$%^&*-]{10,}['"]/, '"************"'),
            recommendation: 'Inject credentials at runtime using environment variables or a key management service (KMS).',
            cwe: 'CWE-798: Use of Hard-coded Credentials',
            owaspCategory: 'A07:2021-Identification and Authentication Failures',
            astNodeType: 'VariableDeclaration (Secret)',
            analysisMethod: 'AST',
          });
        }
      }
    });

    return findings;
  }
}
