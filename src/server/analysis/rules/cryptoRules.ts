import { Finding } from '../../../types';
import { SecurityRuleContext } from '../parsers/parserTypes';

export class CryptoRules {
  public static evaluate(ctx: SecurityRuleContext): Finding[] {
    const findings: Finding[] = [];
    const lines = ctx.sourceContent.split('\n');

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return;

      // 1. Weak cryptographic algorithms (MD5 / SHA1)
      if (/(createHash\s*\(\s*['"](md5|sha1)['"]|hashlib\.(md5|sha1)\s*\()/i.test(line)) {
        findings.push({
          id: `rule-crypto-weak-hash-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'HIGH',
          title: 'Vulnerable Cryptographic Hash Function (MD5/SHA-1)',
          description: 'MD5 and SHA-1 suffer from proven collision attacks and are broken for cryptographic integrity or credential hashing.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Upgrade to SHA-256/SHA-512 for data integrity, or Argon2id/bcrypt for password hashing.',
          cwe: 'CWE-328: Use of Weak Hash',
          owaspCategory: 'A02:2021-Cryptographic Failures',
          astNodeType: 'CallExpression (createHash)',
          analysisMethod: 'AST',
        });
      }

      // 2. Insecure Randomness (Math.random for security tokens / keys)
      if (/Math\.random\s*\(\)/.test(line) && /(token|secret|password|nonce|sessionId|salt|auth)/i.test(line)) {
        findings.push({
          id: `rule-crypto-prng-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'MEDIUM',
          title: 'Cryptographically Weak Pseudo-Random Generator (Math.random)',
          description: 'Math.random() is deterministic (Xoroshiro128+ algorithm) and predictable. Attackers can predict future security tokens or authentication nonces.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Use crypto.randomBytes() in Node.js or crypto.getRandomValues() in the browser.',
          cwe: 'CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)',
          owaspCategory: 'A02:2021-Cryptographic Failures',
          astNodeType: 'CallExpression (Math.random)',
          analysisMethod: 'AST',
        });
      }

      // 3. Electronic Codebook (ECB) Mode
      if (/aes-(128|192|256)-ecb/i.test(line)) {
        findings.push({
          id: `rule-crypto-ecb-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'HIGH',
          title: 'Insecure Cipher Mode (AES-ECB)',
          description: 'ECB mode encrypts identical plaintext blocks into identical ciphertext blocks, leaking data patterns and structure.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Use authenticated encryption modes like AES-GCM (Galois/Counter Mode) or ChaCha20-Poly1305 with random nonces.',
          cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
          owaspCategory: 'A02:2021-Cryptographic Failures',
          astNodeType: 'Literal (Cipher Mode)',
          analysisMethod: 'AST',
        });
      }
    });

    return findings;
  }
}
