import { Finding } from '../../../types';
import { SecurityRuleContext } from '../parsers/parserTypes';

export class SsrfRules {
  public static evaluate(ctx: SecurityRuleContext): Finding[] {
    const findings: Finding[] = [];
    const lines = ctx.sourceContent.split('\n');

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return;

      // 1. Cloud Instance Metadata IP hardcoded or requested
      if (/169\.254\.169\.254|metadata\.google\.internal/i.test(line)) {
        findings.push({
          id: `rule-ssrf-metadata-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'CRITICAL',
          title: 'Cloud Metadata Service SSRF Target Detected',
          description: 'Reference to Cloud Instance Metadata Service (169.254.169.254). Adversaries exploit SSRF to harvest temporary IAM credentials and cluster secrets.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Block all outbound requests directed at link-local metadata endpoints (169.254.0.0/16) and enforce IMDSv2.',
          cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
          owaspCategory: 'A10:2021-Server-Side Request Forgery',
          astNodeType: 'Literal (Metadata IP)',
          analysisMethod: 'HEURISTIC',
        });
      }

      // 2. Dynamic Outbound Requests with unvalidated user input
      const isHttpCall = /\b(fetch|axios\.(get|post|request)|http\.(get|request)|urllib\.request|requests\.(get|post))\s*\(/.test(line);
      const hasUserInput = /\b(req\.(query|body|params)|request\.(args|json|form)|user_url|target_url)\b/.test(line);
      const hasAllowlist = /validateUrl|isAllowedHost|allowlist|ALLOWED_HOSTS/i.test(ctx.sourceContent);

      if (isHttpCall && hasUserInput && !hasAllowlist) {
        findings.push({
          id: `rule-ssrf-dynamic-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'HIGH',
          title: 'Server-Side Request Forgery (SSRF) via Unvalidated Outbound Request',
          description: 'Server issues outbound HTTP requests to a destination URL directly specified by client parameters without domain allowlisting or private IP blocking.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Validate URLs against an explicit domain allowlist, and block private RFC1918 IPv4 and loopback destinations before issuing network requests.',
          cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
          owaspCategory: 'A10:2021-Server-Side Request Forgery',
          astNodeType: 'CallExpression (HTTP Client)',
          analysisMethod: 'AST',
        });
      }
    });

    return findings;
  }
}
