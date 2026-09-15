import { Finding } from '../../../types';
import { SecurityRuleContext } from '../parsers/parserTypes';

export class XssRules {
  public static evaluate(ctx: SecurityRuleContext): Finding[] {
    const findings: Finding[] = [];
    const lines = ctx.sourceContent.split('\n');

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) return;

      // 1. innerHTML / outerHTML assignment with non-static content
      if (/\b(innerHTML|outerHTML)\s*=\s*/.test(line)) {
        // Safe if assigned a clean static string or sanitized via DOMPurify
        const isSanitized = /DOMPurify\.sanitize/i.test(line) || /sanitizeHtml/i.test(line);
        const isStaticString = /=\s*['"`][^$`]*['"`]\s*;?\s*$/.test(line);

        if (!isSanitized && !isStaticString) {
          findings.push({
            id: `rule-xss-innerhtml-${ctx.scanId}-${lineNum}`,
            scanId: ctx.scanId,
            category: 'SECURITY',
            severity: 'HIGH',
            title: 'DOM Cross-Site Scripting (XSS) via Unsanitized innerHTML',
            description: `Dynamic assignment to innerHTML/outerHTML without sanitization allows malicious script tags or event handlers to execute in user sessions.`,
            filePath: ctx.filePath,
            lineNumber: lineNum,
            codeSnippet: line.trim(),
            recommendation: 'Use safe DOM property textContent, or sanitize untrusted HTML using DOMPurify before inserting.',
            cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)',
            owaspCategory: 'A03:2021-Injection',
            astNodeType: 'PropertyAssignment (innerHTML)',
            analysisMethod: 'AST',
          });
        }
      }

      // 2. React dangerouslySetInnerHTML
      if (/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/.test(line)) {
        if (!/DOMPurify\.sanitize/i.test(line)) {
          findings.push({
            id: `rule-xss-react-${ctx.scanId}-${lineNum}`,
            scanId: ctx.scanId,
            category: 'SECURITY',
            severity: 'HIGH',
            title: 'Reflected/Stored XSS via dangerouslySetInnerHTML',
            description: 'Directly rendering HTML strings via dangerouslySetInnerHTML without sanitization exposes components to arbitrary script injection.',
            filePath: ctx.filePath,
            lineNumber: lineNum,
            codeSnippet: line.trim(),
            recommendation: 'Sanitize content with DOMPurify.sanitize() or refactor into structured React JSX components.',
            cwe: 'CWE-79: Cross-site Scripting',
            owaspCategory: 'A03:2021-Injection',
            astNodeType: 'JsxAttribute (dangerouslySetInnerHTML)',
            analysisMethod: 'AST',
          });
        }
      }

      // 3. document.write / document.writeln
      if (/document\.(write|writeln)\s*\(/.test(line)) {
        findings.push({
          id: `rule-xss-docwrite-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'HIGH',
          title: 'Unsafe DOM Mutation via document.write()',
          description: 'document.write directly writes unparsed text to the document stream, creating severe XSS risks and blocking document parsing.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: line.trim(),
          recommendation: 'Manipulate specific DOM nodes using document.createElement() and node.textContent.',
          cwe: 'CWE-79: Cross-site Scripting',
          owaspCategory: 'A03:2021-Injection',
          astNodeType: 'CallExpression (document.write)',
          analysisMethod: 'AST',
        });
      }
    });

    return findings;
  }
}
