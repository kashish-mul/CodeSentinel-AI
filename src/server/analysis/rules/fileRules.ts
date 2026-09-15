import { Finding } from '../../../types';
import { SecurityRuleContext } from '../parsers/parserTypes';

export class FileRules {
  public static evaluate(ctx: SecurityRuleContext): Finding[] {
    const findings: Finding[] = [];
    const lines = ctx.sourceContent.split('\n');

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return;

      // 1. Unsanitized file system operations using user parameters
      const isFsCall = /\b(fs\.(readFile|readFileSync|createReadStream|unlink|unlinkSync|writeFile|writeFileSync)|open\s*\()\b/.test(line);
      const hasUserInput = /\b(req\.(query|params|body)|request\.(args|values|form))\b/.test(line);
      const hasSanitization = /path\.normalize|replace\(\/\.\.\//i.test(ctx.sourceContent);

      if (isFsCall && hasUserInput && !hasSanitization) {
        findings.push({
          id: `rule-file-traversal-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'HIGH',
          title: 'Path Traversal Vulnerability in File System Operation',
          description: 'A file read/write operation is supplied an unvalidated user path parameter. Attackers can supply "../" sequences to read arbitrary system files.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Validate paths against a base directory using path.resolve() and verify path.normalize() starts with the allowed root.',
          cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
          owaspCategory: 'A01:2021-Broken Access Control',
          astNodeType: 'CallExpression (fs.readFile)',
          analysisMethod: 'AST',
        });
      }

      // 2. Hardcoded Path Traversal sequence in tests or sensitive logic
      if (/['"](\.\.\/){2,}/.test(line) && !line.includes('import ') && !line.includes('from ')) {
        findings.push({
          id: `rule-file-dotdot-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'MEDIUM',
          title: 'Relative Path Traversal Sequence in String Literal',
          description: 'Repeated directory traversal sequence ("../../") detected in path expression. May access files outside intended root.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Use absolute project root resolutions rather than nested relative parent sequences.',
          cwe: 'CWE-22: Path Traversal',
          owaspCategory: 'A01:2021-Broken Access Control',
          astNodeType: 'Literal (Path)',
          analysisMethod: 'AST',
        });
      }
    });

    return findings;
  }
}
