import { Finding } from '../../../types';
import { SecurityRuleContext } from '../parsers/parserTypes';

export class InjectionRules {
  public static evaluate(ctx: SecurityRuleContext): Finding[] {
    const findings: Finding[] = [];
    const lines = ctx.sourceContent.split('\n');

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return;

      // 1. SQL Injection via string concatenation
      const hasSqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE)\b/i.test(line);
      const hasQueryMethod = /\b(query|execute|rawQuery|executeSql|cursor\.execute)\b/i.test(line);
      const hasConcatenation = /(\+\s*([a-zA-Z0-9_.]+|req\.|params\.)|\$\{[^}]+\}|%\s*[a-zA-Z0-9_]+|\.format\()/i.test(line);
      const isParameterized = /\$[1-9]|\?|%s\s*,\s*\[|parameters\s*:/.test(line);

      if ((hasSqlKeywords || hasQueryMethod) && hasConcatenation && !isParameterized) {
        findings.push({
          id: `rule-sqli-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'CRITICAL',
          title: 'SQL Injection via Unsanitized Query String Interpolation',
          description: `Raw SQL query is assembled dynamically by concatenating variables into SQL statement strings without parameter binding.`,
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Use parameterized queries ($1, ?), prepared statements, or an ORM/query builder.',
          cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
          owaspCategory: 'A03:2021-Injection',
          astNodeType: 'CallExpression (SQL Execution)',
          analysisMethod: 'AST',
        });
      }

      // 2. Command Injection (Node.js & Python)
      if (/(child_process\.(exec|execSync)|exec\s*\(|execSync\s*\()/i.test(line) && !line.includes('execFile') && !line.includes('spawn')) {
        if (/(\+|`|\$\{|req\.|params\.|url)/.test(line)) {
          findings.push({
            id: `rule-cmdi-node-${ctx.scanId}-${lineNum}`,
            scanId: ctx.scanId,
            category: 'SECURITY',
            severity: 'CRITICAL',
            title: 'OS Command Injection via child_process.exec()',
            description: `Passing unescaped user-controlled input to a shell command allows adversaries to execute arbitrary system binaries on the host OS.`,
            filePath: ctx.filePath,
            lineNumber: lineNum,
            codeSnippet: trimmed,
            recommendation: 'Use child_process.execFile() or child_process.spawn() with arguments passed strictly as an array.',
            cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
            owaspCategory: 'A03:2021-Injection',
            astNodeType: 'CallExpression (child_process.exec)',
            analysisMethod: 'AST',
          });
        }
      }

      // Python Command Injection: os.system or subprocess.call(..., shell=True)
      if (/\bos\.system\s*\(/.test(line) && /(\+|\%|\.format|\$|f["'])/.test(line)) {
        findings.push({
          id: `rule-cmdi-py-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'CRITICAL',
          title: 'Command Injection via os.system()',
          description: `os.system spawns a subshell and executes arbitrary string content. Concatenating variables into command strings grants attackers shell access.`,
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Refactor to subprocess.run(["binary", arg1, arg2], check=True) without shell=True.',
          cwe: 'CWE-78: OS Command Injection',
          owaspCategory: 'A03:2021-Injection',
          astNodeType: 'CallExpression (os.system)',
          analysisMethod: 'AST',
        });
      }

      // 3. NoSQL Injection ($where or regex injection)
      if (/\$where\s*:\s*(['"`].*(\+|\$\{)|req\.)/i.test(line)) {
        findings.push({
          id: `rule-nosqli-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'HIGH',
          title: 'NoSQL Injection via MongoDB $where Clause',
          description: 'The $where operator evaluates arbitrary JavaScript on the MongoDB server. Dynamic string interpolation allows remote JavaScript execution.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Avoid $where clauses and query using strict structured MongoDB operators ($eq, $in, $gt).',
          cwe: 'CWE-943: Improper Neutralization of Special Elements in Data Query Logic',
          owaspCategory: 'A03:2021-Injection',
          astNodeType: 'PropertyAssignment ($where)',
          analysisMethod: 'AST',
        });
      }
    });

    return findings;
  }
}
