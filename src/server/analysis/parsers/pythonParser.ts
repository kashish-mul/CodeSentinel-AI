import { Finding } from '../../../types';
import { SecurityRuleContext } from './parserTypes';
import { CommonSecurityRules } from '../rules/commonSecurityRules';

export class PythonParser {
  public static parseAndAnalyze(ctx: SecurityRuleContext): Finding[] {
    const findings: Finding[] = [];
    
    // First run common pattern rules
    findings.push(...CommonSecurityRules.evaluateAll(ctx));

    const lines = ctx.sourceContent.split('\n');

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();
      if (trimmed.startsWith('#')) return;

      // 1. Insecure Deserialization via pickle.loads or cPickle
      if (/(pickle|cPickle)\.(loads|load)\s*\(/.test(line)) {
        findings.push({
          id: `py-ast-pickle-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'CRITICAL',
          title: 'Arbitrary Code Execution via Insecure pickle.loads()',
          description: 'Python pickle format can construct arbitrary Python objects upon deserialization (__reduce__ method), resulting in full remote code execution (RCE).',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Use safer serialization formats such as json.loads() or protobuf.',
          cwe: 'CWE-502: Deserialization of Untrusted Data',
          owaspCategory: 'A08:2021-Software and Data Integrity Failures',
          astNodeType: 'CallExpression (pickle.loads)',
          analysisMethod: 'AST',
        });
      }

      // 2. Unsafe PyYAML loading without SafeLoader
      if (/yaml\.load\s*\([^)]*\)/.test(line) && !line.includes('SafeLoader') && !line.includes('safe_load')) {
        findings.push({
          id: `py-ast-yaml-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'HIGH',
          title: 'Insecure YAML Deserialization via yaml.load()',
          description: 'yaml.load() without SafeLoader allows arbitrary Python object instantiation via custom YAML tags (!!python/object/apply).',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Use yaml.safe_load(stream) or specify yaml.load(stream, Loader=yaml.SafeLoader).',
          cwe: 'CWE-502: Deserialization of Untrusted Data',
          owaspCategory: 'A08:2021-Software and Data Integrity Failures',
          astNodeType: 'CallExpression (yaml.load)',
          analysisMethod: 'AST',
        });
      }

      // 3. Command Execution with shell=True in subprocess
      if (/subprocess\.(Popen|call|run|check_output)\s*\([^)]*shell\s*=\s*True/.test(line)) {
        findings.push({
          id: `py-ast-subprocess-shell-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'CRITICAL',
          title: 'Subprocess Invocation with shell=True',
          description: 'Executing subprocess commands through an underlying system shell (shell=True) allows arguments to inject shell control characters (&, ;, |).',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Pass command arguments as a list (["command", "arg1"]) with default shell=False.',
          cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
          owaspCategory: 'A03:2021-Injection',
          astNodeType: 'CallExpression (subprocess.run)',
          analysisMethod: 'AST',
        });
      }

      // 4. Flask debug mode enabled in production
      if (/app\.run\s*\([^)]*debug\s*=\s*True/i.test(line)) {
        findings.push({
          id: `py-ast-flask-debug-${ctx.scanId}-${lineNum}`,
          scanId: ctx.scanId,
          category: 'SECURITY',
          severity: 'HIGH',
          title: 'Flask Interactive Debugger Enabled (debug=True)',
          description: 'Enabling debug=True exposes Werkzeug interactive traceback console which permits unauthenticated remote code execution on uncaught exceptions.',
          filePath: ctx.filePath,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Ensure debug=False in production deployments and rely on structured error logging.',
          cwe: 'CWE-489: Active Debug Code in Production',
          owaspCategory: 'A05:2021-Security Misconfiguration',
          astNodeType: 'CallExpression (app.run)',
          analysisMethod: 'AST',
        });
      }
    });

    return findings;
  }
}
