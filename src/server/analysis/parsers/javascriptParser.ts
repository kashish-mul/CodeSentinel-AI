import ts from 'typescript';
import { Finding } from '../../../types';
import { SecurityRuleContext } from './parserTypes';
import { CommonSecurityRules } from '../rules/commonSecurityRules';

export class JavaScriptParser {
  public static parseAndAnalyze(ctx: SecurityRuleContext): Finding[] {
    const findings: Finding[] = [];
    const fileName = ctx.filePath;

    // First run common pattern rules
    findings.push(...CommonSecurityRules.evaluateAll(ctx));

    // TypeScript Compiler AST Traversal
    try {
      const isJsx = fileName.endsWith('.tsx') || fileName.endsWith('.jsx');
      const sourceFile = ts.createSourceFile(
        fileName,
        ctx.sourceContent,
        ts.ScriptTarget.Latest,
        true,
        isJsx ? ts.ScriptKind.TSX : ts.ScriptKind.TS
      );

      const getLine = (node: ts.Node): number => {
        const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
        return line + 1;
      };

      const visit = (node: ts.Node) => {
        // 1. Call Expressions: eval, Function, child_process.exec
        if (ts.isCallExpression(node)) {
          const calleeText = node.expression.getText(sourceFile);
          const lineNum = getLine(node);

          if (calleeText === 'eval' || calleeText === 'Function' || calleeText === 'window.eval') {
            if (!findings.some(f => f.lineNumber === lineNum && f.title.includes('eval()'))) {
              findings.push({
                id: `ast-eval-${ctx.scanId}-${lineNum}`,
                scanId: ctx.scanId,
                category: 'SECURITY',
                severity: 'HIGH',
                title: 'Arbitrary Code Execution via eval() [AST Verified]',
                description: `AST CallExpression Node (${calleeText}) executes arbitrary string expressions with current runtime privileges.`,
                filePath: ctx.filePath,
                lineNumber: lineNum,
                codeSnippet: node.getText(sourceFile).split('\n')[0].substring(0, 100),
                recommendation: 'Replace eval() with safe JSON.parse() or structured domain data processors.',
                cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
                owaspCategory: 'A03:2021-Injection',
                astNodeType: 'CallExpression (eval)',
                analysisMethod: 'AST',
              });
            }
          }
        }

        ts.forEachChild(node, visit);
      };

      visit(sourceFile);
    } catch (err) {
      console.warn(`[JavaScriptParser] AST traversal warning on ${fileName}:`, err);
    }

    return findings;
  }
}
