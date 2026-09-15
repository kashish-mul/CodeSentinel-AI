import { Finding } from '../../types';
import { FileInput } from './securityAnalyzer';

export class QualityAnalyzer {
  public static analyzeFile(file: FileInput, scanId: string): Finding[] {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');

    let inFunction = false;
    let currentFunctionName = '';
    let functionStartLine = 0;
    let functionLineCount = 0;
    let functionBranchCount = 1; // Base complexity

    // Measure overall file comments and documentation ratio
    let commentLines = 0;
    let codeLines = 0;
    let emptyCatchBlockFound = false;

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const trimmed = line.trim();

      if (!trimmed) return;

      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
        commentLines++;
        return;
      }

      codeLines++;

      // Detect function boundary
      const fnMatch = line.match(/(?:function\s+([a-zA-Z0-9_$]+)|(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|def\s+([a-zA-Z0-9_]+)\s*\()/);
      if (fnMatch) {
        // If we were already in a function, check if the previous one was oversized
        if (inFunction && functionLineCount > 45) {
          findings.push({
            id: `qual-len-${scanId}-${functionStartLine}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'CODE_QUALITY',
            severity: 'MEDIUM',
            title: `Excessive Function Length (${currentFunctionName})`,
            description: `Function '${currentFunctionName}' is ${functionLineCount} lines long, exceeding recommended clean-code threshold (40 lines).`,
            filePath: file.path,
            lineNumber: functionStartLine,
            codeSnippet: `function ${currentFunctionName}() ... [${functionLineCount} lines]`,
            recommendation: 'Refactor and decompose into smaller, single-responsibility helper functions to improve testability and readability.'
          });
        }

        inFunction = true;
        currentFunctionName = fnMatch[1] || fnMatch[2] || fnMatch[3] || 'anonymous';
        functionStartLine = lineNum;
        functionLineCount = 0;
        functionBranchCount = 1;
      }

      if (inFunction) {
        functionLineCount++;

        // Count cyclomatic branches: if, else if, switch, case, catch, for, while, &&, ||, ternary ?
        if (/\b(if|elif|else if|for|while|case|catch)\b/.test(line) || /(\|\||&&|\?)/.test(line)) {
          functionBranchCount++;
        }

        // High cyclomatic complexity check
        if (functionBranchCount >= 10 && lineNum === functionStartLine + 15) {
          findings.push({
            id: `qual-cplx-${scanId}-${functionStartLine}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'MAINTAINABILITY',
            severity: functionBranchCount >= 15 ? 'HIGH' : 'MEDIUM',
            title: `High Cyclomatic Complexity (${currentFunctionName}: CC ${functionBranchCount})`,
            description: `Function '${currentFunctionName}' has high branching complexity (${functionBranchCount} independent decision paths).`,
            filePath: file.path,
            lineNumber: functionStartLine,
            codeSnippet: line.trim(),
            recommendation: 'Reduce nested branching with guard clauses, polymorphic dispatch, or lookup tables.'
          });
        }
      }

      // Check for empty catch blocks
      if (/(catch\s*\([^)]*\)\s*\{\s*\}|except\s*:\s*pass)/.test(line) && !emptyCatchBlockFound) {
        emptyCatchBlockFound = true;
        findings.push({
          id: `qual-catch-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
          scanId,
          category: 'CODE_QUALITY',
          severity: 'MEDIUM',
          title: 'Silent Exception Suppression (Empty Catch Block)',
          description: 'Exceptions are caught and discarded without logging or handling, causing silent failures in production.',
          filePath: file.path,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Log the error with context or rethrow a domain-specific exception to prevent silent data corruption.'
        });
      }

      // Check for lingering debug print/console logs in production source
      if (/(console\.log\(|print\("DEBUG|debugger;)/.test(line)) {
        findings.push({
          id: `qual-dbg-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
          scanId,
          category: 'CODE_QUALITY',
          severity: 'LOW',
          title: 'Development Debugging Statement Present',
          description: 'Leftover debugging statements (console.log / debugger) can leak internal object structures and pollute runtime logs.',
          filePath: file.path,
          lineNumber: lineNum,
          codeSnippet: trimmed,
          recommendation: 'Use a structured logging library with appropriate log levels (debug, info, warn, error) or strip logs during build.'
        });
      }
    });

    // Check overall documentation ratio in file if it's significant
    if (codeLines > 50 && commentLines / codeLines < 0.05) {
      findings.push({
        id: `doc-ratio-${scanId}-1-${Math.random().toString(36).substr(2, 6)}`,
        scanId,
        category: 'DOCUMENTATION',
        severity: 'LOW',
        title: 'Low Documentation & Comment Density',
        description: `File has ${codeLines} lines of code but only ${commentLines} lines of comments (${((commentLines / codeLines) * 100).toFixed(1)}% doc ratio).`,
        filePath: file.path,
        lineNumber: 1,
        codeSnippet: lines[0] || '// File header',
        recommendation: 'Add JSDoc / TypeDoc or PEP 257 docstrings for exported modules, interfaces, and complex algorithms.'
      });
    }

    return findings;
  }
}
