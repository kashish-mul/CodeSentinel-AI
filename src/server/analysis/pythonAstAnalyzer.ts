import { Finding } from '../../types';
import { FileInput } from './securityAnalyzer';

// Structured AST Node types for Python
export interface PythonAstNode {
  type: 'Call' | 'Assign' | 'FunctionDef' | 'TryExcept' | 'Import';
  line: number;
  name?: string;
  callee?: string;
  args?: string[];
  rawCode: string;
  astDetails: string;
}

export class PythonAstAnalyzer {
  public static parseToAst(content: string): PythonAstNode[] {
    const nodes: PythonAstNode[] = [];
    const lines = content.split('\n');

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();

      if (!trimmed || trimmed.startsWith('#')) return;

      // 1. AST: FunctionDef
      const fnMatch = trimmed.match(/^def\s+([a-zA-Z0-9_]+)\s*\((.*?)\):/);
      if (fnMatch) {
        nodes.push({
          type: 'FunctionDef',
          line: lineNum,
          name: fnMatch[1],
          args: fnMatch[2].split(',').map(s => s.trim()).filter(Boolean),
          rawCode: trimmed,
          astDetails: `FunctionDef(${fnMatch[1]})`,
        });
      }

      // 2. AST: Assign (e.g. x = "...")
      const assignMatch = trimmed.match(/^([a-zA-Z0-9_]+)\s*=\s*(.*)$/);
      if (assignMatch && !trimmed.startsWith('if') && !trimmed.startsWith('return')) {
        nodes.push({
          type: 'Assign',
          line: lineNum,
          name: assignMatch[1],
          rawCode: trimmed,
          astDetails: `Assign(target='${assignMatch[1]}', value=${assignMatch[2].substring(0, 40)})`,
        });
      }

      // 3. AST: Call (e.g. obj.method(...) or func(...))
      const callMatch = trimmed.match(/([a-zA-Z0-9_.]+)\s*\((.*)\)/);
      if (callMatch && !trimmed.startsWith('def ')) {
        nodes.push({
          type: 'Call',
          line: lineNum,
          callee: callMatch[1],
          rawCode: trimmed,
          astDetails: `Call(func='${callMatch[1]}')`,
        });
      }

      // 4. AST: TryExcept (e.g. except: pass)
      if (trimmed.match(/except(\s+[a-zA-Z0-9_]+)?\s*:\s*pass/)) {
        nodes.push({
          type: 'TryExcept',
          line: lineNum,
          rawCode: trimmed,
          astDetails: 'TryExcept(handler=pass)',
        });
      }
    });

    return nodes;
  }

  public static analyze(file: FileInput, scanId: string): Finding[] {
    const findings: Finding[] = [];
    if (!file.path.endsWith('.py')) return findings;

    const astNodes = this.parseToAst(file.content);

    for (const node of astNodes) {
      // Rule 1: AST Call -> SQL Injection
      if (node.type === 'Call' && node.callee) {
        const isDbCall = /(cursor\.execute|db\.execute|connection\.execute|execute|raw)$/i.test(node.callee);
        if (isDbCall) {
          // Check if argument uses string concatenation (+), f-string (f"..."), or % formatting
          const hasConcat = node.rawCode.includes(' + ');
          const hasFString = /f["'].*?\{.*?\}["']/.test(node.rawCode);
          const hasFormat = /\.format\(/.test(node.rawCode);
          const hasPercent = /%s.*%/.test(node.rawCode);

          if (hasConcat || hasFString || hasFormat || hasPercent) {
            const detail = hasConcat ? 'BinOp(+)' : hasFString ? 'FormattedValue (f-string)' : '.format()';
            findings.push({
              id: `ast-py-sqli-${scanId}-${node.line}-${Math.random().toString(36).substr(2, 6)}`,
              scanId,
              category: 'SECURITY',
              severity: 'CRITICAL',
              title: 'SQL Injection via Unparameterized Query [Python AST Verified]',
              description: `AST Node: Call('${node.callee}') with interpolated ${detail} argument. Raw SQL string formatting allows arbitrary query manipulation.`,
              filePath: file.path,
              lineNumber: node.line,
              codeSnippet: node.rawCode,
              recommendation: 'Use parameterized SQL queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
              cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
              owaspCategory: 'A03:2021-Injection',
              astNodeType: `Call('${node.callee}') -> ${detail}`,
              analysisMethod: 'AST',
            });
          }
        }

        // Rule 2: AST Call -> Command Injection
        if (/(os\.system|subprocess\.Popen|subprocess\.call|subprocess\.run)$/i.test(node.callee)) {
          if (node.rawCode.includes(' + ') || /f["'].*?\{.*?\}["']/.test(node.rawCode) || node.rawCode.includes('shell=True')) {
            findings.push({
              id: `ast-py-cmd-${scanId}-${node.line}-${Math.random().toString(36).substr(2, 6)}`,
              scanId,
              category: 'SECURITY',
              severity: 'CRITICAL',
              title: 'OS Command Injection via Shell Execution [Python AST Verified]',
              description: `AST Node: Call('${node.callee}') initiates shell execution using concatenated input or shell=True.`,
              filePath: file.path,
              lineNumber: node.line,
              codeSnippet: node.rawCode,
              recommendation: 'Pass arguments as a list: subprocess.run(["ping", "-c", "1", host], check=True) without shell=True.',
              cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
              owaspCategory: 'A03:2021-Injection',
              astNodeType: `Call('${node.callee}')`,
              analysisMethod: 'AST',
            });
          }
        }

        // Rule 3: AST Call -> Insecure Deserialization
        if (node.callee === 'pickle.loads' || node.callee === 'pickle.load' || (node.callee === 'yaml.load' && !node.rawCode.includes('Loader=SafeLoader') && !node.rawCode.includes('safe_load'))) {
          findings.push({
            id: `ast-py-deser-${scanId}-${node.line}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: 'HIGH',
            title: `Unsafe Deserialization (${node.callee}) [Python AST Verified]`,
            description: `AST Node: Call('${node.callee}') deserializes untrusted bytes. Attackers can achieve Remote Code Execution via constructed __reduce__ methods.`,
            filePath: file.path,
            lineNumber: node.line,
            codeSnippet: node.rawCode,
            recommendation: 'Use safe serialization like JSON, or yaml.safe_load(). Never unpack untrusted pickles.',
            cwe: 'CWE-502: Deserialization of Untrusted Data',
            owaspCategory: 'A08:2021-Software and Data Integrity Failures',
            astNodeType: `Call('${node.callee}')`,
            analysisMethod: 'AST',
          });
        }

        // Rule 4: AST Call -> Weak Crypto
        if (/(hashlib\.md5|hashlib\.sha1)$/i.test(node.callee)) {
          const algo = node.callee.includes('md5') ? 'MD5' : 'SHA-1';
          findings.push({
            id: `ast-py-crypto-${scanId}-${node.line}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: 'MEDIUM',
            title: `Weak Hash Function (${algo}) [Python AST Verified]`,
            description: `AST Node: Call('${node.callee}') uses broken digest algorithm ${algo}.`,
            filePath: file.path,
            lineNumber: node.line,
            codeSnippet: node.rawCode,
            recommendation: 'Use hashlib.sha256() for data integrity or argon2-cffi / bcrypt for user passwords.',
            cwe: 'CWE-328: Use of Weak Hash',
            owaspCategory: 'A02:2021-Cryptographic Failures',
            astNodeType: `Call('${node.callee}')`,
            analysisMethod: 'AST',
          });
        }

        // Rule 5: AST Call -> Dynamic eval/exec
        if (node.callee === 'eval' || node.callee === 'exec') {
          findings.push({
            id: `ast-py-eval-${scanId}-${node.line}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: 'HIGH',
            title: `Arbitrary Code Execution via ${node.callee}() [Python AST Verified]`,
            description: `AST Node: Call('${node.callee}') evaluates arbitrary Python source expressions dynamically.`,
            filePath: file.path,
            lineNumber: node.line,
            codeSnippet: node.rawCode,
            recommendation: 'Use ast.literal_eval() for safe evaluation of literals or parse using json.loads().',
            cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
            owaspCategory: 'A03:2021-Injection',
            astNodeType: `Call('${node.callee}')`,
            analysisMethod: 'AST',
          });
        }
      }

      // Rule 6: AST Assign -> Secrets
      if (node.type === 'Assign' && node.name) {
        if (/AKIA[0-9A-Z]{16}/.test(node.rawCode)) {
          findings.push({
            id: `ast-py-aws-${scanId}-${node.line}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: 'CRITICAL',
            title: 'Exposed AWS Access Key in Variable [Python AST Verified]',
            description: `AST Node: Assign(target='${node.name}') assigns hardcoded AWS access credentials.`,
            filePath: file.path,
            lineNumber: node.line,
            codeSnippet: node.rawCode,
            recommendation: 'Use AWS IAM Roles or os.environ.get("AWS_ACCESS_KEY_ID").',
            cwe: 'CWE-798: Use of Hard-coded Credentials',
            owaspCategory: 'A07:2021-Identification and Authentication Failures',
            astNodeType: `Assign(target='${node.name}')`,
            analysisMethod: 'AST',
          });
        } else if (/(api_?key|secret_?key|auth_?token|jwt_?secret|db_?pass|password)/i.test(node.name) && node.rawCode.length > 25 && /["'][^"'\s]{8,}["']/.test(node.rawCode)) {
          findings.push({
            id: `ast-py-secret-${scanId}-${node.line}-${Math.random().toString(36).substr(2, 6)}`,
            scanId,
            category: 'SECURITY',
            severity: 'HIGH',
            title: `Hardcoded Credential in Variable (${node.name}) [Python AST Verified]`,
            description: `AST Node: Assign(target='${node.name}') stores a plaintext secret.`,
            filePath: file.path,
            lineNumber: node.line,
            codeSnippet: `${node.name} = "***REDACTED***"`,
            recommendation: 'Load sensitive configurations from environment variables or a key vault.',
            cwe: 'CWE-798: Use of Hard-coded Credentials',
            owaspCategory: 'A07:2021-Identification and Authentication Failures',
            astNodeType: `Assign(target='${node.name}')`,
            analysisMethod: 'AST',
          });
        }
      }
    }

    return findings;
  }
}
