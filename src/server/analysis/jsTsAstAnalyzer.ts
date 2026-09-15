import ts from 'typescript';
import { Finding } from '../../types';
import { FileInput } from './securityAnalyzer';

export class JsTsAstAnalyzer {
  public static analyze(file: FileInput, scanId: string): Finding[] {
    const findings: Finding[] = [];
    const fileName = file.path;

    // Only run on JS/TS/JSX/TSX files
    if (!/\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(fileName)) {
      return findings;
    }

    try {
      const sourceFile = ts.createSourceFile(
        fileName,
        file.content,
        ts.ScriptTarget.Latest,
        true,
        fileName.endsWith('.tsx') || fileName.endsWith('.jsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
      );

      const getLineNumber = (node: ts.Node): number => {
        const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
        return line + 1;
      };

      const getNodeSnippet = (node: ts.Node): string => {
        return node.getText(sourceFile).trim().split('\n')[0].substring(0, 120);
      };

      const visit = (node: ts.Node) => {
        // 1. Call Expressions: eval, db.query, child_process, crypto, etc.
        if (ts.isCallExpression(node)) {
          const calleeText = node.expression.getText(sourceFile);
          const lineNum = getLineNumber(node);

          // 1a. eval() or Function()
          if (calleeText === 'eval' || calleeText === 'Function' || calleeText === 'window.eval') {
            findings.push({
              id: `ast-eval-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
              scanId,
              category: 'SECURITY',
              severity: 'HIGH',
              title: 'Arbitrary Code Execution via eval() [AST Verified]',
              description: `AST Node: CallExpression ('${calleeText}') executes arbitrary string expressions with current JavaScript runtime privileges.`,
              filePath: file.path,
              lineNumber: lineNum,
              codeSnippet: getNodeSnippet(node),
              recommendation: 'Replace eval() with safe JSON.parse() or structured domain data processors.',
              cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
              owaspCategory: 'A03:2021-Injection',
              astNodeType: 'CallExpression (eval)',
              analysisMethod: 'AST',
            });
          }

          // 1b. SQL Injection in db.query, cursor.execute, rawQuery
          if (/(query|execute|rawQuery|executeSql)$/i.test(calleeText) && node.arguments.length > 0) {
            const firstArg = node.arguments[0];

            // Check if first argument is a BinaryExpression with addition (+) or TemplateExpression
            let isUnsafeQuery = false;
            let astDetail = '';

            if (ts.isBinaryExpression(firstArg) && firstArg.operatorToken.kind === ts.SyntaxKind.PlusToken) {
              isUnsafeQuery = true;
              astDetail = 'BinaryExpression (+) string concatenation';
            } else if (ts.isTemplateExpression(firstArg) && firstArg.templateSpans.length > 0) {
              isUnsafeQuery = true;
              astDetail = 'TemplateExpression (${...}) variable interpolation';
            }

            if (isUnsafeQuery) {
              findings.push({
                id: `ast-sqli-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
                scanId,
                category: 'SECURITY',
                severity: 'CRITICAL',
                title: 'SQL Injection via Dynamic String Construction [AST Verified]',
                description: `AST Node: CallExpression ('${calleeText}') with argument of type ${astDetail}. Dynamic user variables concatenated directly into SQL queries risk full database compromise.`,
                filePath: file.path,
                lineNumber: lineNum,
                codeSnippet: getNodeSnippet(node),
                recommendation: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = $1", [userId]) or prepared statements.',
                cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
                owaspCategory: 'A03:2021-Injection',
                astNodeType: `CallExpression (${calleeText}) -> ${astDetail}`,
                analysisMethod: 'AST',
              });
            }
          }

          // 1c. Command Injection via child_process.exec / execSync
          if (/(child_process\.exec|exec|execSync)$/i.test(calleeText) && node.arguments.length > 0) {
            const firstArg = node.arguments[0];
            let isUnsafeCmd = false;

            if (ts.isBinaryExpression(firstArg) && firstArg.operatorToken.kind === ts.SyntaxKind.PlusToken) {
              isUnsafeCmd = true;
            } else if (ts.isTemplateExpression(firstArg) && firstArg.templateSpans.length > 0) {
              isUnsafeCmd = true;
            }

            if (isUnsafeCmd) {
              findings.push({
                id: `ast-cmd-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
                scanId,
                category: 'SECURITY',
                severity: 'CRITICAL',
                title: 'Command Injection via Shell Execution [AST Verified]',
                description: `AST Node: CallExpression ('${calleeText}') executes an unvalidated shell string formed via dynamic concatenation.`,
                filePath: file.path,
                lineNumber: lineNum,
                codeSnippet: getNodeSnippet(node),
                recommendation: 'Use execFile() or spawn() passing arguments as an array instead of invoking a shell interpreter.',
                cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
                owaspCategory: 'A03:2021-Injection',
                astNodeType: `CallExpression (${calleeText})`,
                analysisMethod: 'AST',
              });
            }
          }

          // 1d. Weak Crypto: createHash('md5') / ('sha1')
          if (/(createHash|crypto\.createHash)$/i.test(calleeText) && node.arguments.length > 0) {
            const firstArgText = node.arguments[0].getText(sourceFile).toLowerCase().replace(/['"]/g, '');
            if (firstArgText === 'md5' || firstArgText === 'sha1') {
              findings.push({
                id: `ast-crypto-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
                scanId,
                category: 'SECURITY',
                severity: 'MEDIUM',
                title: `Weak Cryptographic Hash Algorithm (${firstArgText.toUpperCase()}) [AST Verified]`,
                description: `AST Node: CallExpression ('${calleeText}') initializes broken hash algorithm '${firstArgText}'. Vulnerable to collision attacks.`,
                filePath: file.path,
                lineNumber: lineNum,
                codeSnippet: getNodeSnippet(node),
                recommendation: 'Migrate to SHA-256 or SHA-512 for data integrity, or bcrypt/Argon2 for passwords.',
                cwe: 'CWE-328: Use of Weak Hash',
                owaspCategory: 'A02:2021-Cryptographic Failures',
                astNodeType: `CallExpression (${calleeText} with '${firstArgText}')`,
                analysisMethod: 'AST',
              });
            }
          }

          // 1e. Math.random() for security
          if (calleeText === 'Math.random') {
            findings.push({
              id: `ast-prng-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
              scanId,
              category: 'SECURITY',
              severity: 'LOW',
              title: 'Cryptographically Weak PRNG (Math.random) [AST Verified]',
              description: 'AST Node: CallExpression (Math.random) is predictable and unsuited for generating authentication tokens, salt, or passwords.',
              filePath: file.path,
              lineNumber: lineNum,
              codeSnippet: getNodeSnippet(node),
              recommendation: 'Use crypto.randomBytes() or window.crypto.getRandomValues().',
              cwe: 'CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator',
              owaspCategory: 'A02:2021-Cryptographic Failures',
              astNodeType: 'CallExpression (Math.random)',
              analysisMethod: 'AST',
            });
          }

          // 1f. Server-Side Request Forgery (SSRF) via axios/fetch
          if (/(axios\.get|axios\.post|fetch|http\.get|https\.get)$/i.test(calleeText) && node.arguments.length > 0) {
            const urlArg = node.arguments[0].getText(sourceFile);
            if (/(req\.query|req\.params|req\.body|url_param|user_url)/i.test(urlArg)) {
              findings.push({
                id: `ast-ssrf-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
                scanId,
                category: 'SECURITY',
                severity: 'HIGH',
                title: 'Potential Server-Side Request Forgery (SSRF) [AST Verified]',
                description: `AST Node: CallExpression ('${calleeText}') initiates outbound network requests using untrusted client input '${urlArg}' without allowlist validation.`,
                filePath: file.path,
                lineNumber: lineNum,
                codeSnippet: getNodeSnippet(node),
                recommendation: 'Validate target hosts against a strict server-side allowlist and restrict internal private IP ranges (RFC 1918).',
                cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
                owaspCategory: 'A10:2021-Server-Side Request Forgery',
                astNodeType: `CallExpression (${calleeText} with untrusted input)`,
                analysisMethod: 'AST',
              });
            }
          }
        }

        // 2. Binary Expressions: Assignment to innerHTML / outerHTML (DOM XSS)
        if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
          const leftText = node.left.getText(sourceFile);
          if (/(innerHTML|outerHTML)$/i.test(leftText)) {
            const lineNum = getLineNumber(node);
            findings.push({
              id: `ast-xss-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
              scanId,
              category: 'SECURITY',
              severity: 'HIGH',
              title: 'Cross-Site Scripting (DOM XSS via innerHTML) [AST Verified]',
              description: `AST Node: BinaryExpression assigns unescaped data directly to '${leftText}', exposing web users to script execution.`,
              filePath: file.path,
              lineNumber: lineNum,
              codeSnippet: getNodeSnippet(node),
              recommendation: 'Use textContent or an HTML sanitization library (DOMPurify.sanitize()).',
              cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)',
              owaspCategory: 'A03:2021-Injection',
              astNodeType: `BinaryExpression (= to ${leftText})`,
              analysisMethod: 'AST',
            });
          }
        }

        // 3. React JSX: dangerouslySetInnerHTML
        if (ts.isJsxAttribute(node)) {
          const attrName = node.name.getText(sourceFile);
          if (attrName === 'dangerouslySetInnerHTML') {
            const lineNum = getLineNumber(node);
            findings.push({
              id: `ast-jsx-xss-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
              scanId,
              category: 'SECURITY',
              severity: 'HIGH',
              title: 'React dangerouslySetInnerHTML Usage [AST Verified]',
              description: 'AST Node: JsxAttribute dangerouslySetInnerHTML bypasses React built-in XSS protections.',
              filePath: file.path,
              lineNumber: lineNum,
              codeSnippet: getNodeSnippet(node),
              recommendation: 'Sanitize content with DOMPurify before passing to dangerouslySetInnerHTML, or use safe standard JSX children.',
              cwe: 'CWE-79: Cross-Site Scripting (XSS)',
              owaspCategory: 'A03:2021-Injection',
              astNodeType: 'JsxAttribute (dangerouslySetInnerHTML)',
              analysisMethod: 'AST',
            });
          }
        }

        // 4. Variable Declaration / Secrets: AKIA or API keys in string literals
        if (ts.isVariableDeclaration(node) && node.initializer && ts.isStringLiteral(node.initializer)) {
          const varName = node.name.getText(sourceFile);
          const val = node.initializer.text;
          const lineNum = getLineNumber(node);

          if (/AKIA[0-9A-Z]{16}/.test(val)) {
            findings.push({
              id: `ast-secret-aws-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
              scanId,
              category: 'SECURITY',
              severity: 'CRITICAL',
              title: 'Exposed AWS Access Key in Variable [AST Verified]',
              description: `AST Node: VariableDeclaration ('${varName}') contains a hardcoded AWS Access Key ID literal.`,
              filePath: file.path,
              lineNumber: lineNum,
              codeSnippet: `${varName} = "${val.substring(0, 8)}..."`,
              recommendation: 'Remove credential from source code and load via AWS IAM roles or environment variables.',
              cwe: 'CWE-798: Use of Hard-coded Credentials',
              owaspCategory: 'A07:2021-Identification and Authentication Failures',
              astNodeType: `VariableDeclaration (${varName})`,
              analysisMethod: 'AST',
            });
          } else if (/(api_?key|secret_?key|auth_?token|jwt_?secret|db_?pass|password)/i.test(varName) && val.length >= 10) {
            findings.push({
              id: `ast-secret-key-${scanId}-${lineNum}-${Math.random().toString(36).substr(2, 6)}`,
              scanId,
              category: 'SECURITY',
              severity: 'HIGH',
              title: `Hardcoded Credential in Variable (${varName}) [AST Verified]`,
              description: `AST Node: VariableDeclaration ('${varName}') assigns a sensitive plaintext string credential.`,
              filePath: file.path,
              lineNumber: lineNum,
              codeSnippet: `${varName} = "${val.substring(0, 4)}***"`,
              recommendation: 'Store sensitive credentials in environment variables or cloud secrets management (e.g. process.env).',
              cwe: 'CWE-798: Use of Hard-coded Credentials',
              owaspCategory: 'A07:2021-Identification and Authentication Failures',
              astNodeType: `VariableDeclaration (${varName})`,
              analysisMethod: 'AST',
            });
          }
        }

        ts.forEachChild(node, visit);
      };

      visit(sourceFile);
    } catch (err) {
      console.warn(`[JsTsAstAnalyzer] Parsing failed for ${file.path}:`, err);
    }

    return findings;
  }
}
