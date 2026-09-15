import { Finding, AIRemediation } from '../../../types';
import { PatchService } from './patchService';

export class ExplanationService {
  public static generateFallback(finding: Finding): AIRemediation {
    const isSql = finding.cwe?.includes('89') || finding.title.toLowerCase().includes('sql');
    const isXss = finding.cwe?.includes('79') || finding.title.toLowerCase().includes('xss');
    const isCmd = finding.cwe?.includes('78') || finding.title.toLowerCase().includes('command');
    const isSecret = finding.cwe?.includes('798') || finding.title.toLowerCase().includes('secret');
    const isDep = finding.category === 'DEPENDENCY' || Boolean(finding.dependencyInfo);

    let problemExplanation = `AST inspection flagged dynamic construction in ${finding.filePath} at line ${finding.lineNumber}.`;
    let securityImpact = 'Unauthorized manipulation of execution flow or sensitive asset access.';
    let stepByStepFix = [
      'Isolate untrusted variables from executable commands or queries.',
      'Apply standard parameterization, encoding, or safe library wrappers.',
      'Run regression unit tests to verify behavior.'
    ];
    let remediatedCode = finding.codeSnippet;

    if (isSql) {
      problemExplanation = 'Unsanitized string interpolation directly assembles user input into database query statements.';
      securityImpact = 'Allows full SQL injection (CWE-89), enabling remote database dumping, data modification, or privilege escalation.';
      stepByStepFix = [
        'Replace inline string concatenation with parameterized placeholders ($1, ?).',
        'Supply query arguments in a separate parameters array to the database driver.',
        'Enforce least-privilege DB role permissions.'
      ];
      remediatedCode = finding.codeSnippet.replace(/\+\s*[a-zA-Z0-9_.]+|\$\{[^}]+\}/g, '$1');
      if (!remediatedCode.includes('[$1]')) {
        remediatedCode = `db.query("SELECT * FROM table WHERE id = $1", [userId]);`;
      }
    } else if (isXss) {
      problemExplanation = 'Directly rendering unencoded input into DOM nodes creates Cross-Site Scripting (XSS).';
      securityImpact = 'Adversaries can inject arbitrary client JavaScript to steal session tokens, cookies, or redirect victims to phishing portals.';
      stepByStepFix = [
        'Replace innerHTML with textContent for plaintext assignments.',
        'If HTML rendering is necessary, sanitize using DOMPurify.sanitize(input).',
        'Configure a restrictive Content Security Policy (CSP).'
      ];
      remediatedCode = finding.codeSnippet.includes('innerHTML')
        ? finding.codeSnippet.replace('innerHTML', 'textContent')
        : `import DOMPurify from 'dompurify';\nconst safeContent = DOMPurify.sanitize(userInput);`;
    } else if (isCmd) {
      problemExplanation = 'Shell commands are invoked using string concatenation without argument escaping.';
      securityImpact = 'Adversaries can chain command separators (;, |, `) to execute arbitrary OS commands as the application user.';
      stepByStepFix = [
        'Avoid invoking shell interpreters (shell=True or exec).',
        'Use child_process.execFile() or subprocess.run() passing arguments strictly as a list.',
        'Validate input strings against strict alphanumeric character patterns.'
      ];
      remediatedCode = `const { execFile } = require('child_process');\nexecFile('ping', ['-c', '4', host], (err, stdout) => { ... });`;
    } else if (isSecret) {
      problemExplanation = 'Cryptographic keys or access tokens are hardcoded in plaintext within source files.';
      securityImpact = 'Any contributor or attacker viewing git commit history acquires perpetual access to connected cloud infrastructure.';
      stepByStepFix = [
        'Revoke and rotate the exposed credential immediately.',
        'Store secrets in environment variables or cloud secret managers (AWS Secrets Manager / Vault).',
        'Add sensitive config files to .gitignore and install pre-commit secret scanning hooks.'
      ];
      remediatedCode = `const apiKey = process.env.API_KEY || throw new Error("API_KEY required");`;
    } else if (isDep) {
      const dep = finding.dependencyInfo;
      problemExplanation = `The declared package "${dep?.packageName}" (version ${dep?.installedVersion}) contains known CVE advisory ${dep?.cve}.`;
      securityImpact = 'Known public vulnerabilities can be targeted by automated scanning bots and exploit kits.';
      stepByStepFix = [
        `Update "${dep?.packageName}" to safe patched version ${dep?.fixedVersion || 'latest'}.`,
        'Run `npm audit fix` or `pip install -U package` in your environment.',
        'Add automated SCA scans to your CI/CD pull request workflows.'
      ];
      remediatedCode = `"${dep?.packageName}": "^${dep?.fixedVersion}"`;
    }

    const diffSnippet = PatchService.generateUnifiedDiff(
      finding.filePath,
      finding.lineNumber,
      finding.codeSnippet,
      remediatedCode
    );

    return {
      problemExplanation,
      securityImpact,
      stepByStepFix,
      remediatedCode,
      saferAlternativeSnippet: remediatedCode,
      diffSnippet,
      modelUsed: 'AST Deterministic Analyzer',
      generatedAt: new Date().toISOString(),
    };
  }
}
