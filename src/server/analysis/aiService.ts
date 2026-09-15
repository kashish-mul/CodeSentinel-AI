import { GoogleGenAI } from '@google/genai';
import { AIRemediation, Finding } from '../../types';

let genAIClient: GoogleGenAI | null = null;

function getGeminiClient(): GoogleGenAI | null {
  if (!genAIClient && process.env.GEMINI_API_KEY) {
    genAIClient = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
  }
  return genAIClient;
}

export class AIService {
  public static async explainAndRemediate(finding: Finding): Promise<AIRemediation> {
    const ai = getGeminiClient();

    if (ai) {
      try {
        const prompt = `You are CodeSentinel AI, a senior AppSec and code-quality architect.
Analyze the following static analysis finding detected in a repository:

Finding Title: ${finding.title}
Severity: ${finding.severity}
Category: ${finding.category}
File: ${finding.filePath} (Line ${finding.lineNumber})
Code Snippet:
\`\`\`
${finding.codeSnippet}
\`\`\`
Static Description: ${finding.description}
CWE / OWASP: ${finding.cwe || 'N/A'} - ${finding.owaspCategory || 'N/A'}

Provide a structured, security-focused remediation in valid JSON with these exact keys:
{
  "problemExplanation": "A concise explanation of what is wrong in developer terms (1-2 sentences).",
  "securityImpact": "Why it matters and what threat an attacker or runtime failure introduces.",
  "stepByStepFix": ["Step 1...", "Step 2...", "Step 3..."],
  "remediatedCode": "The fixed, secure replacement code for this snippet.",
  "saferAlternativeSnippet": "A snippet demonstrating the safe pattern/library usage."
}
Return ONLY valid JSON without markdown fences.`;

        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
        });

        const text = response.text || '';
        const cleanedText = text.replace(/```json\s*/g, '').replace(/```\s*$/g, '').trim();

        try {
          const parsed = JSON.parse(cleanedText);
          const remediatedCode = parsed.remediatedCode || '// Secure pattern implemented';
          const diffSnippet = AIService.generateUnifiedDiff(finding.codeSnippet, remediatedCode, finding.filePath);
          return {
            problemExplanation: parsed.problemExplanation || finding.description,
            securityImpact: parsed.securityImpact || 'Could permit unauthorized access or system instability.',
            stepByStepFix: Array.isArray(parsed.stepByStepFix) ? parsed.stepByStepFix : [finding.recommendation],
            remediatedCode,
            saferAlternativeSnippet: parsed.saferAlternativeSnippet || remediatedCode,
            diffSnippet,
            modelUsed: 'gemini-2.5-flash (AI-Assisted Guidance)',
            generatedAt: new Date().toISOString(),
          };
        } catch {
          // Fall through to deterministic remediation if JSON parse failed
        }
      } catch (err) {
        console.warn('Gemini API call encountered an issue, falling back to expert rule remediation:', err);
      }
    }

    // Deterministic Rule-Based Fallback
    return this.getDeterministicRemediation(finding);
  }

  public static generateUnifiedDiff(original: string, remediated: string, filePath: string): string {
    const origLines = original.trim().split('\n').map(l => `- ${l}`).join('\n');
    const fixLines = remediated.trim().split('\n').map(l => `+ ${l}`).join('\n');
    return `--- a/${filePath}\n+++ b/${filePath}\n@@ -1,${original.split('\n').length} +1,${remediated.split('\n').length} @@\n${origLines}\n${fixLines}`;
  }

  private static getDeterministicRemediation(finding: Finding): AIRemediation {
    let problemExplanation = finding.description;
    let securityImpact = 'Unvalidated code patterns can be leveraged by attackers or cause runtime failures.';
    let stepByStepFix: string[] = [
      'Isolate the vulnerable code fragment.',
      'Refactor according to standard secure coding guidelines.',
      'Add an automated regression test covering this pattern.'
    ];
    let remediatedCode = '// Remediated safe implementation';
    let saferAlternativeSnippet = '';

    const title = finding.title.toLowerCase();

    if (title.includes('sql injection')) {
      problemExplanation = 'User-supplied parameters are directly concatenated or interpolated into an SQL query string.';
      securityImpact = 'Attackers can manipulate SQL syntax to bypass authentication, dump database tables, or execute arbitrary commands.';
      stepByStepFix = [
        'Replace string concatenation or template literals with parameterized query place-holders ($1, ?, or named parameters).',
        'Pass user input as a distinct tuple or array into the database driver.',
        'Use an ORM/query builder (e.g. Prisma, SQLAlchemy, Drizzle) where feasible.'
      ];
      remediatedCode = `// Safe Parameterized Query (PostgreSQL pg / psycopg2)
const query = 'SELECT * FROM users WHERE id = $1 AND tenant_id = $2';
const result = await db.query(query, [userId, tenantId]);`;
      saferAlternativeSnippet = remediatedCode;
    } else if (title.includes('secret') || title.includes('aws') || title.includes('token')) {
      problemExplanation = 'Private credentials or API keys are committed directly to repository source files.';
      securityImpact = 'Anyone with read access to the repo or commit history can steal credentials and compromise infrastructure.';
      stepByStepFix = [
        'Immediately rotate and invalidate the exposed secret in the cloud provider console.',
        'Move the secret to a local .env file included in .gitignore.',
        'In production, load credentials via Cloud Secret Manager, AWS IAM Roles, or environment variables.'
      ];
      remediatedCode = `// Fetch secret securely from runtime environment
const apiKey = process.env.API_SECRET_KEY;
if (!apiKey) {
  throw new Error('Required environment variable API_SECRET_KEY is missing');
}`;
      saferAlternativeSnippet = remediatedCode;
    } else if (title.includes('eval') || title.includes('command')) {
      problemExplanation = 'Code dynamically evaluates unsanitized strings or invokes system shell interpreters with arbitrary arguments.';
      securityImpact = 'Remote code execution (RCE) allowing attackers to run arbitrary system commands under the web process user account.';
      stepByStepFix = [
        'Eliminate dynamic eval() calls. Use JSON.parse() or a secure domain expression evaluator.',
        'For process execution, use execFile() or subprocess.run() passing arguments as an array rather than shell strings.',
        'Apply strict input allowlists (e.g. regex ^[a-zA-Z0-9_-]+$).'
      ];
      remediatedCode = `// Safe subprocess execution with arguments array (no shell interpreter)
import { execFile } from 'child_process';
execFile('ping', ['-c', '1', safeHost], (error, stdout) => {
  if (error) console.error(error);
});`;
      saferAlternativeSnippet = remediatedCode;
    } else if (title.includes('cross-site') || title.includes('xss') || title.includes('innerhtml')) {
      problemExplanation = 'Untrusted client content is inserted directly into the DOM without HTML escaping or sanitization.';
      securityImpact = 'Attackers can execute arbitrary JavaScript in the victim’s browser, stealing cookies and session tokens.';
      stepByStepFix = [
        'Use safe DOM properties like textContent or standard React JSX expressions ({userContent}).',
        'If HTML rendering is strictly necessary, sanitize inputs using DOMPurify before insertion.'
      ];
      remediatedCode = `// Safe DOM assignment with DOMPurify
import DOMPurify from 'dompurify';
container.innerHTML = DOMPurify.sanitize(untrustedBioText);`;
      saferAlternativeSnippet = remediatedCode;
    } else if (title.includes('ssrf') || title.includes('forgery')) {
      problemExplanation = 'The server initiates outbound HTTP requests based on an untrusted, client-supplied URL or host.';
      securityImpact = 'Attackers can scan internal networks, reach cloud metadata services (169.254.169.254), or access private microservices.';
      stepByStepFix = [
        'Validate destination hostnames against a strict allowlist of approved domains.',
        'Block internal RFC 1918 private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and link-local addresses.',
        'Do not follow redirects to unauthorized hosts.'
      ];
      remediatedCode = `// Validate target host against domain allowlist
const ALLOWED_DOMAINS = ['api.trustedpartner.com', 'cdn.company.com'];
const parsedUrl = new URL(userProvidedUrl);
if (!ALLOWED_DOMAINS.includes(parsedUrl.hostname)) {
  throw new Error('Target domain is not in the approved allowlist');
}
const response = await axios.get(parsedUrl.toString());`;
      saferAlternativeSnippet = remediatedCode;
    } else if (title.includes('dependency') || title.includes('prototype pollution') || finding.dependencyInfo) {
      const dep = finding.dependencyInfo;
      problemExplanation = `The project depends on an outdated version of ${dep?.packageName || 'a third-party library'} with known security vulnerabilities.`;
      securityImpact = 'Known CVEs can be exploited by attackers via public exploits targeting this library version.';
      stepByStepFix = [
        `Update the dependency in package.json or requirements.txt to >= ${dep?.fixedVersion || 'the latest secure patch'}.`,
        'Run `npm audit fix` or `pip install --upgrade <package>`.',
        'Run the automated test suite to confirm backward compatibility.'
      ];
      remediatedCode = `// Updated package.json dependency
"${dep?.packageName || 'library'}": "^${dep?.fixedVersion || 'latest'}"`;
      saferAlternativeSnippet = remediatedCode;
    } else if (title.includes('md5') || title.includes('hash')) {
      problemExplanation = 'Outdated cryptographic hash function (MD5 or SHA-1) used in hashing routine.';
      securityImpact = 'Known collision and preimage attacks allow attackers to forge signatures or crack passwords with rainbow tables.';
      stepByStepFix = [
        'For integrity checks, migrate to SHA-256 or SHA-512.',
        'For password storage, never use raw hashing; use Argon2id, bcrypt, or PBKDF2 with high work factor.'
      ];
      remediatedCode = `// Secure modern password hashing using bcrypt
import bcrypt from 'bcryptjs';
const saltRounds = 12;
const passwordHash = bcrypt.hashSync(rawPassword, saltRounds);`;
      saferAlternativeSnippet = remediatedCode;
    } else {
      remediatedCode = `// Refactored implementation complying with CWE guidelines
// Ensure input validation and parameter encapsulation`;
      saferAlternativeSnippet = remediatedCode;
    }

    const diffSnippet = AIService.generateUnifiedDiff(finding.codeSnippet, remediatedCode, finding.filePath);

    return {
      problemExplanation,
      securityImpact,
      stepByStepFix,
      remediatedCode,
      saferAlternativeSnippet,
      diffSnippet,
      modelUsed: 'deterministic-rules-engine-v2 (Offline Fallback)',
      generatedAt: new Date().toISOString(),
    };
  }

  public static async askCopilot(
    finding: Finding,
    question: string,
    history: { role: string; content: string }[] = []
  ): Promise<string> {
    const ai = getGeminiClient();
    if (!ai) {
      return `[Copilot Offline Mode]: To ask live interactive questions to Gemini, provide a valid GEMINI_API_KEY. Rule reference: ${finding.cwe || finding.title}. Line ${finding.lineNumber} in ${finding.filePath} should be refactored using parameterized input or modern security APIs.`;
    }

    try {
      const historyFormatted = history
        .slice(-4)
        .map(h => `${h.role === 'user' ? 'Developer' : 'Copilot'}: ${h.content}`)
        .join('\n');

      const prompt = `You are CodeSentinel Security Copilot, an expert AppSec assistant.
Developer context:
- Finding: ${finding.title} (${finding.severity})
- File: ${finding.filePath}:${finding.lineNumber}
- Code:
\`\`\`
${finding.codeSnippet}
\`\`\`
- Recommendation: ${finding.recommendation}

${historyFormatted ? `Conversation history:\n${historyFormatted}\n` : ''}
Developer Question: "${question}"

Provide a concise, direct, helpful AppSec engineer response (1-3 paragraphs or formatted bullets).`;

      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
      });

      return response.text || 'No response generated.';
    } catch (err: any) {
      return `Copilot service error: ${err.message}`;
    }
  }
}
