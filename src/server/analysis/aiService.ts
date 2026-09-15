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
Analyze the following static analysis finding detected in a developer repository:

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

Provide a structured remediation in valid JSON with these exact keys:
{
  "problemExplanation": "A concise explanation of what is wrong in simple developer terms (1-2 sentences).",
  "securityImpact": "Why it matters and what an attacker or system failure could cause.",
  "stepByStepFix": ["Step 1...", "Step 2...", "Step 3..."],
  "remediatedCode": "The fixed, secure, and clean replacement code for this snippet.",
  "saferAlternativeSnippet": "A concrete snippet showing the safe idiom / library usage."
}
Return ONLY valid JSON without markdown fences.`;

        const response = await ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: prompt,
        });

        const text = response.text || '';
        const cleanedText = text.replace(/```json\s*/g, '').replace(/```\s*$/g, '').trim();

        try {
          const parsed = JSON.parse(cleanedText);
          return {
            problemExplanation: parsed.problemExplanation || finding.description,
            securityImpact: parsed.securityImpact || 'Could permit unauthorized access or system instability.',
            stepByStepFix: Array.isArray(parsed.stepByStepFix) ? parsed.stepByStepFix : [finding.recommendation],
            remediatedCode: parsed.remediatedCode || '// Secure pattern implemented',
            saferAlternativeSnippet: parsed.saferAlternativeSnippet || parsed.remediatedCode || '',
            modelUsed: 'gemini-3.8-flash',
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

    if (finding.title.includes('SQL Injection')) {
      problemExplanation = 'User-supplied parameters are directly concatenated or interpolated into an SQL query string.';
      securityImpact = 'Attackers can manipulate SQL syntax to bypass authentication, dump sensitive database tables, or execute unauthorized DDL/DML.';
      stepByStepFix = [
        'Replace string concatenation or template literals with parameterized query place-holders ($1, ?, or named parameters).',
        'Pass user input as a distinct tuple or array into the database driver.',
        'Use an ORM/query builder (e.g. Prisma, SQLAlchemy, Drizzle) where feasible.'
      ];
      remediatedCode = `// Safe Parameterized Query (e.g., PostgreSQL pg / psycopg2)
const query = 'SELECT * FROM users WHERE id = $1 AND tenant_id = $2';
const result = await db.query(query, [userId, tenantId]);`;
      saferAlternativeSnippet = remediatedCode;
    } else if (finding.title.includes('Secret') || finding.title.includes('AWS')) {
      problemExplanation = 'Private credentials or API keys are committed directly to repository source files.';
      securityImpact = 'Anyone with read access to the repo (or git history) can steal access tokens and compromise connected cloud infrastructure.';
      stepByStepFix = [
        'Immediately rotate and invalidate the exposed secret in your provider console.',
        'Move the secret to a local .env file included in .gitignore.',
        'In production, fetch credentials via Cloud Secret Manager, AWS SSM, or environment variables.'
      ];
      remediatedCode = `// Fetch secret securely from environment runtime
const apiKey = process.env.API_SECRET_KEY;
if (!apiKey) {
  throw new Error('API_SECRET_KEY environment variable is missing.');
}`;
      saferAlternativeSnippet = remediatedCode;
    } else if (finding.title.includes('eval') || finding.title.includes('Command')) {
      problemExplanation = 'Code dynamically evaluates unsanitized strings or invokes system shell interpreters with arbitrary arguments.';
      securityImpact = 'Remote code execution (RCE) allowing attackers to run arbitrary system commands under the web process user account.';
      stepByStepFix = [
        'Eliminate dynamic eval() calls. Use JSON.parse() or a secure domain expression evaluator.',
        'For process execution, use execFile() or subprocess.run() passing arguments as an array rather than shell strings.',
        'Apply strict input allowlists (e.g. regex ^[a-zA-Z0-9_-]+$).'
      ];
      remediatedCode = `// Safe subprocess execution without shell interpretation
import { execFile } from 'child_process';
execFile('ping', ['-c', '1', safeHost], (error, stdout) => {
  if (error) console.error(error);
});`;
      saferAlternativeSnippet = remediatedCode;
    } else if (finding.title.includes('MD5') || finding.title.includes('Hash')) {
      problemExplanation = 'Outdated cryptographic hash function (MD5 or SHA-1) used in hashing routine.';
      securityImpact = 'Known collision and preimage attacks allow attackers to forge valid signatures or crack passwords quickly with rainbow tables.';
      stepByStepFix = [
        'For integrity checks or digital signatures, migrate to SHA-256 or SHA-512.',
        'For password storage, never use raw hashing; use Argon2id, bcrypt, or PBKDF2 with high work factor.'
      ];
      remediatedCode = `// Secure modern password hashing using bcrypt or Argon2
import bcrypt from 'bcrypt';
const saltRounds = 12;
const passwordHash = await bcrypt.hash(rawPassword, saltRounds);`;
      saferAlternativeSnippet = remediatedCode;
    } else if (finding.title.includes('Complexity') || finding.title.includes('Length')) {
      problemExplanation = 'The function exceeds healthy cyclomatic complexity or code length limits, leading to high cognitive load.';
      securityImpact = 'Excessive branching exponentially increases edge-case bug rates and makes unit testing difficult.';
      stepByStepFix = [
        'Extract distinct subroutines into single-responsibility helper functions.',
        'Replace deeply nested if/else statements with guard clauses or table lookups.',
        'Write dedicated unit tests for each separated function.'
      ];
      remediatedCode = `// Refactored with early returns / guard clauses
function processTransaction(account, amount) {
  if (!account.isActive) return { success: false, reason: 'Inactive account' };
  if (account.balance < amount) return { success: false, reason: 'Insufficient funds' };
  
  return executeTransfer(account, amount);
}`;
      saferAlternativeSnippet = remediatedCode;
    }

    return {
      problemExplanation,
      securityImpact,
      stepByStepFix,
      remediatedCode,
      saferAlternativeSnippet,
      modelUsed: 'rules-engine-v2',
      generatedAt: new Date().toISOString(),
    };
  }
}
