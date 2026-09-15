import { Finding } from '../../../types';

export class PromptBuilder {
  public static buildRemediationPrompt(finding: Finding): string {
    return `You are CodeSentinel AI, an expert Principal Application Security Architect.
Analyze the following security finding discovered during static analysis (AST / SCA) and generate an actionable, production-grade remediation plan with a complete code fix and unified git diff.

FINDING DETAILS:
- Title: ${finding.title}
- File Path: ${finding.filePath}
- Line Number: ${finding.lineNumber}
- Category: ${finding.category}
- Severity: ${finding.severity}
- CWE: ${finding.cwe || 'N/A'}
- OWASP Category: ${finding.owaspCategory || 'N/A'}
- AST Node Type: ${finding.astNodeType || 'Syntax Node'}
- Analysis Method: ${finding.analysisMethod || 'AST Analysis'}
${finding.dependencyInfo ? `- Dependency: ${finding.dependencyInfo.packageName} (Installed: ${finding.dependencyInfo.installedVersion}, Fixed: ${finding.dependencyInfo.fixedVersion})` : ''}

OFFENDING CODE SNIPPET:
\`\`\`
${finding.codeSnippet}
\`\`\`

REQUIREMENTS:
1. Explain the underlying root cause clearly.
2. Detail the exact threat scenario (how an adversary could exploit this).
3. Provide step-by-step remediation instructions.
4. Provide the EXACT corrected, hardened code snippet.
5. Provide a realistic unified diff format snippet (--- a/file +++ b/file @@ ... @@ -old +new).

Respond ONLY with valid JSON matching this exact structure:
{
  "problemExplanation": "string explaining technical root cause",
  "securityImpact": "string detailing exploitation and business threat",
  "stepByStepFix": ["step 1", "step 2", "step 3"],
  "remediatedCode": "exact remediated code",
  "saferAlternativeSnippet": "complete hardened code block or pattern",
  "diffSnippet": "--- a/file\\n+++ b/file\\n@@ -1,1 +1,1 @@\\n-vulnerable code\\n+hardened code"
}`;
  }

  public static buildCopilotQuestionPrompt(
    finding: Finding,
    userQuestion: string,
    chatHistory: { role: string; content: string }[] = []
  ): string {
    const historyText = chatHistory
      .slice(-4)
      .map(m => `${m.role === 'user' ? 'Developer' : 'Copilot'}: ${m.content}`)
      .join('\n');

    return `You are CodeSentinel Security Copilot, an AI assistant built specifically for software developers and AppSec engineers.
You are helping a developer inspect and fix a specific code vulnerability.

CONTEXT:
- Finding: ${finding.title}
- File: ${finding.filePath}:${finding.lineNumber}
- Severity: ${finding.severity}
- CWE: ${finding.cwe || 'N/A'}
- OWASP: ${finding.owaspCategory || 'N/A'}
- AST Node: ${finding.astNodeType || 'Syntax Node'}
- Code Snippet:
\`\`\`
${finding.codeSnippet}
\`\`\`

${historyText ? `RECENT CONVERSATION:\n${historyText}\n` : ''}
DEVELOPER QUESTION:
"${userQuestion}"

Provide a concise, direct, technically accurate answer (2-4 paragraphs or formatted bullet points/code snippet). Directly answer their question regarding threat, false positives, patch verification, or alternatives.`;
  }
}
