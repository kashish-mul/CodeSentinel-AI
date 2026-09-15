import { GoogleGenAI } from '@google/genai';
import { Finding, AIRemediation } from '../../../types';
import { PromptBuilder } from './promptBuilder';
import { ExplanationService } from './explanationService';
import { PatchService } from './patchService';

export class RemediationService {
  private static aiClient: GoogleGenAI | null = null;

  private static getClient(): GoogleGenAI | null {
    if (!this.aiClient && process.env.GEMINI_API_KEY) {
      this.aiClient = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
    }
    return this.aiClient;
  }

  public static async explainAndRemediate(finding: Finding): Promise<AIRemediation> {
    const client = this.getClient();
    if (!client) {
      return ExplanationService.generateFallback(finding);
    }

    try {
      const prompt = PromptBuilder.buildRemediationPrompt(finding);
      const response = await client.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
        config: {
          temperature: 0.1,
          responseMimeType: 'application/json',
        }
      });

      const text = response.text || '';
      const parsed = JSON.parse(text);

      let diffSnippet = parsed.diffSnippet;
      if (!diffSnippet && parsed.remediatedCode) {
        diffSnippet = PatchService.generateUnifiedDiff(
          finding.filePath,
          finding.lineNumber,
          finding.codeSnippet,
          parsed.remediatedCode
        );
      }

      return {
        problemExplanation: parsed.problemExplanation || 'Identified security risk.',
        securityImpact: parsed.securityImpact || 'Exploitation may compromise application integrity.',
        stepByStepFix: Array.isArray(parsed.stepByStepFix) ? parsed.stepByStepFix : ['Review vulnerable code and apply patch.'],
        remediatedCode: parsed.remediatedCode || finding.codeSnippet,
        saferAlternativeSnippet: parsed.saferAlternativeSnippet || parsed.remediatedCode || finding.codeSnippet,
        diffSnippet,
        modelUsed: 'gemini-2.5-flash',
        generatedAt: new Date().toISOString(),
      };
    } catch (err) {
      console.warn('[RemediationService] Gemini generation failed, using deterministic AST fallback:', err);
      return ExplanationService.generateFallback(finding);
    }
  }

  public static async askCopilot(
    finding: Finding,
    question: string,
    chatHistory: { role: string; content: string }[] = []
  ): Promise<string> {
    const client = this.getClient();
    if (!client) {
      return `[Offline Security Copilot]: Based on rule ${finding.cwe || finding.title}, this code at ${finding.filePath}:${finding.lineNumber} requires parameterization or input sanitization. In production, connect Gemini API key to enable live interactive Q&A.`;
    }

    try {
      const prompt = PromptBuilder.buildCopilotQuestionPrompt(finding, question, chatHistory);
      const response = await client.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
        config: {
          temperature: 0.2,
        }
      });

      return response.text || 'No response from Copilot.';
    } catch (err: any) {
      console.warn('[RemediationService] Copilot Q&A failed:', err);
      return `Copilot service temporarily unavailable: ${err.message || 'Error communicating with AI model'}.`;
    }
  }
}
