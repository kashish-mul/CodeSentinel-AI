import { Finding } from '../../types';
import { DependencyScanner } from './dependencyScanner';
import { FileInput } from './securityAnalyzer';

export interface DependencyAuditResult {
  totalDependencies: number;
  vulnerableCount: number;
  findings: Finding[];
}

export class DependencyAnalyzer {
  public static isManifestFile(filePath: string): boolean {
    const lower = filePath.toLowerCase();
    return lower.endsWith('package.json') || lower.endsWith('requirements.txt');
  }

  public static analyzeManifest(file: FileInput, scanId: string): Finding[] {
    return DependencyScanner.scanFile(file, scanId);
  }

  public static auditProject(files: FileInput[], scanId: string): DependencyAuditResult {
    const findings: Finding[] = [];
    let totalDependencies = 0;

    for (const file of files) {
      if (this.isManifestFile(file.path)) {
        const manifestFindings = this.analyzeManifest(file, scanId);
        findings.push(...manifestFindings);

        // Approximate total deps from manifest
        if (file.path.endsWith('package.json')) {
          try {
            const parsed = JSON.parse(file.content);
            totalDependencies += Object.keys(parsed.dependencies || {}).length + Object.keys(parsed.devDependencies || {}).length;
          } catch {
            // Ignore parse errors
          }
        } else if (file.path.endsWith('requirements.txt')) {
          const lines = file.content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
          totalDependencies += lines.length;
        }
      }
    }

    return {
      totalDependencies: Math.max(totalDependencies, findings.length),
      vulnerableCount: findings.length,
      findings,
    };
  }
}
