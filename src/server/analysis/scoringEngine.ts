import { Finding, ScanScores, SeverityCounts } from '../../types';

export class ScoringEngine {
  public static calculateScores(findings: Finding[], totalFiles: number, totalLines: number): {
    scores: ScanScores;
    counts: SeverityCounts;
  } {
    const counts: SeverityCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    let securityPenalties = 0;
    let qualityPenalties = 0;
    let maintainabilityPenalties = 0;
    let documentationPenalties = 0;

    for (const f of findings) {
      // Count severities
      switch (f.severity) {
        case 'CRITICAL':
          counts.critical++;
          break;
        case 'HIGH':
          counts.high++;
          break;
        case 'MEDIUM':
          counts.medium++;
          break;
        case 'LOW':
          counts.low++;
          break;
        case 'INFO':
          counts.info++;
          break;
      }

      // Penalty weight based on severity
      const weight = f.severity === 'CRITICAL' ? 22 : f.severity === 'HIGH' ? 12 : f.severity === 'MEDIUM' ? 6 : 2;

      switch (f.category) {
        case 'SECURITY':
          securityPenalties += weight;
          break;
        case 'CODE_QUALITY':
          qualityPenalties += weight;
          break;
        case 'MAINTAINABILITY':
          maintainabilityPenalties += weight;
          break;
        case 'DOCUMENTATION':
          documentationPenalties += weight;
          break;
      }
    }

    const securityScore = Math.max(10, Math.min(100, Math.round(100 - securityPenalties)));
    const qualityScore = Math.max(15, Math.min(100, Math.round(100 - qualityPenalties)));
    const maintainabilityScore = Math.max(20, Math.min(100, Math.round(100 - maintainabilityPenalties)));
    const documentationScore = Math.max(20, Math.min(100, Math.round(100 - documentationPenalties)));

    // Overall Score: 40% Security, 30% Quality, 20% Maintainability, 10% Documentation
    const overallScore = Math.round(
      securityScore * 0.4 +
      qualityScore * 0.3 +
      maintainabilityScore * 0.2 +
      documentationScore * 0.1
    );

    return {
      scores: {
        overall: Math.max(10, Math.min(100, overallScore)),
        security: securityScore,
        quality: qualityScore,
        maintainability: maintainabilityScore,
        documentation: documentationScore,
      },
      counts,
    };
  }
}
