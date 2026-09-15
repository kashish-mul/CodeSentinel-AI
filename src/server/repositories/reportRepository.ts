import { dbClient } from '../db/client';
import { RemediationReport } from '../../types';

export class ReportRepository {
  public static async save(report: RemediationReport): Promise<void> {
    const pool = dbClient.getPool();
    if (dbClient.isPgConnected() && pool) {
      try {
        await pool.query(
          `INSERT INTO remediation_reports (
            id, scan_id, repository_name, overall_score, executive_summary, findings_summary, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
          ON CONFLICT (id) DO UPDATE SET
            overall_score = $4,
            executive_summary = $5,
            findings_summary = $6`,
          [
            report.id,
            report.scanId,
            report.repositoryName,
            report.overallScore,
            report.executiveSummary,
            JSON.stringify({
              totalFindings: report.totalFindings,
              critical: report.criticalFindingsCount,
              scores: report.scores,
              severityCounts: report.severityCounts,
            }),
          ]
        );
      } catch (err) {
        console.error('[ReportRepository] PG save error:', err);
      }
    }

    const store = dbClient.getFallbackData();
    const idx = store.reports.findIndex(r => r.id === report.id);
    if (idx >= 0) {
      store.reports[idx] = report;
    } else {
      store.reports.push(report);
    }
    dbClient.saveFallbackStore();
  }

  public static async findByScanId(scanId: string): Promise<RemediationReport | null> {
    const pool = dbClient.getPool();
    if (dbClient.isPgConnected() && pool) {
      try {
        const res = await pool.query('SELECT * FROM remediation_reports WHERE scan_id = $1', [scanId]);
        if (res.rows.length > 0) {
          const row = res.rows[0];
          return {
            id: row.id,
            scanId: row.scan_id,
            repositoryName: row.repository_name,
            generatedAt: row.created_at,
            overallScore: row.overall_score,
            executiveSummary: row.executive_summary,
            scores: row.findings_summary?.scores || { overall: 85, security: 80, quality: 85, maintainability: 90, documentation: 80 },
            severityCounts: row.findings_summary?.severityCounts || { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            totalFindings: row.findings_summary?.totalFindings || 0,
            criticalFindingsCount: row.findings_summary?.critical || 0,
            findings: [],
          };
        }
      } catch (err) {
        console.error('[ReportRepository] PG find error:', err);
      }
    }

    const store = dbClient.getFallbackData();
    return store.reports.find(r => r.scanId === scanId) || null;
  }
}
