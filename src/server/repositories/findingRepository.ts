import { dbClient } from '../db/client';
import { Finding } from '../../types';

export class FindingRepository {
  public static async findByScanId(scanId: string): Promise<Finding[]> {
    const pool = dbClient.getPool();
    if (dbClient.isPgConnected() && pool) {
      try {
        const res = await pool.query('SELECT * FROM findings WHERE scan_id = $1 ORDER BY line_number ASC', [scanId]);
        return res.rows.map(f => ({
          id: f.id,
          scanId: f.scan_id,
          category: f.category,
          severity: f.severity,
          title: f.title,
          description: f.description || f.title,
          filePath: f.file_path,
          lineNumber: f.line_number,
          codeSnippet: f.code_snippet,
          recommendation: f.recommendation,
          cwe: f.cwe,
          owaspCategory: f.owasp_category,
          astNodeType: f.ast_node_type,
          analysisMethod: f.analysis_method,
          dependencyInfo: f.dependency_info,
          aiExplanation: f.ai_explanation,
        }));
      } catch (err) {
        console.error('[FindingRepository] PG findByScanId error:', err);
      }
    }

    const store = dbClient.getFallbackData();
    const scan = store.scans.find(s => s.id === scanId);
    return scan ? scan.findings : [];
  }

  public static async updateFindingRemediation(findingId: string, aiExplanation: any): Promise<void> {
    const pool = dbClient.getPool();
    if (dbClient.isPgConnected() && pool) {
      try {
        await pool.query('UPDATE findings SET ai_explanation = $1 WHERE id = $2', [JSON.stringify(aiExplanation), findingId]);
      } catch (err) {
        console.error('[FindingRepository] PG update error:', err);
      }
    }

    const store = dbClient.getFallbackData();
    for (const scan of store.scans) {
      const f = scan.findings.find(item => item.id === findingId);
      if (f) {
        f.aiExplanation = aiExplanation;
        break;
      }
    }
    dbClient.saveFallbackStore();
  }
}
