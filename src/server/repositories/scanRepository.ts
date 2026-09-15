import { dbClient } from '../db/client';
import { Scan } from '../../types';

export class ScanRepository {
  public static async create(scan: Scan): Promise<void> {
    const pool = dbClient.getPool();
    if (dbClient.isPgConnected() && pool) {
      try {
        await pool.query(
          `INSERT INTO scans (
            id, user_id, repository_name, source_type, source_url, status,
            scores_json, severity_counts_json, total_files, total_lines,
            started_at, completed_at, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
          ON CONFLICT (id) DO UPDATE SET
            status = $6,
            scores_json = $7,
            severity_counts_json = $8,
            completed_at = $12`,
          [
            scan.id,
            scan.userId || null,
            scan.repositoryName,
            scan.sourceType,
            scan.sourceUrl || null,
            scan.status,
            JSON.stringify(scan.scores),
            JSON.stringify(scan.severityCounts),
            scan.totalFilesAnalyzed,
            scan.totalLinesOfCode,
            scan.startedAt,
            scan.completedAt || null,
          ]
        );

        // Also persist findings to findings table
        if (scan.findings && scan.findings.length > 0) {
          for (const f of scan.findings) {
            await pool.query(
              `INSERT INTO findings (
                id, scan_id, title, severity, category, cwe, owasp_category,
                file_path, line_number, code_snippet, recommendation,
                ast_node_type, analysis_method, dependency_info, ai_explanation, created_at
              ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
              ON CONFLICT (id) DO NOTHING`,
              [
                f.id,
                scan.id,
                f.title,
                f.severity,
                f.category,
                f.cwe || null,
                f.owaspCategory || null,
                f.filePath,
                f.lineNumber,
                f.codeSnippet,
                f.recommendation,
                f.astNodeType || null,
                f.analysisMethod || null,
                f.dependencyInfo ? JSON.stringify(f.dependencyInfo) : null,
                f.aiExplanation ? JSON.stringify(f.aiExplanation) : null,
              ]
            );
          }
        }
      } catch (err) {
        console.error('[ScanRepository] PG create error:', err);
      }
    }

    // Always mirror in fallback local store
    const store = dbClient.getFallbackData();
    const idx = store.scans.findIndex(s => s.id === scan.id);
    if (idx >= 0) {
      store.scans[idx] = scan;
    } else {
      store.scans.unshift(scan);
    }
    dbClient.saveFallbackStore();
  }

  public static async findById(id: string, userId?: string): Promise<Scan | null> {
    const pool = dbClient.getPool();
    if (dbClient.isPgConnected() && pool) {
      try {
        const query = userId
          ? `SELECT * FROM scans WHERE id = $1 AND (user_id = $2 OR user_id IS NULL)`
          : `SELECT * FROM scans WHERE id = $1`;
        const res = await pool.query(query, userId ? [id, userId] : [id]);
        if (res.rows.length > 0) {
          const row = res.rows[0];
          // Fetch associated findings
          const findingsRes = await pool.query('SELECT * FROM findings WHERE scan_id = $1 ORDER BY line_number ASC', [id]);
          const findings = findingsRes.rows.map(f => ({
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

          return {
            id: row.id,
            userId: row.user_id,
            repositoryName: row.repository_name,
            sourceType: row.source_type,
            sourceUrl: row.source_url,
            status: row.status,
            scores: row.scores_json,
            severityCounts: row.severity_counts_json,
            totalFilesAnalyzed: row.total_files,
            totalLinesOfCode: row.total_lines,
            startedAt: row.started_at,
            completedAt: row.completed_at,
            findings,
          };
        }
      } catch (err) {
        console.error('[ScanRepository] PG findById error:', err);
      }
    }

    const store = dbClient.getFallbackData();
    const found = store.scans.find(s => {
      if (s.id !== id) return false;
      if (!userId) return true;
      return !s.userId || s.userId === userId;
    });
    return found || null;
  }

  public static async findAll(userId?: string): Promise<Scan[]> {
    const pool = dbClient.getPool();
    if (dbClient.isPgConnected() && pool) {
      try {
        const query = userId
          ? `SELECT * FROM scans WHERE user_id = $1 OR user_id IS NULL ORDER BY created_at DESC LIMIT 50`
          : `SELECT * FROM scans ORDER BY created_at DESC LIMIT 50`;
        const res = await pool.query(query, userId ? [userId] : []);
        return res.rows.map(row => ({
          id: row.id,
          userId: row.user_id,
          repositoryName: row.repository_name,
          sourceType: row.source_type,
          sourceUrl: row.source_url,
          status: row.status,
          scores: row.scores_json,
          severityCounts: row.severity_counts_json,
          totalFilesAnalyzed: row.total_files,
          totalLinesOfCode: row.total_lines,
          startedAt: row.started_at,
          completedAt: row.completed_at,
          findings: [],
        }));
      } catch (err) {
        console.error('[ScanRepository] PG findAll error:', err);
      }
    }

    const store = dbClient.getFallbackData();
    return store.scans.filter(s => {
      if (!userId) return true;
      return !s.userId || s.userId === userId;
    });
  }
}
