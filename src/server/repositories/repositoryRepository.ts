import { dbClient } from '../db/client';
import { RepositorySummary } from '../../types';

export class RepositoryRepository {
  public static async listByUser(userId?: string): Promise<RepositorySummary[]> {
    const pool = dbClient.getPool();
    if (dbClient.isPgConnected() && pool) {
      try {
        const query = userId
          ? `SELECT r.*, s.scores_json->>'overall' as overall_score, s.severity_counts_json->>'critical' as critical_issues
             FROM repositories r
             LEFT JOIN scans s ON s.repository_id = r.id
             WHERE r.user_id = $1 OR r.user_id IS NULL
             ORDER BY r.created_at DESC`
          : `SELECT r.*, s.scores_json->>'overall' as overall_score, s.severity_counts_json->>'critical' as critical_issues
             FROM repositories r
             LEFT JOIN scans s ON s.repository_id = r.id
             ORDER BY r.created_at DESC`;
        const res = await pool.query(query, userId ? [userId] : []);
        return res.rows.map(row => ({
          id: row.id,
          name: row.name,
          sourceType: row.source || 'GITHUB',
          sourceUrl: row.url,
          lastScannedAt: row.created_at,
          overallScore: parseInt(row.overall_score || '85', 10),
          criticalIssues: parseInt(row.critical_issues || '0', 10),
        }));
      } catch (err) {
        console.error('[RepositoryRepository] PG listByUser error:', err);
      }
    }

    const store = dbClient.getFallbackData();
    return store.repositories.map(r => ({
      id: r.id,
      name: r.name,
      sourceType: r.source || 'GITHUB',
      sourceUrl: r.url,
      lastScannedAt: r.created_at || new Date().toISOString(),
      overallScore: r.overallScore || 85,
      criticalIssues: r.criticalIssues || 0,
    }));
  }

  public static async save(repo: { id: string; userId?: string; name: string; source: string; url?: string }): Promise<void> {
    const pool = dbClient.getPool();
    if (dbClient.isPgConnected() && pool) {
      try {
        await pool.query(
          `INSERT INTO repositories (id, user_id, name, source, url, created_at)
           VALUES ($1, $2, $3, $4, $5, NOW())
           ON CONFLICT (id) DO UPDATE SET name = $3, url = $5`,
          [repo.id, repo.userId || null, repo.name, repo.source, repo.url || null]
        );
      } catch (err) {
        console.error('[RepositoryRepository] PG save error:', err);
      }
    }

    const store = dbClient.getFallbackData();
    const idx = store.repositories.findIndex(r => r.id === repo.id);
    if (idx >= 0) {
      store.repositories[idx] = repo;
    } else {
      store.repositories.push(repo);
    }
    dbClient.saveFallbackStore();
  }
}
