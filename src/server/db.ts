import pg from 'pg';
import fs from 'fs';
import path from 'path';
import { Scan, User, Finding } from '../types';
import { isValidPostgresUrl } from './db/client';

const { Pool } = pg;

export interface DBUser extends User {
  password_hash?: string;
}

class DatabaseManager {
  private pool: pg.Pool | null = null;
  private isPostgresAvailable: boolean = false;
  private fallbackStorePath: string;
  private localStore: {
    users: DBUser[];
    scans: Scan[];
  } = { users: [], scans: [] };

  constructor() {
    this.fallbackStorePath = path.join(process.cwd(), 'data', 'codesentinel_store.json');
    this.ensureFallbackStore();
  }

  private ensureFallbackStore() {
    try {
      const dir = path.dirname(this.fallbackStorePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      if (fs.existsSync(this.fallbackStorePath)) {
        const raw = fs.readFileSync(this.fallbackStorePath, 'utf8');
        this.localStore = JSON.parse(raw);
      } else {
        this.saveLocalStore();
      }
    } catch (err) {
      console.warn('[DB] Fallback local store init warning:', err);
    }
  }

  private saveLocalStore() {
    try {
      fs.writeFileSync(this.fallbackStorePath, JSON.stringify(this.localStore, null, 2), 'utf8');
    } catch (err) {
      console.error('[DB] Failed to persist local store:', err);
    }
  }

  public async initialize(): Promise<boolean> {
    const connectionString = process.env.DATABASE_URL?.trim();
    if (!connectionString || !isValidPostgresUrl(connectionString)) {
      console.log(`[DB] Running on local persistent disk storage (${this.fallbackStorePath}).`);
      this.isPostgresAvailable = false;
      return false;
    }
    
    try {
      this.pool = new Pool({
        connectionString,
        connectionTimeoutMillis: 2000,
      });

      // Quick ping test
      const client = await this.pool.connect();
      
      // Run DDL for schema
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id VARCHAR(128) PRIMARY KEY,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          name VARCHAR(255) NOT NULL,
          role VARCHAR(100) NOT NULL,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS scans (
          id VARCHAR(128) PRIMARY KEY,
          repository_name VARCHAR(255) NOT NULL,
          source_type VARCHAR(64) NOT NULL,
          source_url TEXT,
          status VARCHAR(64) NOT NULL,
          scores JSONB NOT NULL,
          severity_counts JSONB NOT NULL,
          total_files_analyzed INT NOT NULL,
          total_lines_of_code INT NOT NULL,
          started_at TIMESTAMPTZ NOT NULL,
          completed_at TIMESTAMPTZ,
          findings JSONB NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repository_name);
        CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
      `);

      client.release();
      this.isPostgresAvailable = true;
      console.log('[DB] PostgreSQL connected successfully. Schema validated.');
      return true;
    } catch (err: any) {
      console.log(`[DB] PostgreSQL not reachable (${err.message}). Using local persistent disk storage (${this.fallbackStorePath}).`);
      if (this.pool) {
        this.pool.end().catch(() => {});
        this.pool = null;
      }
      this.isPostgresAvailable = false;
      return false;
    }
  }

  public isPostgresConnected(): boolean {
    return this.isPostgresAvailable;
  }

  // --- Users ---
  public async getUserByEmail(email: string): Promise<DBUser | null> {
    if (this.isPostgresAvailable && this.pool) {
      try {
        const res = await this.pool.query('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [email]);
        if (res.rows.length > 0) {
          const r = res.rows[0];
          return {
            id: r.id,
            email: r.email,
            name: r.name,
            role: r.role,
            password_hash: r.password_hash,
          };
        }
        return null;
      } catch (err) {
        console.error('[DB] PostgreSQL getUserByEmail error, falling back:', err);
      }
    }

    const found = this.localStore.users.find(u => u.email.toLowerCase() === email.toLowerCase());
    return found || null;
  }

  public async createUser(user: DBUser): Promise<DBUser> {
    if (this.isPostgresAvailable && this.pool) {
      try {
        await this.pool.query(
          'INSERT INTO users (id, email, password_hash, name, role) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (email) DO UPDATE SET name = $4, role = $5',
          [user.id, user.email, user.password_hash || '', user.name, user.role]
        );
      } catch (err) {
        console.error('[DB] PostgreSQL createUser error:', err);
      }
    }

    const idx = this.localStore.users.findIndex(u => u.email.toLowerCase() === user.email.toLowerCase());
    if (idx >= 0) {
      this.localStore.users[idx] = user;
    } else {
      this.localStore.users.push(user);
    }
    this.saveLocalStore();
    return user;
  }

  // --- Scans ---
  public async saveScan(scan: Scan): Promise<void> {
    if (this.isPostgresAvailable && this.pool) {
      try {
        await this.pool.query(
          `INSERT INTO scans (
            id, repository_name, source_type, source_url, status,
            scores, severity_counts, total_files_analyzed, total_lines_of_code,
            started_at, completed_at, findings
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
          ON CONFLICT (id) DO UPDATE SET
            status = $5, scores = $6, severity_counts = $7,
            completed_at = $11, findings = $12`,
          [
            scan.id,
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
            JSON.stringify(scan.findings),
          ]
        );
      } catch (err) {
        console.error('[DB] PostgreSQL saveScan error:', err);
      }
    }

    const existingIdx = this.localStore.scans.findIndex(s => s.id === scan.id);
    if (existingIdx >= 0) {
      this.localStore.scans[existingIdx] = scan;
    } else {
      this.localStore.scans.unshift(scan);
    }
    this.saveLocalStore();
  }

  public async getScans(): Promise<Scan[]> {
    if (this.isPostgresAvailable && this.pool) {
      try {
        const res = await this.pool.query('SELECT * FROM scans ORDER BY started_at DESC');
        return res.rows.map(r => ({
          id: r.id,
          repositoryName: r.repository_name,
          sourceType: r.source_type,
          sourceUrl: r.source_url || undefined,
          status: r.status,
          scores: r.scores,
          severityCounts: r.severity_counts,
          totalFilesAnalyzed: r.total_files_analyzed,
          totalLinesOfCode: r.total_lines_of_code,
          startedAt: r.started_at,
          completedAt: r.completed_at || undefined,
          findings: r.findings || [],
        }));
      } catch (err) {
        console.error('[DB] PostgreSQL getScans error, falling back:', err);
      }
    }

    return this.localStore.scans;
  }

  public async getScanById(id: string): Promise<Scan | null> {
    if (this.isPostgresAvailable && this.pool) {
      try {
        const res = await this.pool.query('SELECT * FROM scans WHERE id = $1', [id]);
        if (res.rows.length > 0) {
          const r = res.rows[0];
          return {
            id: r.id,
            repositoryName: r.repository_name,
            sourceType: r.source_type,
            sourceUrl: r.source_url || undefined,
            status: r.status,
            scores: r.scores,
            severityCounts: r.severity_counts,
            totalFilesAnalyzed: r.total_files_analyzed,
            totalLinesOfCode: r.total_lines_of_code,
            startedAt: r.started_at,
            completedAt: r.completed_at || undefined,
            findings: r.findings || [],
          };
        }
      } catch (err) {
        console.error('[DB] PostgreSQL getScanById error:', err);
      }
    }

    return this.localStore.scans.find(s => s.id === id) || null;
  }

  public async getRepositories(): Promise<{ name: string; count: number; lastScore: number }[]> {
    const allScans = await this.getScans();
    const repoMap = new Map<string, { name: string; count: number; lastScore: number }>();
    for (const s of allScans) {
      repoMap.set(s.repositoryName, {
        name: s.repositoryName,
        count: (repoMap.get(s.repositoryName)?.count || 0) + 1,
        lastScore: s.scores.overall,
      });
    }
    return Array.from(repoMap.values());
  }
}

export const db = new DatabaseManager();
