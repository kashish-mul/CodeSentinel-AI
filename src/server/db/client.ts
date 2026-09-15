import pg from 'pg';
import fs from 'fs';
import path from 'path';
import { runMigrations } from './migrations';

const { Pool } = pg;

export function isValidPostgresUrl(url: string | undefined): boolean {
  if (!url || typeof url !== 'string') return false;
  const trimmed = url.trim();
  if (!trimmed.startsWith('postgres://') && !trimmed.startsWith('postgresql://')) {
    return false;
  }
  try {
    const parsed = new URL(trimmed);
    return Boolean(parsed.hostname && parsed.hostname !== 'base' && parsed.hostname !== 'undefined');
  } catch {
    return false;
  }
}

export class DbClient {
  private static instance: DbClient;
  private pool: pg.Pool | null = null;
  private isConnected: boolean = false;
  private fallbackStorePath: string;
  private fallbackData: {
    users: any[];
    repositories: any[];
    scans: any[];
    findings: any[];
    reports: any[];
  } = { users: [], repositories: [], scans: [], findings: [], reports: [] };

  private constructor() {
    this.fallbackStorePath = path.join(process.cwd(), 'data', 'codesentinel_store.json');
    this.loadFallbackStore();
  }

  public static getInstance(): DbClient {
    if (!DbClient.instance) {
      DbClient.instance = new DbClient();
    }
    return DbClient.instance;
  }

  private loadFallbackStore() {
    try {
      const dir = path.dirname(this.fallbackStorePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      if (fs.existsSync(this.fallbackStorePath)) {
        const content = fs.readFileSync(this.fallbackStorePath, 'utf8');
        const parsed = JSON.parse(content);
        this.fallbackData = {
          users: parsed.users || [],
          repositories: parsed.repositories || [],
          scans: parsed.scans || [],
          findings: parsed.findings || [],
          reports: parsed.reports || [],
        };
      } else {
        this.saveFallbackStore();
      }
    } catch (err) {
      console.warn('[DbClient] Fallback store load error:', err);
    }
  }

  public saveFallbackStore() {
    try {
      fs.writeFileSync(this.fallbackStorePath, JSON.stringify(this.fallbackData, null, 2), 'utf8');
    } catch (err) {
      console.error('[DbClient] Failed to persist fallback store:', err);
    }
  }

  public async initialize(): Promise<boolean> {
    const connStr = process.env.DATABASE_URL?.trim();
    if (!connStr || !isValidPostgresUrl(connStr)) {
      console.log('[DbClient] Running on high-reliability persistent local JSON store (PostgreSQL connection string not configured).');
      this.isConnected = false;
      return false;
    }

    try {
      this.pool = new Pool({
        connectionString: connStr,
        connectionTimeoutMillis: 2500,
      });

      const client = await this.pool.connect();
      client.release();
      this.isConnected = true;
      console.log('[DbClient] PostgreSQL connection established successfully.');

      await runMigrations(this.pool);
      return true;
    } catch (err: any) {
      console.log(`[DbClient] PostgreSQL unreachable (${err.message}). Seamlessly activated local store fallback.`);
      if (this.pool) {
        this.pool.end().catch(() => {});
        this.pool = null;
      }
      this.isConnected = false;
      return false;
    }
  }

  public getPool(): pg.Pool | null {
    return this.pool;
  }

  public isPgConnected(): boolean {
    return this.isConnected;
  }

  public getFallbackData() {
    return this.fallbackData;
  }
}

export const dbClient = DbClient.getInstance();
