import pg from 'pg';
import { SCHEMA_SQL } from './schema';

export async function runMigrations(pool: pg.Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query(SCHEMA_SQL);
    console.log('[DB Migrations] PostgreSQL tables verified and updated.');
  } catch (err) {
    console.error('[DB Migrations] Migration failed:', err);
    throw err;
  } finally {
    client.release();
  }
}
