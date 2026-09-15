import { dbClient } from '../db/client';
import { User } from '../../types';

export interface DBUser extends User {
  password_hash?: string;
  created_at?: string;
}

export class UserRepository {
  public static async findByEmail(email: string): Promise<DBUser | null> {
    const pool = dbClient.getPool();
    if (dbClient.isPgConnected() && pool) {
      try {
        const res = await pool.query('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [email]);
        if (res.rows.length > 0) {
          const row = res.rows[0];
          return {
            id: row.id,
            email: row.email,
            name: row.name,
            role: row.role,
            password_hash: row.password_hash,
            created_at: row.created_at,
          };
        }
      } catch (err) {
        console.error('[UserRepository] PG findByEmail error:', err);
      }
    }

    const fallback = dbClient.getFallbackData().users.find(
      u => u.email.toLowerCase() === email.toLowerCase()
    );
    return fallback || null;
  }

  public static async findById(id: string): Promise<DBUser | null> {
    const pool = dbClient.getPool();
    if (dbClient.isPgConnected() && pool) {
      try {
        const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        if (res.rows.length > 0) {
          const row = res.rows[0];
          return {
            id: row.id,
            email: row.email,
            name: row.name,
            role: row.role,
            password_hash: row.password_hash,
            created_at: row.created_at,
          };
        }
      } catch (err) {
        console.error('[UserRepository] PG findById error:', err);
      }
    }

    const fallback = dbClient.getFallbackData().users.find(u => u.id === id);
    return fallback || null;
  }

  public static async create(user: DBUser): Promise<DBUser> {
    const pool = dbClient.getPool();
    if (dbClient.isPgConnected() && pool) {
      try {
        await pool.query(
          `INSERT INTO users (id, email, name, role, password_hash, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
           ON CONFLICT (id) DO UPDATE SET name = $3, role = $4, updated_at = NOW()`,
          [user.id, user.email, user.name, user.role || 'Security Engineer', user.password_hash]
        );
      } catch (err) {
        console.error('[UserRepository] PG create error:', err);
      }
    }

    // Always mirror in fallback store
    const store = dbClient.getFallbackData();
    const idx = store.users.findIndex(u => u.id === user.id || u.email.toLowerCase() === user.email.toLowerCase());
    if (idx >= 0) {
      store.users[idx] = user;
    } else {
      store.users.push(user);
    }
    dbClient.saveFallbackStore();

    return user;
  }
}
