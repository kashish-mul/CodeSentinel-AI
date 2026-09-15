import { FileInput } from './analysis/securityAnalyzer';

export interface SampleRepo {
  id: string;
  name: string;
  description: string;
  files: FileInput[];
}

export const SAMPLE_REPOSITORIES: SampleRepo[] = [
  {
    id: 'ecommerce-api-vulnerable',
    name: 'ecommerce-backend-api',
    description: 'Typical web API with raw SQL queries, hardcoded dev credentials, and shell command execution.',
    files: [
      {
        path: 'src/config.py',
        content: `# Backend Configuration
DATABASE_URL = "postgresql://postgres:root@localhost:5432/ecommerce"
AWS_ACCESS_KEY_ID = "AKIA9876543210SAMPLE"
JWT_SECRET_KEY = "mysecret123"
API_KEY = "sk_live_998877665544332211"
DEBUG = True
`
      },
      {
        path: 'src/routes/users.py',
        content: `from fastapi import APIRouter, Request
import sqlite3
import hashlib

router = APIRouter()

@router.get("/users/search")
def search_user(query_term: str):
    conn = sqlite3.connect("ecommerce.db")
    cursor = conn.cursor()
    # Direct dynamic SQL string interpolation
    query = "SELECT id, username, email FROM users WHERE username LIKE '%" + query_term + "%'"
    cursor.execute(query)
    return cursor.fetchall()

@router.post("/users/register")
def register_user(username: str, password_raw: str):
    # Weak cryptographic hash algorithm
    pwd_hash = hashlib.md5(password_raw.encode()).hexdigest()
    conn = sqlite3.connect("ecommerce.db")
    conn.execute("INSERT INTO users (username, password) VALUES ('" + username + "', '" + pwd_hash + "')")
    conn.commit()
    return {"status": "created"}
`
      },
      {
        path: 'src/utils/backup.py',
        content: `import os

def trigger_system_backup(bucket_destination: str):
    # Dangerous system command execution with shell concatenation
    os.system("tar -czf /tmp/backup.tar.gz /var/data && aws s3 cp /tmp/backup.tar.gz " + bucket_destination)
    print("DEBUG: Backup process finished")
`
      },
      {
        path: 'src/services/order_processor.py',
        content: `def calculate_discount_and_tax(order):
    try:
        total = order['price'] * order['quantity']
        if order['customer_tier'] == 'VIP':
            if total > 500:
                total *= 0.8
            elif total > 200:
                total *= 0.85
            else:
                total *= 0.9
        elif order['customer_tier'] == 'MEMBER':
            if total > 300:
                total *= 0.9
            else:
                total *= 0.95
        if order['state'] == 'CA':
            total *= 1.09
        elif order['state'] == 'NY':
            total *= 1.085
        elif order['state'] == 'TX':
            total *= 1.08
        return total
    except:
        pass
`
      }
    ]
  },
  {
    id: 'secure-microservice',
    name: 'secure-auth-service',
    description: 'Hardened cloud microservice following OWASP best practices, parameterized queries, and environment secrets.',
    files: [
      {
        path: 'src/config.ts',
        content: `/**
 * Application Configuration Module
 * Loads validated configuration from process environment.
 */
export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  jwtSecret: process.env.JWT_SECRET || (() => { throw new Error('JWT_SECRET missing'); })(),
  databaseUrl: process.env.DATABASE_URL || (() => { throw new Error('DATABASE_URL missing'); })(),
};
`
      },
      {
        path: 'src/controllers/auth.controller.ts',
        content: `import { Request, Response } from 'express';
import { Pool } from 'pg';
import argon2 from 'argon2';

const pool = new Pool();

export async function loginHandler(req: Request, res: Response) {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Missing required credentials' });
    }

    // Secure parameterized query preventing SQL injection
    const query = 'SELECT id, password_hash FROM users WHERE email = $1';
    const { rows } = await pool.query(query, [email]);
    
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValid = await argon2.verify(rows[0].password_hash, password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    return res.json({ status: 'authenticated' });
  } catch (err) {
    return res.status(500).json({ error: 'Internal authentication failure' });
  }
}
`
      },
      {
        path: 'README.md',
        content: `# Secure Auth Service

A production-grade authentication microservice implementing OWASP Top 10 defenses.

## Features
- Parameterized SQL statements with pg Pool
- Argon2id password hashing
- Strict environment secret validation
- Zero eval() or shell invocations
`
      }
    ]
  }
];
