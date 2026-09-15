import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { Request, Response, NextFunction } from 'express';
import { db, DBUser } from './db';
import { User } from '../types';

const JWT_SECRET = process.env.JWT_SECRET || 'codesentinel-enterprise-jwt-signing-secret-2026';
const JWT_EXPIRES_IN = '24h';

export interface AuthRequest extends Request {
  user?: User;
}

export class AuthService {
  public static async seedDefaultUser(): Promise<void> {
    const existing = await db.getUserByEmail('developer@codesentinel.io');
    if (!existing) {
      const salt = bcrypt.genSaltSync(10);
      const password_hash = bcrypt.hashSync('SentinelPass123!', salt);
      await db.createUser({
        id: 'usr_sec_lead_01',
        email: 'developer@codesentinel.io',
        name: 'Lead AppSec Engineer',
        role: 'Principal Security Architect',
        password_hash,
      });
      console.log('[Auth] Default security engineer account seeded: developer@codesentinel.io');
    }
  }

  public static hashPassword(password: string): string {
    const salt = bcrypt.genSaltSync(10);
    return bcrypt.hashSync(password, salt);
  }

  public static verifyPassword(password: string, hash: string): boolean {
    return bcrypt.compareSync(password, hash);
  }

  public static generateToken(user: User): string {
    return jwt.sign(
      {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
  }

  public static verifyToken(token: string): User | null {
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as User;
      return {
        id: decoded.id,
        email: decoded.email,
        name: decoded.name,
        role: decoded.role,
      };
    } catch (err) {
      return null;
    }
  }

  public static middleware(req: AuthRequest, res: Response, next: NextFunction) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      // Allow demo access but mark unauthenticated
      return next();
    }

    const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : authHeader;
    const user = AuthService.verifyToken(token);
    if (!user) {
      return res.status(401).json({ error: 'Invalid or expired JWT token' });
    }

    req.user = user;
    next();
  }

  public static requireAuth(req: AuthRequest, res: Response, next: NextFunction) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      return res.status(401).json({ error: 'Authorization header with Bearer token is required' });
    }

    const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : authHeader;
    const user = AuthService.verifyToken(token);
    if (!user) {
      return res.status(401).json({ error: 'Invalid or expired JWT token' });
    }

    req.user = user;
    next();
  }
}
