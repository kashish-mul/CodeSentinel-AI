import jwt from 'jsonwebtoken';
import { User } from '../../types';

export class TokenService {
  private static getSecret(): string {
    return process.env.JWT_SECRET || 'codesentinel_static_analysis_secret_default_key';
  }

  public static generate(user: User): string {
    const payload = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    };

    return jwt.sign(payload, this.getSecret(), {
      expiresIn: '7d',
      algorithm: 'HS256',
    });
  }

  public static verify(token: string): User | null {
    try {
      const decoded = jwt.verify(token, this.getSecret(), {
        algorithms: ['HS256'],
      }) as any;

      if (!decoded || !decoded.id) return null;

      return {
        id: decoded.id,
        email: decoded.email,
        name: decoded.name,
        role: decoded.role,
      };
    } catch {
      return null;
    }
  }
}
