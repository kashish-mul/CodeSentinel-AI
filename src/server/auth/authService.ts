import { UserRepository, DBUser } from '../repositories/userRepository';
import { PasswordService } from './passwordService';
import { TokenService } from './tokenService';
import { User } from '../../types';

export class AuthService {
  public static async register(name: string, email: string, password: string): Promise<{ user: User; token: string }> {
    const existing = await UserRepository.findByEmail(email);
    if (existing) {
      throw new Error('A user with this email address already exists.');
    }

    const password_hash = PasswordService.hash(password);
    const id = `usr_${Date.now().toString(36)}_${Math.random().toString(36).substr(2, 4)}`;

    const newUser: DBUser = {
      id,
      name,
      email,
      role: 'Security Engineer',
      password_hash,
    };

    await UserRepository.create(newUser);

    const userPayload: User = {
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
    };

    const token = TokenService.generate(userPayload);
    return { user: userPayload, token };
  }

  public static async login(email: string, password: string): Promise<{ user: User; token: string }> {
    const user = await UserRepository.findByEmail(email);
    if (!user) {
      throw new Error('Invalid email or password.');
    }

    if (user.password_hash) {
      const isValid = PasswordService.verify(password, user.password_hash);
      if (!isValid) {
        throw new Error('Invalid email or password.');
      }
    }

    const userPayload: User = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    const token = TokenService.generate(userPayload);
    return { user: userPayload, token };
  }

  public static async seedDefaultUser(): Promise<void> {
    const defaultEmail = 'developer@codesentinel.io';
    const existing = await UserRepository.findByEmail(defaultEmail);
    if (!existing) {
      console.log('[Auth] Seeding primary security architect account...');
      await UserRepository.create({
        id: 'usr_sec_lead_01',
        name: 'Lead AppSec Engineer',
        email: defaultEmail,
        role: 'Principal Security Architect',
        password_hash: PasswordService.hash('SentinelAdmin2026!'),
      });
    }
  }
}
