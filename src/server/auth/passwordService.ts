import bcrypt from 'bcryptjs';

export class PasswordService {
  private static readonly SALT_ROUNDS = 10;

  public static hash(password: string): string {
    const salt = bcrypt.genSaltSync(this.SALT_ROUNDS);
    return bcrypt.hashSync(password, salt);
  }

  public static verify(password: string, hash: string): boolean {
    if (!password || !hash) return false;
    try {
      return bcrypt.compareSync(password, hash);
    } catch {
      return false;
    }
  }
}
