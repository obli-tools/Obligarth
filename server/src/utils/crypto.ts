import bcrypt from 'bcryptjs';
import crypto from 'crypto';

const SALT_ROUNDS = 12;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function generateToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

// No look-alike characters (0/O, 1/l/I): the password is read from a log.
const PASSWORD_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';

/** Random password, uniform over 57 symbols (24 characters ≈ 140 bits). */
export function generatePassword(length: number = 24): string {
  let password = '';
  for (let i = 0; i < length; i++) password += PASSWORD_ALPHABET[crypto.randomInt(PASSWORD_ALPHABET.length)];
  return password;
}
