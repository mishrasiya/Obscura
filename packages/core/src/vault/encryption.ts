import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // recommended for GCM

/** Encrypted blob, serialized as a single string: `iv:authTag:ciphertext` (all base64). */
export type EncryptedPayload = string;

/**
 * Normalizes a user-supplied key into a 32-byte buffer suitable for AES-256.
 * Accepts a raw Buffer, a 64-char hex string, or a base64 string.
 */
export function normalizeKey(key: string | Buffer): Buffer {
  if (Buffer.isBuffer(key)) {
    if (key.length !== 32) throw new Error("Encryption key must be exactly 32 bytes for AES-256");
    return key;
  }
  if (/^[0-9a-fA-F]{64}$/.test(key)) return Buffer.from(key, "hex");
  const b64 = Buffer.from(key, "base64");
  if (b64.length === 32) return b64;
  throw new Error("Encryption key must be a 32-byte Buffer, 64-char hex string, or base64-encoded 32 bytes");
}

/** Generates a fresh random 32-byte key (used when no key is configured). */
export function generateKey(): Buffer {
  return randomBytes(32);
}

/** Encrypts plaintext with AES-256-GCM, returning a self-contained serialized payload. */
export function encrypt(plaintext: string, key: Buffer): EncryptedPayload {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [iv.toString("base64"), authTag.toString("base64"), ciphertext.toString("base64")].join(":");
}

/** Decrypts a payload produced by {@link encrypt}. */
export function decrypt(payload: EncryptedPayload, key: Buffer): string {
  const [ivB64, authTagB64, ciphertextB64] = payload.split(":");
  if (!ivB64 || !authTagB64 || !ciphertextB64) throw new Error("Malformed encrypted payload");
  const iv = Buffer.from(ivB64, "base64");
  const authTag = Buffer.from(authTagB64, "base64");
  const ciphertext = Buffer.from(ciphertextB64, "base64");
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
