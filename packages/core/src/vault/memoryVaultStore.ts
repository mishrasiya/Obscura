import { VaultRecord, VaultStore } from "../types.js";
import { decrypt, encrypt, generateKey, normalizeKey } from "./encryption.js";

interface StoredRecord {
  token: string;
  encryptedValue: string;
  type: string;
  requestId: string;
  createdAt: number;
  expiresAt: number;
}

/**
 * Default in-memory {@link VaultStore} implementation.
 *
 * Original sensitive values are encrypted at rest with AES-256-GCM. Records
 * expire after `ttlMs` and are purged lazily (on access) and periodically
 * via a background sweep. For multi-instance/enterprise deployments, supply
 * a custom {@link VaultStore} (e.g. backed by Redis) via `SanitizerConfig.vaultStore`.
 */
export class MemoryVaultStore implements VaultStore {
  private records = new Map<string, StoredRecord>();
  private readonly key: Buffer;
  private readonly ttlMs: number;
  private sweepTimer?: NodeJS.Timeout;

  constructor(options: { encryptionKey?: string | Buffer; ttlMs?: number } = {}) {
    this.key = options.encryptionKey ? normalizeKey(options.encryptionKey) : generateKey();
    this.ttlMs = options.ttlMs ?? 60 * 60 * 1000; // 1 hour default

    // Periodic sweep to bound memory growth from abandoned requests.
    this.sweepTimer = setInterval(() => this.sweep(), Math.min(this.ttlMs, 5 * 60 * 1000));
    // Don't keep the process alive solely for cleanup.
    this.sweepTimer.unref?.();
  }

  async set(record: VaultRecord): Promise<void> {
    this.records.set(record.token, {
      token: record.token,
      encryptedValue: encrypt(record.value, this.key),
      type: String(record.type),
      requestId: record.requestId,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
    });
  }

  async get(token: string): Promise<VaultRecord | undefined> {
    const stored = this.records.get(token);
    if (!stored) return undefined;
    if (Date.now() > stored.expiresAt) {
      this.records.delete(token);
      return undefined;
    }
    return {
      token: stored.token,
      value: decrypt(stored.encryptedValue, this.key),
      type: stored.type,
      requestId: stored.requestId,
      createdAt: stored.createdAt,
      expiresAt: stored.expiresAt,
    };
  }

  async getAll(requestId: string): Promise<VaultRecord[]> {
    const now = Date.now();
    const result: VaultRecord[] = [];
    for (const stored of this.records.values()) {
      if (stored.requestId !== requestId) continue;
      if (now > stored.expiresAt) continue;
      result.push({
        token: stored.token,
        value: decrypt(stored.encryptedValue, this.key),
        type: stored.type,
        requestId: stored.requestId,
        createdAt: stored.createdAt,
        expiresAt: stored.expiresAt,
      });
    }
    return result;
  }

  async deleteAll(requestId: string): Promise<void> {
    for (const [token, stored] of this.records) {
      if (stored.requestId === requestId) this.records.delete(token);
    }
  }

  /** Removes all expired records. Called periodically; safe to call manually. */
  private sweep(): void {
    const now = Date.now();
    for (const [token, stored] of this.records) {
      if (now > stored.expiresAt) this.records.delete(token);
    }
  }

  /** Stops the background sweep timer (useful for clean shutdown in tests). */
  dispose(): void {
    if (this.sweepTimer) clearInterval(this.sweepTimer);
  }
}
