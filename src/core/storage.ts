import { DatabaseSync } from 'node:sqlite';
import { ComputeReceipt } from './receipt.js';

/**
 * Outcome of an atomic check-and-accept operation.
 * A rejected receipt never consumes its nonce or sequence number.
 */
export type ReceiptAcceptOutcome =
  | { accepted: true }
  | { accepted: false; reason: 'REPLAY_DETECTED' | 'INVALID_SEQUENCE' };

export interface ReceiptStore {
  store(receipt: ComputeReceipt): void;
  get(receiptId: string): ComputeReceipt | undefined;
  exists(receiptId: string): boolean;
  /** Returns true if `nonce` was already accepted. Scoped to `nodeId` when provided. */
  hasNonce?(nonce: string, nodeId?: string): boolean;
  /** Highest accepted sequence number for `nodeId` (0 when none). */
  getLastSequenceNumber?(nodeId: string): number;
  /**
   * Atomically verifies replay/sequence state and persists the receipt.
   * Implementations MUST perform the check and the write as one atomic unit.
   */
  tryAccept?(receipt: ComputeReceipt): ReceiptAcceptOutcome;
}

const nonceKey = (nodeId: string, nonce: string) => `${nodeId}\u0000${nonce}`;

/**
 * Ephemeral, process-local store. State is lost on restart; use
 * {@link SqliteReceiptStore} when replay protection must survive restarts.
 */
export class MemoryReceiptStore implements ReceiptStore {
  private db = new Map<string, ComputeReceipt>();
  private nonces = new Set<string>();
  private nodeSequences = new Map<string, number>();

  public store(receipt: ComputeReceipt): void {
    this.db.set(receipt.receiptId, receipt);
    if (receipt.nonce) this.nonces.add(nonceKey(receipt.nodeId, receipt.nonce));
    const prev = this.nodeSequences.get(receipt.nodeId) || 0;
    if (receipt.sequenceNumber > prev) {
      this.nodeSequences.set(receipt.nodeId, receipt.sequenceNumber);
    }
  }

  public get(receiptId: string): ComputeReceipt | undefined {
    return this.db.get(receiptId);
  }

  public exists(receiptId: string): boolean {
    return this.db.has(receiptId);
  }

  public hasNonce(nonce: string, nodeId?: string): boolean {
    if (nodeId !== undefined) return this.nonces.has(nonceKey(nodeId, nonce));
    for (const key of this.nonces) {
      if (key.endsWith(`\u0000${nonce}`)) return true;
    }
    return false;
  }

  public getLastSequenceNumber(nodeId: string): number {
    return this.nodeSequences.get(nodeId) || 0;
  }

  /** Synchronous, so it is atomic with respect to the single JS thread. */
  public tryAccept(receipt: ComputeReceipt): ReceiptAcceptOutcome {
    if (this.db.has(receipt.receiptId) || this.nonces.has(nonceKey(receipt.nodeId, receipt.nonce))) {
      return { accepted: false, reason: 'REPLAY_DETECTED' };
    }
    if (receipt.sequenceNumber <= this.getLastSequenceNumber(receipt.nodeId)) {
      return { accepted: false, reason: 'INVALID_SEQUENCE' };
    }
    this.store(receipt);
    return { accepted: true };
  }
}

export interface SqliteReceiptStoreOptions {
  /** Milliseconds to wait for a competing writer's lock before failing. Default 5000. */
  busyTimeoutMs?: number;
}

const SCHEMA_VERSION = 1;

/**
 * Durable receipt store backed by Node's built-in `node:sqlite` (Node >= 22.13).
 *
 * - File-backed databases use WAL journaling; `:memory:` databases are private to
 *   this connection and are discarded on close.
 * - Uniqueness of (nodeId, nonce), (nodeId, sequenceNumber) and receiptId is enforced
 *   by the database itself, so even a stale application-level read cannot cause a
 *   double-accept.
 * - Sequence numbers must be strictly increasing per node. Gaps are permitted.
 */
export class SqliteReceiptStore implements ReceiptStore {
  private db: DatabaseSync;
  private closed = false;
  public readonly dbPath: string;

  constructor(dbPath: string = ':memory:', options: SqliteReceiptStoreOptions = {}) {
    this.dbPath = dbPath;
    this.db = new DatabaseSync(dbPath);
    const busyTimeout = Math.max(0, Math.floor(options.busyTimeoutMs ?? 5000));
    this.db.exec(`PRAGMA busy_timeout = ${busyTimeout};`);
    if (dbPath !== ':memory:') {
      this.db.exec('PRAGMA journal_mode = WAL;');
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS receipts (
        receiptId TEXT PRIMARY KEY,
        nodeId TEXT NOT NULL,
        nonce TEXT NOT NULL,
        sequenceNumber INTEGER NOT NULL,
        data TEXT NOT NULL,
        createdAt INTEGER NOT NULL,
        UNIQUE(nodeId, nonce),
        UNIQUE(nodeId, sequenceNumber)
      );
      CREATE TABLE IF NOT EXISTS node_sequences (
        nodeId TEXT PRIMARY KEY,
        lastSequence INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('receipt_store_version', '${SCHEMA_VERSION}');
    `);
  }

  private assertOpen(): void {
    if (this.closed) throw new Error('SqliteReceiptStore is closed.');
  }

  public store(receipt: ComputeReceipt): void {
    this.assertOpen();
    const outcome = this.tryAccept(receipt);
    if (!outcome.accepted) {
      throw new Error(`Receipt rejected by store: ${outcome.reason}`);
    }
  }

  public get(receiptId: string): ComputeReceipt | undefined {
    this.assertOpen();
    const row = this.db.prepare(`SELECT data FROM receipts WHERE receiptId = ?`).get(receiptId) as
      | { data: string }
      | undefined;
    return row ? (JSON.parse(row.data) as ComputeReceipt) : undefined;
  }

  public exists(receiptId: string): boolean {
    this.assertOpen();
    return this.db.prepare(`SELECT 1 FROM receipts WHERE receiptId = ?`).get(receiptId) !== undefined;
  }

  public hasNonce(nonce: string, nodeId?: string): boolean {
    this.assertOpen();
    if (nodeId !== undefined) {
      return this.db.prepare(`SELECT 1 FROM receipts WHERE nodeId = ? AND nonce = ?`).get(nodeId, nonce) !== undefined;
    }
    return this.db.prepare(`SELECT 1 FROM receipts WHERE nonce = ?`).get(nonce) !== undefined;
  }

  public getLastSequenceNumber(nodeId: string): number {
    this.assertOpen();
    const row = this.db.prepare(`SELECT lastSequence FROM node_sequences WHERE nodeId = ?`).get(nodeId) as
      | { lastSequence: number | bigint }
      | undefined;
    return row ? Number(row.lastSequence) : 0;
  }

  public tryAccept(receipt: ComputeReceipt): ReceiptAcceptOutcome {
    this.assertOpen();
    // BEGIN IMMEDIATE takes the RESERVED write lock up-front, so two connections
    // (or processes) cannot both pass the checks below against the same state.
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const dup = this.db
        .prepare(`SELECT 1 FROM receipts WHERE receiptId = ? OR (nodeId = ? AND nonce = ?)`)
        .get(receipt.receiptId, receipt.nodeId, receipt.nonce);
      if (dup !== undefined) {
        this.db.exec('ROLLBACK');
        return { accepted: false, reason: 'REPLAY_DETECTED' };
      }

      const row = this.db.prepare(`SELECT lastSequence FROM node_sequences WHERE nodeId = ?`).get(receipt.nodeId) as
        | { lastSequence: number | bigint }
        | undefined;
      const last = row ? Number(row.lastSequence) : 0;
      if (receipt.sequenceNumber <= last) {
        this.db.exec('ROLLBACK');
        return { accepted: false, reason: 'INVALID_SEQUENCE' };
      }

      this.db
        .prepare(
          `INSERT INTO receipts (receiptId, nodeId, nonce, sequenceNumber, data, createdAt) VALUES (?, ?, ?, ?, ?, ?)`
        )
        .run(receipt.receiptId, receipt.nodeId, receipt.nonce, receipt.sequenceNumber, JSON.stringify(receipt), Date.now());
      this.db
        .prepare(
          `INSERT INTO node_sequences (nodeId, lastSequence) VALUES (?, ?)
           ON CONFLICT(nodeId) DO UPDATE SET lastSequence = excluded.lastSequence
           WHERE excluded.lastSequence > node_sequences.lastSequence`
        )
        .run(receipt.nodeId, receipt.sequenceNumber);

      this.db.exec('COMMIT');
      return { accepted: true };
    } catch (err: any) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        // Transaction may already be closed by SQLite; nothing else to undo.
      }
      if (typeof err?.message === 'string' && err.message.includes('UNIQUE constraint failed')) {
        return { accepted: false, reason: 'REPLAY_DETECTED' };
      }
      throw err;
    }
  }

  /** Idempotent. */
  public close(): void {
    if (this.closed) return;
    this.closed = true;
    this.db.close();
  }
}
