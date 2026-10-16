import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  NodeIdentity,
  ReceiptSigner,
  ReceiptVerifier,
  MockTelemetryProvider,
  NodeRegistry,
  MemoryReceiptStore,
  SqliteReceiptStore,
  createWitnessApi
} from '../src/index.js';

describe('Telemetry Witness: Enterprise Security & Replay Protection Suite', () => {
  let node: NodeIdentity;
  let registry: NodeRegistry;
  let store: SqliteReceiptStore;
  let verifier: ReceiptVerifier;
  let signer: ReceiptSigner;
  let tempDir: string | null = null;

  beforeEach(() => {
    node = new NodeIdentity('node-01');
    registry = new NodeRegistry();
    registry.registerKey(node.nodeId, 'key-v1', node.publicKey);

    store = new SqliteReceiptStore(':memory:');
    verifier = new ReceiptVerifier(registry, store);
    signer = new ReceiptSigner(node, new MockTelemetryProvider(), 'key-v1');
  });

  afterEach(() => {
    store.close();
    if (tempDir) {
      rmSync(tempDir, { recursive: true, force: true });
      tempDir = null;
    }
  });

  it('1. accepts the first valid receipt and persists it', () => {
    const receipt = signer.createReceipt({
      taskId: '1',
      workloadId: 'w1',
      workloadDescriptor: 'd1',
      inputData: 'i1',
      executionTimeMs: 100
    });
    const res = verifier.verify(receipt);
    expect(res.valid).toBe(true);
    expect(res.trustLevel).toBe('VERIFIABLE_EXECUTION');
    expect(store.exists(receipt.receiptId)).toBe(true);
    expect(store.get(receipt.receiptId)?.receiptId).toBe(receipt.receiptId);
    expect(store.getLastSequenceNumber(node.nodeId)).toBe(1);
  });

  it('2. accepts a valid next sequence number', () => {
    const r1 = signer.createReceipt({ taskId: '1', workloadId: 'w1', workloadDescriptor: 'd1', inputData: 'i1', executionTimeMs: 50 });
    const r2 = signer.createReceipt({ taskId: '2', workloadId: 'w2', workloadDescriptor: 'd2', inputData: 'i2', executionTimeMs: 60 });
    expect(verifier.verify(r1).valid).toBe(true);
    expect(verifier.verify(r2).valid).toBe(true);
    expect(store.getLastSequenceNumber(node.nodeId)).toBe(2);
  });

  it('3. rejects duplicate nonce even with a new receiptId and higher sequence number', () => {
    const r1 = signer.createReceipt({
      taskId: '1',
      workloadId: 'w1',
      workloadDescriptor: 'd1',
      inputData: 'i1',
      executionTimeMs: 50,
      nonce: 'nonce-fixed-001',
      sequenceNumber: 1
    });
    const r2 = signer.createReceipt({
      taskId: '2',
      workloadId: 'w2',
      workloadDescriptor: 'd2',
      inputData: 'i2',
      executionTimeMs: 50,
      nonce: 'nonce-fixed-001', // Duplicate nonce, validly signed with sequence 2
      sequenceNumber: 2
    });

    expect(verifier.verify(r1).valid).toBe(true);
    const dupRes = verifier.verify(r2);
    expect(dupRes.valid).toBe(false);
    expect(dupRes.reasons).toContain('REPLAY_DETECTED');
    expect(store.getLastSequenceNumber(node.nodeId)).toBe(1);
  });

  it('4. rejects duplicate sequence number even with a fresh nonce and valid signature', () => {
    const r1 = signer.createReceipt({
      taskId: '1',
      workloadId: 'w1',
      workloadDescriptor: 'd1',
      inputData: 'i1',
      executionTimeMs: 50,
      sequenceNumber: 5
    });
    const r2 = signer.createReceipt({
      taskId: '2',
      workloadId: 'w2',
      workloadDescriptor: 'd2',
      inputData: 'i2',
      executionTimeMs: 50,
      sequenceNumber: 5 // Duplicate sequence number, validly signed
    });

    expect(verifier.verify(r1).valid).toBe(true);
    const dupSeqRes = verifier.verify(r2);
    expect(dupSeqRes.valid).toBe(false);
    expect(dupSeqRes.reasons).toContain('INVALID_SEQUENCE');
  });

  it('5. rejects decreasing sequence numbers', () => {
    const r1 = signer.createReceipt({
      taskId: '1',
      workloadId: 'w1',
      workloadDescriptor: 'd1',
      inputData: 'i1',
      executionTimeMs: 50,
      sequenceNumber: 10
    });
    const r2 = signer.createReceipt({
      taskId: '2',
      workloadId: 'w2',
      workloadDescriptor: 'd2',
      inputData: 'i2',
      executionTimeMs: 50,
      sequenceNumber: 9
    });

    expect(verifier.verify(r1).valid).toBe(true);
    const res = verifier.verify(r2);
    expect(res.valid).toBe(false);
    expect(res.reasons).toContain('INVALID_SEQUENCE');
  });

  it('6. allows sequence number gaps under strictly increasing sequence policy', () => {
    const r1 = signer.createReceipt({
      taskId: '1',
      workloadId: 'w1',
      workloadDescriptor: 'd1',
      inputData: 'i1',
      executionTimeMs: 50,
      sequenceNumber: 1
    });
    const rGap = signer.createReceipt({
      taskId: '2',
      workloadId: 'w2',
      workloadDescriptor: 'd2',
      inputData: 'i2',
      executionTimeMs: 50,
      sequenceNumber: 10
    });
    const rSkipped = signer.createReceipt({
      taskId: '3',
      workloadId: 'w3',
      workloadDescriptor: 'd3',
      inputData: 'i3',
      executionTimeMs: 50,
      sequenceNumber: 5
    });

    expect(verifier.verify(r1).valid).toBe(true);
    expect(verifier.verify(rGap).valid).toBe(true);
    expect(store.getLastSequenceNumber(node.nodeId)).toBe(10);
    // Any earlier skipped sequence is rejected once 10 is accepted
    expect(verifier.verify(rSkipped).valid).toBe(false);
    expect(verifier.verify(rSkipped).reasons).toContain('INVALID_SEQUENCE');
  });

  it('7. rejects invalid cryptographic signatures and tampered fields', () => {
    const receipt = signer.createReceipt({
      taskId: '1',
      workloadId: 'w1',
      workloadDescriptor: 'd1',
      inputData: 'i1',
      executionTimeMs: 50
    });
    const tampered = { ...receipt, context: { ...receipt.context, taskId: 'tampered-task' } };
    const res = verifier.verify(tampered);
    expect(res.valid).toBe(false);
    expect(res.reasons).toContain('INVALID_SIGNATURE');
    expect(store.exists(receipt.receiptId)).toBe(false);
  });

  it('8. rejects missing or malformed receipt fields without mutating state', () => {
    expect(verifier.verify(null as any).reasons).toContain('MALFORMED_RECEIPT');
    expect(verifier.verify({} as any).reasons).toContain('MALFORMED_RECEIPT');

    const valid = signer.createReceipt({
      taskId: '1',
      workloadId: 'w1',
      workloadDescriptor: 'd1',
      inputData: 'i1',
      executionTimeMs: 50
    });
    expect(verifier.verify({ ...valid, nonce: '' }).reasons).toContain('MALFORMED_RECEIPT');
    expect(verifier.verify({ ...valid, sequenceNumber: 0 }).reasons).toContain('MALFORMED_RECEIPT');
    expect(verifier.verify({ ...valid, sequenceNumber: -3 }).reasons).toContain('MALFORMED_RECEIPT');
    expect(verifier.verify({ ...valid, completedAt: NaN }).reasons).toContain('MALFORMED_RECEIPT');
    expect(store.getLastSequenceNumber(node.nodeId)).toBe(0);
  });

  it('9. maintains independent sequence and nonce spaces across distinct nodes', () => {
    const node2 = new NodeIdentity('node-02');
    registry.registerKey(node2.nodeId, 'key-v1', node2.publicKey);
    const signer2 = new ReceiptSigner(node2, new MockTelemetryProvider(), 'key-v1');

    const r1Node1 = signer.createReceipt({
      taskId: '1',
      workloadId: 'w1',
      workloadDescriptor: 'd1',
      inputData: 'i1',
      executionTimeMs: 50,
      nonce: 'shared-nonce-string',
      sequenceNumber: 10
    });
    const r1Node2 = signer2.createReceipt({
      taskId: '1',
      workloadId: 'w1',
      workloadDescriptor: 'd1',
      inputData: 'i1',
      executionTimeMs: 50,
      nonce: 'shared-nonce-string',
      sequenceNumber: 1
    });

    expect(verifier.verify(r1Node1).valid).toBe(true);
    expect(verifier.verify(r1Node2).valid).toBe(true);
    expect(store.getLastSequenceNumber(node.nodeId)).toBe(10);
    expect(store.getLastSequenceNumber(node2.nodeId)).toBe(1);
  });

  it('10. persists accepted receipts across verifier and store restarts on disk', () => {
    tempDir = mkdtempSync(join(tmpdir(), 'witness-sqlite-'));
    const dbPath = join(tempDir, 'receipts.db');

    const persistentStore1 = new SqliteReceiptStore(dbPath);
    const verifier1 = new ReceiptVerifier(registry, persistentStore1);

    const r1 = signer.createReceipt({ taskId: '1', workloadId: 'w1', workloadDescriptor: 'd1', inputData: 'i1', executionTimeMs: 50 });
    const r2 = signer.createReceipt({ taskId: '2', workloadId: 'w2', workloadDescriptor: 'd2', inputData: 'i2', executionTimeMs: 50 });
    expect(verifier1.verify(r1).valid).toBe(true);
    expect(verifier1.verify(r2).valid).toBe(true);
    persistentStore1.close();

    // Reopen against the same SQLite file
    const persistentStore2 = new SqliteReceiptStore(dbPath);
    const verifier2 = new ReceiptVerifier(registry, persistentStore2);

    expect(persistentStore2.getLastSequenceNumber(node.nodeId)).toBe(2);
    expect(persistentStore2.get(r1.receiptId)?.receiptId).toBe(r1.receiptId);

    // Replay of r2 after restart must fail
    const replay = verifier2.verify(r2);
    expect(replay.valid).toBe(false);
    expect(replay.reasons).toContain('REPLAY_DETECTED');

    // Stale sequence 2 with new nonce after restart must fail
    const staleAfterRestart = signer.createReceipt({
      taskId: '3',
      workloadId: 'w3',
      workloadDescriptor: 'd3',
      inputData: 'i3',
      executionTimeMs: 50,
      sequenceNumber: 2
    });
    expect(verifier2.verify(staleAfterRestart).valid).toBe(false);
    expect(verifier2.verify(staleAfterRestart).reasons).toContain('INVALID_SEQUENCE');

    // Sequence 3 succeeds
    const r3 = signer.createReceipt({
      taskId: '4',
      workloadId: 'w4',
      workloadDescriptor: 'd4',
      inputData: 'i4',
      executionTimeMs: 50,
      sequenceNumber: 3
    });
    expect(verifier2.verify(r3).valid).toBe(true);
    persistentStore2.close();
  });

  it('11. rejects concurrent duplicate submissions so exactly one succeeds', async () => {
    const receipt = signer.createReceipt({
      taskId: '1',
      workloadId: 'w1',
      workloadDescriptor: 'd1',
      inputData: 'i1',
      executionTimeMs: 50
    });

    const results = await Promise.all(
      Array.from({ length: 20 }, () => Promise.resolve().then(() => verifier.verify(receipt)))
    );
    const accepted = results.filter((r) => r.valid);
    const rejected = results.filter((r) => !r.valid);

    expect(accepted.length).toBe(1);
    expect(rejected.length).toBe(19);
    for (const r of rejected) {
      expect(r.reasons).toContain('REPLAY_DETECTED');
    }
  });

  it('12. rejects concurrent conflicting sequence submissions across two connections', async () => {
    tempDir = mkdtempSync(join(tmpdir(), 'witness-concurrent-'));
    const dbPath = join(tempDir, 'receipts.db');

    const storeA = new SqliteReceiptStore(dbPath);
    const storeB = new SqliteReceiptStore(dbPath);
    const verifierA = new ReceiptVerifier(registry, storeA);
    const verifierB = new ReceiptVerifier(registry, storeB);

    const candidateA = signer.createReceipt({
      taskId: 'A',
      workloadId: 'wA',
      workloadDescriptor: 'dA',
      inputData: 'iA',
      executionTimeMs: 50,
      sequenceNumber: 1
    });
    const candidateB = signer.createReceipt({
      taskId: 'B',
      workloadId: 'wB',
      workloadDescriptor: 'dB',
      inputData: 'iB',
      executionTimeMs: 50,
      sequenceNumber: 1
    });

    const [resA, resB] = await Promise.all([
      Promise.resolve().then(() => verifierA.verify(candidateA)),
      Promise.resolve().then(() => verifierB.verify(candidateB))
    ]);

    const successes = [resA, resB].filter((r) => r.valid);
    const failures = [resA, resB].filter((r) => !r.valid);
    expect(successes.length).toBe(1);
    expect(failures.length).toBe(1);
    expect(storeA.getLastSequenceNumber(node.nodeId)).toBe(1);

    storeA.close();
    storeB.close();
  });

  it('13. handles database close and storage constraints predictably', () => {
    const localStore = new SqliteReceiptStore(':memory:');
    const r1 = signer.createReceipt({ taskId: '1', workloadId: 'w1', workloadDescriptor: 'd1', inputData: 'i1', executionTimeMs: 50 });
    localStore.store(r1);
    // Direct duplicate store throws
    expect(() => localStore.store(r1)).toThrow(/REPLAY_DETECTED/);

    localStore.close();
    // Second close is idempotent
    expect(() => localStore.close()).not.toThrow();
    // Operations on a closed store throw a clear error
    expect(() => localStore.get(r1.receiptId)).toThrow(/SqliteReceiptStore is closed/);
  });

  it('14. ensures rejected receipts never poison or consume nonces or sequence numbers', () => {
    const validReceipt = signer.createReceipt({
      taskId: '1',
      workloadId: 'w1',
      workloadDescriptor: 'd1',
      inputData: 'i1',
      executionTimeMs: 50,
      nonce: 'unpoisoned-nonce-1',
      sequenceNumber: 1
    });

    // Attempt 1: Bad signature with the same nonce & sequenceNumber = 1
    const forgedAttempt = { ...validReceipt, signature: '00'.repeat(64) };
    const forgedRes = verifier.verify(forgedAttempt);
    expect(forgedRes.valid).toBe(false);
    expect(forgedRes.reasons).toContain('INVALID_SIGNATURE');

    // Attempt 2: High sequence number (999) with bad signature must NOT advance high-water mark
    const forgedHighSeq = { ...validReceipt, sequenceNumber: 999, nonce: 'forged-999', signature: '00'.repeat(64) };
    expect(verifier.verify(forgedHighSeq).valid).toBe(false);
    expect(store.getLastSequenceNumber(node.nodeId)).toBe(0);
    expect(store.hasNonce('unpoisoned-nonce-1', node.nodeId)).toBe(false);

    // Attempt 3: Now submit the genuine validReceipt (nonce 'unpoisoned-nonce-1', sequenceNumber 1)
    const genuineRes = verifier.verify(validReceipt);
    expect(genuineRes.valid).toBe(true);
    expect(store.getLastSequenceNumber(node.nodeId)).toBe(1);
  });

  it('rejects revoked nodes and future timestamps and supports MemoryReceiptStore + Express factory', () => {
    const memStore = new MemoryReceiptStore();
    const memVerifier = new ReceiptVerifier(registry, memStore);
    const api = createWitnessApi(memVerifier);
    expect(typeof api.use).toBe('function');

    const futureReceipt = signer.createReceipt({ taskId: '1', workloadId: 'w1', workloadDescriptor: 'd1', inputData: 'i1', executionTimeMs: 50 });
    futureReceipt.completedAt = Date.now() + 500000;
    expect(memVerifier.verify(futureReceipt).reasons).toContain('INVALID_TIMESTAMP_FUTURE');

    registry.revokeKey(node.nodeId, 'key-v1');
    const revokedReceipt = signer.createReceipt({ taskId: '2', workloadId: 'w2', workloadDescriptor: 'd2', inputData: 'i2', executionTimeMs: 50 });
    expect(memVerifier.verify(revokedReceipt).reasons).toContain('REVOKED_NODE');
  });
});
