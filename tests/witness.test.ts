import { describe, it, expect, beforeEach } from 'vitest';
import { NodeIdentity, ReceiptSigner, ReceiptVerifier, MockTelemetryProvider, NodeRegistry, MemoryReceiptStore, NodeStatus } from '../src/index.js';

describe('Telemetry Witness: Enterprise Security Suite', () => {
  let node: NodeIdentity;
  let registry: NodeRegistry;
  let store: MemoryReceiptStore;
  let verifier: ReceiptVerifier;
  let signer: ReceiptSigner;

  beforeEach(() => {
    node = new NodeIdentity('node-01');
    registry = new NodeRegistry();
    registry.registerKey(node.nodeId, 'key-v1', node.publicKey);
    
    store = new MemoryReceiptStore();
    verifier = new ReceiptVerifier(registry, store);
    signer = new ReceiptSigner(node, new MockTelemetryProvider(), 'key-v1');
  });

  it('verifies valid execution receipts', () => {
    const receipt = signer.createReceipt({ taskId: '1', workloadId: 'w1', workloadDescriptor: 'd1', inputData: 'i1', executionTimeMs: 100 });
    const res = verifier.verify(receipt);
    expect(res.valid).toBe(true);
    expect(res.trustLevel).toBe('VERIFIABLE_EXECUTION');
  });

  it('rejects revoked nodes', () => {
    registry.revokeKey(node.nodeId, 'key-v1');
    const receipt = signer.createReceipt({ taskId: '1', workloadId: 'w1', workloadDescriptor: 'd1', inputData: 'i1', executionTimeMs: 100 });
    const res = verifier.verify(receipt);
    expect(res.valid).toBe(false);
    expect(res.reasons).toContain('REVOKED_NODE');
  });

  it('blocks receipt replay attacks via abstract storage', () => {
    const receipt = signer.createReceipt({ taskId: '1', workloadId: 'w1', workloadDescriptor: 'd1', inputData: 'i1', executionTimeMs: 100 });
    verifier.verify(receipt); // First pass
    const replayRes = verifier.verify(receipt); // Replay
    expect(replayRes.valid).toBe(false);
    expect(replayRes.reasons).toContain('REPLAY_DETECTED');
  });

  it('detects future timestamp manipulation', () => {
    const receipt = signer.createReceipt({ taskId: '1', workloadId: 'w1', workloadDescriptor: 'd1', inputData: 'i1', executionTimeMs: 100 });
    receipt.completedAt = Date.now() + 500000; 
    const res = verifier.verify(receipt);
    expect(res.valid).toBe(false);
    expect(res.reasons).toContain('INVALID_TIMESTAMP_FUTURE');
  });
});
