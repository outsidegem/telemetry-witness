import { randomUUID } from 'node:crypto';
import { NodeIdentity } from './identity.js';
import { ComputeReceipt, computeDataDigest } from './receipt.js';
import { TelemetryProvider } from './telemetry.js';
import { NodeRegistry } from './registry.js';
import { ReceiptStore } from './storage.js';
import { ReceiptState, AssuranceLevel, NodeStatus } from './types.js';

export class ReceiptSigner {
  private sequenceNumber = 0;
  
  constructor(
    private identity: NodeIdentity,
    private telemetryProvider: TelemetryProvider,
    private keyId: string = 'key-v1'
  ) {}

  public createReceipt(params: {
    taskId: string; workloadId: string; workloadDescriptor: unknown; inputData: unknown; executionTimeMs: number;
  }): ComputeReceipt {
    this.sequenceNumber++;
    const metrics = this.telemetryProvider.collectMetrics(params.executionTimeMs);
    const now = Date.now();

    const unsignedReceipt: Omit<ComputeReceipt, 'signature'> = {
      protocolVersion: '2.0.0',
      receiptId: randomUUID(),
      state: ReceiptState.COMPLETED,
      assuranceLevel: AssuranceLevel.VERIFIABLE_EXECUTION,
      context: {
        taskId: params.taskId,
        workloadId: params.workloadId,
        workloadDigest: computeDataDigest(params.workloadDescriptor),
        inputDigest: computeDataDigest(params.inputData),
        environmentMetadata: { runtime: 'Node', version: process.version }
      },
      nodeId: this.identity.nodeId,
      metrics,
      startedAt: now - params.executionTimeMs,
      completedAt: now,
      nonce: randomUUID(),
      sequenceNumber: this.sequenceNumber,
      keyId: this.keyId
    };

    return { ...unsignedReceipt, state: ReceiptState.SIGNED, signature: this.identity.signPayload(unsignedReceipt) };
  }
}

export interface VerificationResult {
  valid: boolean;
  nodeId?: string;
  trustLevel?: AssuranceLevel;
  reasons: string[];
}

export class ReceiptVerifier {
  constructor(
    private registry: NodeRegistry,
    private store: ReceiptStore,
    private config = { maxAgeMs: 300000, maxClockSkewMs: 10000 }
  ) {}

  public verify(receipt: ComputeReceipt): VerificationResult {
    const reasons: string[] = [];
    
    if (!receipt.signature || !receipt.keyId || !receipt.nodeId) {
      return { valid: false, reasons: ['MALFORMED_RECEIPT'] };
    }

    const keyMeta = this.registry.getKey(receipt.nodeId, receipt.keyId);
    if (!keyMeta) return { valid: false, reasons: ['UNKNOWN_NODE'] };
    if (keyMeta.status === NodeStatus.REVOKED) return { valid: false, reasons: ['REVOKED_NODE'] };

    const now = Date.now();
    if (receipt.completedAt > now + this.config.maxClockSkewMs) reasons.push('INVALID_TIMESTAMP_FUTURE');
    if (now - receipt.completedAt > this.config.maxAgeMs) reasons.push('EXPIRED_RECEIPT');
    
    if (this.store.exists(receipt.receiptId)) reasons.push('REPLAY_DETECTED');

    const { signature, state, ...unsignedReceipt } = receipt;
    const isValidSig = NodeIdentity.verifySignature(keyMeta.publicKeyHex, { ...unsignedReceipt, state: ReceiptState.COMPLETED }, signature);
    
    if (!isValidSig) reasons.push('INVALID_SIGNATURE');

    if (reasons.length > 0) {
      return { valid: false, nodeId: receipt.nodeId, reasons };
    }

    this.store.store(receipt);
    return { valid: true, nodeId: receipt.nodeId, trustLevel: receipt.assuranceLevel, reasons: [] };
  }
}
