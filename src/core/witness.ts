import { randomUUID } from 'node:crypto';
import { NodeIdentity } from './identity.js';
import { ComputeReceipt, computeDataDigest } from './receipt.js';
import { TelemetryProvider } from './telemetry.js';
import { NodeRegistry } from './registry.js';
import { ReceiptStore } from './storage.js';
import { ReceiptState, AssuranceLevel, NodeStatus } from './types.js';

export class ReceiptSigner {
  private sequenceNumber: number;

  constructor(
    private identity: NodeIdentity,
    private telemetryProvider: TelemetryProvider,
    private keyId: string = 'key-v1',
    initialSequenceNumber: number = 0
  ) {
    this.sequenceNumber = initialSequenceNumber;
  }

  public setSequenceNumber(sequenceNumber: number): void {
    if (!Number.isInteger(sequenceNumber) || sequenceNumber < 0) {
      throw new Error('Sequence number must be a non-negative integer.');
    }
    this.sequenceNumber = sequenceNumber;
  }

  public getSequenceNumber(): number {
    return this.sequenceNumber;
  }

  public createReceipt(params: {
    taskId: string;
    workloadId: string;
    workloadDescriptor: unknown;
    inputData: unknown;
    executionTimeMs: number;
    nonce?: string;
    sequenceNumber?: number;
  }): ComputeReceipt {
    if (params.sequenceNumber !== undefined) {
      this.sequenceNumber = params.sequenceNumber;
    } else {
      this.sequenceNumber++;
    }
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
      nonce: params.nonce ?? randomUUID(),
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

    if (
      !receipt ||
      typeof receipt !== 'object' ||
      typeof receipt.receiptId !== 'string' ||
      receipt.receiptId.trim() === '' ||
      typeof receipt.signature !== 'string' ||
      receipt.signature.trim() === '' ||
      typeof receipt.keyId !== 'string' ||
      receipt.keyId.trim() === '' ||
      typeof receipt.nodeId !== 'string' ||
      receipt.nodeId.trim() === '' ||
      typeof receipt.nonce !== 'string' ||
      receipt.nonce.trim() === '' ||
      typeof receipt.sequenceNumber !== 'number' ||
      !Number.isInteger(receipt.sequenceNumber) ||
      receipt.sequenceNumber <= 0 ||
      typeof receipt.completedAt !== 'number' ||
      !Number.isFinite(receipt.completedAt) ||
      typeof receipt.startedAt !== 'number' ||
      !Number.isFinite(receipt.startedAt) ||
      !receipt.context ||
      typeof receipt.context !== 'object'
    ) {
      return { valid: false, reasons: ['MALFORMED_RECEIPT'] };
    }

    const keyMeta = this.registry.getKey(receipt.nodeId, receipt.keyId);
    if (!keyMeta) return { valid: false, reasons: ['UNKNOWN_NODE'] };
    if (keyMeta.status === NodeStatus.REVOKED) return { valid: false, reasons: ['REVOKED_NODE'] };

    const now = Date.now();
    if (receipt.completedAt > now + this.config.maxClockSkewMs) reasons.push('INVALID_TIMESTAMP_FUTURE');
    if (now - receipt.completedAt > this.config.maxAgeMs) reasons.push('EXPIRED_RECEIPT');

    if (this.store.exists(receipt.receiptId) || (this.store.hasNonce && this.store.hasNonce(receipt.nonce, receipt.nodeId))) {
      reasons.push('REPLAY_DETECTED');
    }

    if (this.store.getLastSequenceNumber) {
      const lastSeq = this.store.getLastSequenceNumber(receipt.nodeId);
      if (receipt.sequenceNumber <= lastSeq) {
        reasons.push('INVALID_SEQUENCE');
      }
    }

    const { signature, state, ...unsignedReceipt } = receipt;
    const isValidSig = NodeIdentity.verifySignature(
      keyMeta.publicKeyHex,
      { ...unsignedReceipt, state: ReceiptState.COMPLETED },
      signature
    );

    if (!isValidSig) reasons.push('INVALID_SIGNATURE');

    // Never mutate persistent state if any validation check (including signature) failed.
    if (reasons.length > 0) {
      return { valid: false, nodeId: receipt.nodeId, reasons };
    }

    // Commit atomically via tryAccept when supported by the store.
    if (this.store.tryAccept) {
      const outcome = this.store.tryAccept(receipt);
      if (!outcome.accepted) {
        return { valid: false, nodeId: receipt.nodeId, reasons: [outcome.reason] };
      }
    } else {
      this.store.store(receipt);
    }

    return { valid: true, nodeId: receipt.nodeId, trustLevel: receipt.assuranceLevel, reasons: [] };
  }
}
