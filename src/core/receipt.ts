import { createHash } from 'node:crypto';
import { ComputeMetrics, ExecutionContext, ReceiptState, AssuranceLevel } from './types.js';

export interface ComputeReceipt {
  protocolVersion: string;
  receiptId: string;
  state: ReceiptState;
  assuranceLevel: AssuranceLevel;
  context: ExecutionContext;
  nodeId: string;
  metrics: ComputeMetrics;
  startedAt: number;
  completedAt: number;
  nonce: string;
  sequenceNumber: number;
  keyId: string;
  signature: string;
}

export function computeDataDigest(data: unknown): string {
  const content = typeof data === 'string' ? data : JSON.stringify(data);
  return createHash('sha256').update(content).digest('hex');
}
