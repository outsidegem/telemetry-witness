import { AssuranceLevel } from './types.js';

export interface AuditRecord {
  auditId: string;
  receiptId: string;
  nodeId: string;
  workloadId: string;
  valid: boolean;
  reasons: string[];
  trustLevel: AssuranceLevel;
  timestamp: number;
  verifierVersion: string;
}
