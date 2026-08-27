export enum ReceiptState {
  CREATED = 'CREATED',
  COLLECTING = 'COLLECTING',
  COMPLETED = 'COMPLETED',
  SIGNED = 'SIGNED',
  VERIFIED = 'VERIFIED',
  REJECTED = 'REJECTED',
  EXPIRED = 'EXPIRED'
}

export enum NodeStatus {
  ACTIVE = 'ACTIVE',
  REVOKED = 'REVOKED',
  SUSPENDED = 'SUSPENDED'
}

export enum AssuranceLevel {
  SIGNED_TELEMETRY = 'SIGNED_TELEMETRY',
  VERIFIABLE_EXECUTION = 'VERIFIABLE_EXECUTION',
  HARDWARE_ATTESTED = 'HARDWARE_ATTESTED' // Level 3: TPM/TEE pending
}

export type MetricStatus = 'MEASURED' | 'ESTIMATED' | 'MOCK' | 'UNAVAILABLE';

export interface Metric {
  value: number;
  status: MetricStatus;
}

export interface ComputeMetrics {
  executionTimeMs: Metric;
  cpuUsagePercent: Metric;
  memoryUsedBytes: Metric;
  temperatureC: Metric;
  platform: string;
}

export interface ExecutionContext {
  taskId: string;
  workloadId: string;
  workloadDigest: string;
  inputDigest: string;
  environmentMetadata: Record<string, string>;
}
