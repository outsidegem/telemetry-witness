import * as crypto from 'crypto';

export interface HardwareMetrics {
  cpuCycles: number;
  thermalOutputC: number;
  executionTimeMs: number;
}

export interface ComputeReceipt {
  taskId: string;
  nodeId: string;
  metrics: HardwareMetrics;
  timestamp: number;
  signature: string;
}

export class TelemetryWitness {
  private nodeSecret: string;
  public nodeId: string;

  constructor(nodeId: string, nodeSecret: string) {
    this.nodeId = nodeId;
    // In a production DePIN environment, this secret is securely stored in a hardware enclave
    this.nodeSecret = nodeSecret; 
  }

  /**
   * Generates a cryptographic "Proof of Compute" receipt verifying hardware burn.
   */
  public generateReceipt(taskId: string): ComputeReceipt {
    // Simulating hardware telemetry pulled from the edge device
    const metrics: HardwareMetrics = {
      cpuCycles: Math.floor(Math.random() * 50000) + 10000,
      thermalOutputC: parseFloat((Math.random() * 15 + 40).toFixed(1)), // 40.0 - 55.0 C
      executionTimeMs: Math.floor(Math.random() * 500) + 100
    };

    const timestamp = Date.now();
    
    // Lock the telemetry into an immutable hash
    const dataToSign = `${taskId}:${this.nodeId}:${JSON.stringify(metrics)}:${timestamp}:${this.nodeSecret}`;
    const signature = crypto.createHash('sha256').update(dataToSign).digest('hex');

    return {
      taskId,
      nodeId: this.nodeId,
      metrics,
      timestamp,
      signature
    };
  }

  /**
   * Static verifier used by the AI Agent to mathematically prove the receipt is valid
   * before issuing the x402 micro-payment.
   */
  public static verifyReceipt(receipt: ComputeReceipt, expectedNodeSecret: string): boolean {
    const dataToVerify = `${receipt.taskId}:${receipt.nodeId}:${JSON.stringify(receipt.metrics)}:${receipt.timestamp}:${expectedNodeSecret}`;
    const expectedSignature = crypto.createHash('sha256').update(dataToVerify).digest('hex');
    
    return expectedSignature === receipt.signature;
  }
}
