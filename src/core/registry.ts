import { NodeStatus } from './types.js';

export interface KeyMetadata {
  keyId: string;
  publicKeyHex: string;
  status: NodeStatus;
  registeredAt: number;
  rotatedAt?: number;
}

export class NodeRegistry {
  private nodes = new Map<string, Map<string, KeyMetadata>>(); // nodeId -> keyId -> metadata

  public registerKey(nodeId: string, keyId: string, publicKeyHex: string): void {
    if (!this.nodes.has(nodeId)) {
      this.nodes.set(nodeId, new Map());
    }
    const nodeKeys = this.nodes.get(nodeId)!;
    nodeKeys.set(keyId, {
      keyId,
      publicKeyHex,
      status: NodeStatus.ACTIVE,
      registeredAt: Date.now()
    });
  }

  public revokeKey(nodeId: string, keyId: string): void {
    const keyMeta = this.nodes.get(nodeId)?.get(keyId);
    if (keyMeta) {
      keyMeta.status = NodeStatus.REVOKED;
    }
  }

  public getKey(nodeId: string, keyId: string): KeyMetadata | undefined {
    return this.nodes.get(nodeId)?.get(keyId);
  }
}
