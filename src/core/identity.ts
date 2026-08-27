import { generateKeyPairSync, sign, verify, randomBytes } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { getCanonicalBytes } from './canonical.js';

export class NodeIdentity {
  public readonly nodeId: string;
  public readonly publicKey: string;
  private readonly privateKey: Buffer; // Strictly encapsulated. Never serialized.

  constructor(nodeId?: string, keyPair?: { publicKey: Buffer; privateKey: Buffer }) {
    // Red Team Fix: Replaced Math.random() with cryptographically secure randomBytes
    this.nodeId = nodeId || `node-${randomBytes(8).toString('hex')}`;
    const kp = keyPair || generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    this.privateKey = kp.privateKey;
    this.publicKey = kp.publicKey.toString('hex');
  }

  public signPayload(payload: unknown): string {
    const bytes = getCanonicalBytes(payload);
    return sign(null, bytes, { key: this.privateKey, format: 'der', type: 'pkcs8' }).toString('hex');
  }

  public static verifySignature(publicKeyHex: string, payload: unknown, signatureHex: string): boolean {
    try {
      const bytes = getCanonicalBytes(payload);
      const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');
      const signatureBuffer = Buffer.from(signatureHex, 'hex');
      return verify(null, bytes, { key: publicKeyBuffer, format: 'der', type: 'spki' }, signatureBuffer);
    } catch {
      return false;
    }
  }
}
