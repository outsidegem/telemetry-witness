import { AssuranceLevel } from './types.js';

export interface AttestationEvidence {
  providerId: string;
  signature: string;
  timestamp: number;
  claims: Record<string, unknown>;
}

export interface AttestationProvider {
  getAssuranceLevel(): AssuranceLevel;
  generateEvidence(payload: string): AttestationEvidence;
}

export class SoftwareAttestationProvider implements AttestationProvider {
  getAssuranceLevel(): AssuranceLevel {
    return AssuranceLevel.VERIFIABLE_EXECUTION;
  }
  
  generateEvidence(payload: string): AttestationEvidence {
    return {
      providerId: 'software-node-v1',
      signature: 'software-sig-only-not-hardware-backed',
      timestamp: Date.now(),
      claims: {
        warning: 'This is software attestation only. Does not prove physical hardware isolation.'
      }
    };
  }
}
// Future Implementations: TPMAttestationProvider, TEEAttestationProvider
