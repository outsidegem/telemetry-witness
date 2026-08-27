# @digital-mineral/telemetry-witness 🛡️

**A Verifiable Compute Receipt Protocol for Sovereign Edge Nodes.**

## What Telemetry Witness Does
It acts as an on-device Proof-of-Compute oracle for DePIN networks. It binds task execution telemetry (CPU, Memory, Time) to a cryptographic Ed25519 signature, ensuring remote autonomous agents can mathematically verify work was performed by an authorized node before authorizing microtransactions.

## What a Receipt Proves
- **Authenticity:** The execution was signed by a specific, registered `nodeId` and `publicKey`.
- **Workload Binding:** The input and output digests exactly match the authorized intent.
- **Temporal Integrity:** The execution occurred within a strict, non-replayable temporal window.

## What a Receipt Does NOT Prove
Unless paired with a `TPMAttestationProvider` or `TEEAttestationProvider`, a software-generated receipt **does not prove absolute physical hardware isolation**. This library provides Level 2 (Verifiable Execution) assurance. Level 3 (Hardware Attestation) requires integrating physical secure enclaves (e.g., Mac Mini Secure Enclave or Intel SGX).

## Security & Architecture
- **Zero-Dependency Storage:** Uses abstract interfaces (with an in-memory fallback) to avoid forcing heavy database dependencies on edge clients.
- **Strict Input Hardening:** Canonical serialization limits payloads to 2MB to prevent Memory Exhaustion (OOM) attacks from malicious agents.
- **Metabolic Discipline:** Designed for ARM64 and bare-metal environments to route edge-compute intents in microseconds.

## Installation
npm install @digital-mineral/telemetry-witness
