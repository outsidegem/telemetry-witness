import { TelemetryWitness } from './src/index.js';

console.log("=============================================");
console.log("👁️ TITAN ORACLE: TELEMETRY WITNESS ONLINE");
console.log("=============================================");

const NODE_ID = "titan-edge-node-001";
const NODE_SECRET = "super_secure_enclave_key_998"; // Known to the agent and the node

// 1. Node executes the task and generates a receipt
const witness = new TelemetryWitness(NODE_ID, NODE_SECRET);
console.log(`\n[EDGE NODE]: Executing Agent Task: 'job_batch_88'...`);

const receipt = witness.generateReceipt("job_batch_88");
console.log("✅ [PROOF OF COMPUTE RECEIPT GENERATED]:");
console.log(`   -> Hardware Burn: ${receipt.metrics.cpuCycles} cycles | ${receipt.metrics.thermalOutputC}°C`);
console.log(`   -> Signature: ${receipt.signature}`);

// 2. Agent receives the receipt and verifies it before paying
console.log("\n[AGENT]: Receiving receipt... Verifying hardware telemetry...");

const isValid = TelemetryWitness.verifyReceipt(receipt, NODE_SECRET);

if (isValid) {
  console.log("✅ [VERIFIED]: Cryptographic signature matches physical telemetry.");
  console.log("💸 [AGENT ACTION]: Releasing $0.05 x402 payment to Node.");
} else {
  console.log("❌ [FRAUD DETECTED]: Signature mismatch. Hardware execution faked. Payment Denied.");
}

console.log("=============================================");
