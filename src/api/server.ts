import express, { type Express } from 'express';
import { ReceiptVerifier, ComputeReceipt } from '../index.js';

export function createWitnessApi(verifier: ReceiptVerifier): Express {
  const app = express();
  app.use(express.json());

  app.get('/health', (req, res) => res.json({ status: 'ok' }));
  
  app.post('/v1/receipts/verify', (req, res) => {
    const receipt = req.body as ComputeReceipt;
    const result = verifier.verify(receipt);
    res.status(result.valid ? 200 : 400).json(result);
  });

  return app;
}
