import { ComputeReceipt } from './receipt.js';

export interface ReceiptStore {
  store(receipt: ComputeReceipt): void;
  get(receiptId: string): ComputeReceipt | undefined;
  exists(receiptId: string): boolean;
}

export class MemoryReceiptStore implements ReceiptStore {
  private db = new Map<string, ComputeReceipt>();

  public store(receipt: ComputeReceipt): void {
    this.db.set(receipt.receiptId, receipt);
  }

  public get(receiptId: string): ComputeReceipt | undefined {
    return this.db.get(receiptId);
  }

  public exists(receiptId: string): boolean {
    return this.db.has(receiptId);
  }
}
