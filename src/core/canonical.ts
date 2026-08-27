import { Buffer } from 'node:buffer';

const MAX_PAYLOAD_SIZE = 2 * 1024 * 1024; // 2MB Hard Limit to prevent OOM attacks

export function getCanonicalBytes(payload: unknown): Buffer {
  const jsonStr = stringifyDeterministic(payload);
  if (Buffer.byteLength(jsonStr, 'utf8') > MAX_PAYLOAD_SIZE) {
    throw new Error('Payload exceeds maximum allowed size of 2MB.');
  }
  return Buffer.from(jsonStr, 'utf8');
}

function stringifyDeterministic(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj) || 'null';
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => stringifyDeterministic(item)).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const keyVals = keys.map(k => `${JSON.stringify(k)}:${stringifyDeterministic((obj as Record<string, unknown>)[k])}`);
  return '{' + keyVals.join(',') + '}';
}
