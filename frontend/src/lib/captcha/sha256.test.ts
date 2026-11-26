// Run with: npm run test:pow   (Node 22.6+; compares the worker's SHA-256 with Node's crypto)
import { createHash, randomBytes } from 'node:crypto';
import { sha256, leadingZeroBits, solve } from './sha256.ts';

let failures = 0;
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');

for (const len of [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000]) {
  const data = randomBytes(len);
  const want = createHash('sha256').update(data).digest('hex');
  const got = hex(sha256(new Uint8Array(data)));
  if (got !== want) { failures++; console.error(`MISMATCH for length ${len}`); }
}
if (hex(sha256(new TextEncoder().encode('abc'))) !== 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') { failures++; console.error('abc vector failed'); }
if (leadingZeroBits(new Uint8Array([0, 0x1f, 0xff])) !== 11) { failures++; console.error('leadingZeroBits failed'); }

// the server (Go) checks SHA-256(payload ":" nonce) the same way: solve and verify with Node's crypto
const payload = 'v1.00112233445566778899aabbccddeeff.9999999999.14';
const t = Date.now();
const nonce = solve(payload, 14);
const check = createHash('sha256').update(`${payload}:${nonce}`).digest();
if (leadingZeroBits(new Uint8Array(check)) < 14) { failures++; console.error('solver result rejected by node crypto'); }
console.log(`solved 14 bits in ${Date.now() - t} ms (nonce ${nonce})`);

if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
console.log('sha256 / pow solver OK');
