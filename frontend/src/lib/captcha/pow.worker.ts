import { solve } from './sha256';

// Runs off the main thread so the page stays responsive while the proof of work is computed.
self.onmessage = (e: MessageEvent<{ payload: string; difficulty: number }>) => {
  const { payload, difficulty } = e.data;
  const nonce = solve(payload, difficulty, (attempts) => (self as unknown as Worker).postMessage({ progress: attempts }));
  (self as unknown as Worker).postMessage({ nonce });
};
