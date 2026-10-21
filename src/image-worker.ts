import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { inspectImage, type ImageInspection } from './image-inspector';

export type ImageResult = ImageInspection & {
  sha256: string;
  size: number;
  name: string;
  lastModified: number;
};
export type AnalysisRequest = { type: 'analyze'; id: number; file: File };
export type AnalysisEvent =
  | { type: 'progress'; id: number; done: number; total: number }
  | { type: 'result'; id: number; result: ImageResult }
  | { type: 'error'; id: number; message: string };

self.addEventListener('message', async (event: MessageEvent<AnalysisRequest>) => {
  const { id, file } = event.data;
  if (event.data.type !== 'analyze') return;
  try {
    const inspection = await inspectImage(file);
    const hash = sha256.create();
    const chunkSize = 4 * 1024 * 1024;
    let lastProgress = 0;
    for (let offset = 0; offset < file.size; offset += chunkSize) {
      const size = Math.min(chunkSize, file.size - offset);
      const bytes = new Uint8Array(await file.slice(offset, offset + size).arrayBuffer());
      if (bytes.byteLength !== size) throw new Error('Image changed or read failed during checksum calculation.');
      hash.update(bytes);
      const done = offset + bytes.byteLength;
      const now = Date.now();
      if (done === file.size || now - lastProgress > 90) {
        self.postMessage({ type: 'progress', id, done, total: file.size } satisfies AnalysisEvent);
        lastProgress = now;
      }
    }
    self.postMessage({ type: 'result', id, result: {
      ...inspection, name: file.name, size: file.size, lastModified: file.lastModified,
      sha256: bytesToHex(hash.digest()),
    } } satisfies AnalysisEvent);
  } catch (e) {
    self.postMessage({ type: 'error', id, message: e instanceof Error ? e.message : 'Local image inspection failed.' } satisfies AnalysisEvent);
  }
});
