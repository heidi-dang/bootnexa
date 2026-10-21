import type { Device } from './agent';
import type { ImageResult } from './image-worker';

export type PreflightCheck = { label: string; ok: boolean; detail: string };
export type Preflight = { complete: boolean; checks: PreflightCheck[]; headline: string };
export function evaluatePreflight(
  file: File | null,
  image: ImageResult | null,
  device: Device | undefined,
  expectedHash: string,
): Preflight {
  const value = expectedHash.trim().toLowerCase().replace(/^sha256:/, '').trim();
  const expectedPresent = value.length > 0;
  const hashValid = /^[a-f0-9]{64}$/.test(value);
  const hashMatch = Boolean(image && hashValid && image.sha256 === value);
  const checks: PreflightCheck[] = [
    { label: 'Image signature', ok: Boolean(image?.supported), detail: !file ? 'Select a local image.' :
      !image ? 'Waiting for the image to be inspected and hashed.' : image.description },
    { label: 'SHA-256 checksum', ok: Boolean(image && (!expectedPresent || hashMatch)),
      detail: !image ? 'Local checksum pending.' : !expectedPresent ? 'Computed locally; no expected checksum supplied.' :
      !hashValid ? 'Expected SHA-256 must be exactly 64 hexadecimal characters.' :
      hashMatch ? 'Matches the supplied SHA-256.' : 'Checksum mismatch. Do not use this image.' },
    { label: 'Target USB', ok: Boolean(device && !device.readOnly),
      detail: !device ? 'Select a currently connected, eligible USB drive.' :
        device.readOnly ? 'Drive reports write protection. Preflight blocked.' :
        'Current inventory choice recorded for comparison only.' },
    { label: 'Image fits on target', ok: Boolean(image && device && image.size > 0 &&
      Number.isSafeInteger(device.capacityBytes) && image.size <= device.capacityBytes),
      detail: !image || !device ? 'Image and drive required for a capacity comparison.' :
        image.size > device.capacityBytes ? 'Image is larger than the target device.' :
          'Image fits by byte count; layout and bootability are not verified.' },
  ];
  const complete = checks.every(check => check.ok) && Boolean(image && file &&
    image.name === file.name && image.size === file.size && image.lastModified === file.lastModified);
  return { complete, checks, headline: complete
    ? 'Read-only preliminary checks complete — writing unavailable'
    : 'Preflight incomplete — physical writing unavailable' };
}
