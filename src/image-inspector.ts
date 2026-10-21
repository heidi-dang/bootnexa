// Header inspection is intentionally shallow. Recognizing a container does not
// prove that it is bootable, authentic, or suitable for a particular firmware.
export type ImageKind = 'ISO 9660' | 'GPT raw image' | 'MBR raw image' | 'FAT volume image' | 'Unsupported' | 'Unrecognized';
export type ImageInspection = {
  kind: ImageKind;
  supported: boolean;
  description: string;
  label?: string;
  caution?: string;
};
const ascii = (bytes: Uint8Array, offset: number, length: number) =>
  String.fromCharCode(...bytes.subarray(offset, offset + length));
const u16 = (view: DataView, offset: number, little = true) => view.getUint16(offset, little);
const u32 = (view: DataView, offset: number, little = true) => view.getUint32(offset, little);
const error = (kind: ImageKind, description: string): ImageInspection => ({ kind, supported: false, description });

export async function inspectImage(file: File): Promise<ImageInspection> {
  if (file.size === 0 || !Number.isSafeInteger(file.size)) return error('Unrecognized', 'Empty or unrepresentable image size.');
  const bytes = new Uint8Array(await file.slice(0, Math.min(file.size, 96 * 1024)).arrayBuffer());
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const lower = file.name.toLowerCase();
  const unsupportedExt = /\.(vhd|vhdx|ffu|gz|xz|zip)$/i.test(lower);
  const compressed = (bytes[0] === 0x1f && bytes[1] === 0x8b) ||
    (bytes[0] === 0xfd && ascii(bytes, 1, 5) === '7zXZ\0') ||
    (ascii(bytes, 0, 4) === 'PK\x03\x04');
  if (unsupportedExt || compressed || ascii(bytes, 0, 8) === 'vhdxfile') {
    return error('Unsupported', 'Compressed images and VHD/VHDX/FFU containers are not inspected in this milestone.');
  }
  if (!/\.(iso|img|ima|dd)$/i.test(lower)) {
    return error('Unsupported', 'Choose an ISO, IMG, IMA or DD file for local inspection.');
  }

  // CD001 primary descriptor can follow an initial boot/extended descriptor.
  // Bound scanning to 32 descriptors; validate duplicated endian-encoded sizes.
  let detectedIso = false;
  for (let sector = 16; sector < 32; sector++) {
    const base = sector * 2048;
    if (base + 2048 > bytes.length) break;
    if (ascii(bytes, base + 1, 5) !== 'CD001' || bytes[base + 6] !== 1) continue;
    detectedIso = true;
    if (bytes[base] !== 1) continue;
    const blocks = u32(view, base + 80);
    const blocksBig = u32(view, base + 84, false);
    const blockSize = u16(view, base + 128);
    const blockSizeBig = u16(view, base + 130, false);
    if (blocks === 0 || blocks !== blocksBig || blockSize !== 2048 ||
      blockSizeBig !== 2048 || blocks * 2048 > file.size) {
      return error('Unrecognized', 'ISO 9660 primary descriptor contains inconsistent volume dimensions.');
    }
    const label = ascii(bytes, base + 40, 32).replace(/[^\x20-\x7e]/g, '').trim();
    return { kind: 'ISO 9660', supported: true, description: 'ISO 9660 volume descriptor validated (boot support not verified).',
      label: label || undefined, caution: 'ISO detection does not verify an El Torito/UEFI boot record.' };
  }
  if (detectedIso) return error('Unrecognized', 'ISO descriptor sequence lacks a valid primary descriptor.');
  if (file.size < 512 || file.size % 512 !== 0) return error('Unrecognized', 'No supported image structure; raw images require 512-byte sector alignment.');
  const mbrSignature = bytes[510] === 0x55 && bytes[511] === 0xaa;
  const gpt = bytes.length >= 1024 && ascii(bytes, 512, 8) === 'EFI PART';
  if (gpt) {
    if (!mbrSignature || u32(view, 512 + 12) < 92 || u32(view, 512 + 12) > 512 ||
      view.getBigUint64(512 + 24, true) !== 1n || file.size < 34 * 512) {
      return error('Unrecognized', 'GPT header or protective MBR is inconsistent.');
    }
    return { kind: 'GPT raw image', supported: true, description: 'GPT header and protective boot sector detected (partition CRCs not yet verified).',
      caution: 'Container inspection does not prove partition integrity or bootability.' };
  }
  if (mbrSignature) {
    const entries = Array.from({ length: 4 }, (_, i) => 446 + i * 16);
    const partitions = entries.some(offset =>
      (bytes[offset] === 0 || bytes[offset] === 0x80) &&
      bytes[offset + 4] !== 0 && u32(view, offset + 12) !== 0);
    if (partitions) return { kind: 'MBR raw image', supported: true, description: 'MBR partition entries detected (layout not yet verified).',
      caution: 'Boot code, partition boundaries, and operating system remain unverified.' };
    if (ascii(bytes, 54, 3) === 'FAT' || ascii(bytes, 82, 3) === 'FAT') {
      return { kind: 'FAT volume image', supported: true, description: 'FAT volume boot sector detected (filesystem not verified).',
        caution: 'A volume image may not be a whole-disk bootable image.' };
    }
  }
  return error('Unrecognized', 'No ISO 9660, GPT, MBR or FAT volume signature detected.');
}
