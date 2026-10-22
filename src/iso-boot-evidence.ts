// Independent read-only local ISO/El Torito evidence. This code never
// extracts paths, infers Windows/Linux compatibility, or starts disk writing.
export type IsoBootEvidence = {
  iso9660: boolean;
  udfSignature: boolean;
  elTorito: boolean;
  biosCatalogEntry: boolean;
  uefiCatalogEntry: boolean;
  hybridMbrCandidate: boolean;
  catalogVerified: boolean;
  warning: string;
};
const sectorSize = 2048;
const maxDescriptors = 64;
const decode = (bytes: Uint8Array, start: number, len: number) =>
  String.fromCharCode(...bytes.subarray(start, start + len));
const defaultEvidence = (): IsoBootEvidence => ({
  iso9660: false, udfSignature: false, elTorito: false,
  biosCatalogEntry: false, uefiCatalogEntry: false,
  hybridMbrCandidate: false, catalogVerified: false,
  warning: 'Boot media compatibility has not been verified.',
});
function readU32(bytes: Uint8Array, pos: number) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(pos, true);
}
async function getSector(file: File, lba: number) {
  const offset = lba * sectorSize;
  if (!Number.isSafeInteger(offset) || offset + sectorSize > file.size) throw new Error('ISO metadata points outside this file.');
  const bytes = new Uint8Array(await file.slice(offset, offset + sectorSize).arrayBuffer());
  if (bytes.length !== sectorSize) throw new Error('ISO descriptor could not be read completely.');
  return bytes;
}
function verifyCatalog(bytes: Uint8Array) {
  if (bytes[0] !== 1 || bytes[30] !== 0x55 || bytes[31] !== 0xaa) throw new Error('Invalid El Torito boot validation entry.');
  let sum = 0;
  for (let i = 0; i < 32; i += 2) sum = (sum + bytes[i] + bytes[i + 1] * 256) & 0xffff;
  if (sum !== 0) throw new Error('El Torito validation checksum failed.');
  let bios = false;
  let uefi = false;
  if (bytes[32] === 0x88) {
    if (bytes[1] === 0xef) uefi = true;
    else if (bytes[1] === 0) bios = true;
    else throw new Error('Unsupported El Torito boot architecture.');
  } else if (bytes[32] !== 0) throw new Error('Unsupported El Torito default boot entry.');
  let index = 64;
  for (let section = 0; section < 16 && index + 64 <= sectorSize; section++) {
    const kind = bytes[index];
    if (kind === 0) break;
    if (kind !== 0x90 && kind !== 0x91) throw new Error('Malformed El Torito section header.');
    const count = bytes[index + 2] + bytes[index + 3] * 256;
    if (count < 1 || count > 32 || index + 32 + 32 * count > sectorSize) throw new Error('Invalid El Torito boot section length.');
    for (let item = 0; item < count; item++) {
      const entry = index + 32 + item * 32;
      if (bytes[entry] === 0x88) {
        if (bytes[index + 1] === 0xef) uefi = true;
        else if (bytes[index + 1] === 0) bios = true;
        else throw new Error('Unsupported El Torito section architecture.');
      } else if (bytes[entry] !== 0) throw new Error('Unexpected El Torito entry.');
    }
    index += 32 + count * 32;
    if (kind === 0x91) break;
  }
  return { bios, uefi };
}
export async function inspectIsoBoot(file: File): Promise<IsoBootEvidence> {
  const evidence = defaultEvidence();
  if (file.size < 17 * sectorSize) throw new Error('ISO file is too small for a volume descriptor.');
  const first = new Uint8Array(await file.slice(0, 512).arrayBuffer());
  evidence.hybridMbrCandidate = first[510] === 0x55 && first[511] === 0xaa &&
    [0, 1, 2, 3].some(index => first[446 + index * 16 + 4] !== 0 &&
      first.slice(446 + index * 16 + 12, 446 + index * 16 + 16).some(value => value !== 0));
  let catalogLba: number | null = null;
  let terminated = false;
  for (let index = 0; index < maxDescriptors && (16 + index + 1) * sectorSize <= file.size; index++) {
    const bytes = await getSector(file, 16 + index);
    const signature = decode(bytes, 1, 5);
    if (signature === 'NSR02' || signature === 'NSR03') {
      evidence.udfSignature = true;
      continue;
    }
    if (signature === 'BEA01' || signature === 'TEA01') continue;
    if (signature !== 'CD001' || bytes[6] !== 1) throw new Error('Invalid or unsupported ISO volume descriptor.');
    if (bytes[0] === 1) evidence.iso9660 = true;
    if (bytes[0] === 0 && decode(bytes, 7, 23) === 'EL TORITO SPECIFICATION') {
      if (catalogLba !== null) throw new Error('Duplicate boot catalog descriptor.');
      catalogLba = readU32(bytes, 71);
      if (!catalogLba || (catalogLba + 1) * sectorSize > file.size) throw new Error('El Torito catalog is outside this ISO.');
    }
    if (bytes[0] === 255) { terminated = true; break; }
  }
  if (!evidence.iso9660 && !evidence.udfSignature) throw new Error('No supported ISO9660/UDF recognition structure found.');
  if (evidence.iso9660 && !evidence.udfSignature && !terminated) throw new Error('ISO descriptor terminator missing.');
  if (catalogLba !== null) {
    evidence.elTorito = true;
    const result = verifyCatalog(await getSector(file, catalogLba));
    evidence.catalogVerified = true;
    evidence.biosCatalogEntry = result.bios;
    evidence.uefiCatalogEntry = result.uefi;
  }
  evidence.warning = evidence.elTorito
    ? 'El Torito entries are structurally verified. Firmware boot, operating system and hybrid raw-write safety are NOT verified.'
    : 'No validated El Torito boot catalog; bootability and installer compatibility are NOT verified.';
  return evidence;
}
