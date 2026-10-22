// Immutable local, read-only exact-version digest allowlist.
// A filename alone never grants compatibility. No device or write authority.
export const ALPINE_VIRT_3242 = {
  profile: 'alpine-virt-3.24.2-x86_64',
  sha256: '3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b',
  imageBytes: 69206016,
  firmwareEvidence: 'QEMU/OVMF boot to Linux serial login verified in CI',
} as const;

export function identifyVerifiedLinuxVirtualIso(size: number, digest: string) {
  if (!Number.isSafeInteger(size) || size !== ALPINE_VIRT_3242.imageBytes ||
      !/^[a-f0-9]{64}$/.test(digest)) return null;
  return digest === ALPINE_VIRT_3242.sha256 ? ALPINE_VIRT_3242 : null;
}
