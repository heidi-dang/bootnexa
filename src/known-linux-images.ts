// Immutable local, read-only exact-publisher-digest allowlist.
// A filename alone never grants compatibility. No device or write authority.
export const ALPINE_VIRT_3242 = {
  profile: 'alpine-virt-3.24.2-x86_64',
  sha256: '3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b',
  imageBytes: 69206016,
  firmwareEvidence: 'QEMU/OVMF boot to Linux serial login verified in CI',
} as const;

export const ALPINE_VIRT_3241 = {
  profile: 'alpine-virt-3.24.1-x86_64',
  sha256: 'e73a6241bd5f3c5c2d4d38c02cc52c378c0415a7c888bd292066bf36e0f41a39',
  imageBytes: 69206016,
  firmwareEvidence: 'QEMU/OVMF boot to Linux serial login verified in CI (PR #27)',
} as const;

export const VERIFIED_LINUX_VIRTUAL_PROFILES = [ALPINE_VIRT_3242, ALPINE_VIRT_3241] as const;

export function identifyVerifiedLinuxVirtualIso(size: number, digest: string) {
  if (!Number.isSafeInteger(size) || size <= 0 ||
      !/^[a-f0-9]{64}$/.test(digest)) return null;
  return VERIFIED_LINUX_VIRTUAL_PROFILES.find(profile =>
    profile.imageBytes === size && profile.sha256 === digest) ?? null;
}
