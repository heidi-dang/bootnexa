import { test, expect } from '@playwright/test';
import { ALPINE_VIRT_3242, identifyVerifiedLinuxVirtualIso } from '../../src/known-linux-images';

test('the read-only Alpine profile requires both an exact version-size and SHA-256', () => {
  expect(identifyVerifiedLinuxVirtualIso(ALPINE_VIRT_3242.imageBytes, ALPINE_VIRT_3242.sha256))
    .toEqual(ALPINE_VIRT_3242);
  expect(identifyVerifiedLinuxVirtualIso(ALPINE_VIRT_3242.imageBytes + 512, ALPINE_VIRT_3242.sha256))
    .toBeNull();
  expect(identifyVerifiedLinuxVirtualIso(ALPINE_VIRT_3242.imageBytes, '0'.repeat(64)))
    .toBeNull();
  expect(identifyVerifiedLinuxVirtualIso(65536, 'not-a-hash'))
    .toBeNull();
});

test('an Alpine ISO filename cannot spoof publisher SHA-256 or enable USB writing', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'ISO library' }).click();
  await page.locator('#iso-library-file').setInputFiles({
    name: 'alpine-virt-3.24.2-x86_64.iso',
    mimeType: 'application/octet-stream',
    buffer: Buffer.alloc(40960),
  });
  await expect(page.getByTestId('library-sha256')).toBeVisible();
  await expect(page.getByTestId('iso-profile')).toHaveText('Not qualified');
  await expect(page.getByText('Publisher-pinned Linux profile')).toBeVisible();
  await expect(page.getByText('Not matched')).toBeVisible();
  await expect(page.getByTestId('iso-verified-linux-profile')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /start writing|write usb/i })).toHaveCount(0);
});
