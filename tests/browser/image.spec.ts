import { test, expect, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';

const agentBase = 'http://127.0.0.1:43627/v1/';
const grant = 'b'.repeat(64);
function isoFixture(blocks = 36) {
  const data = Buffer.alloc(blocks * 2048);
  const base = 16 * 2048;
  data[base] = 1; data.write('CD001', base + 1); data[base + 6] = 1;
  data.write('BOOTNEXA QA', base + 40);
  data.writeUInt32LE(blocks, base + 80); data.writeUInt32BE(blocks, base + 84);
  data.writeUInt16LE(2048, base + 128); data.writeUInt16BE(2048, base + 130);
  data[17 * 2048] = 255; data.write('CD001', 17 * 2048 + 1);
  return data;
}
function mbrFixture(size = 4096) {
  const bytes = Buffer.alloc(size);
  bytes[510] = 0x55; bytes[511] = 0xaa;
  bytes[446 + 4] = 0x0c; bytes.writeUInt32LE(1, 446 + 8); bytes.writeUInt32LE(2, 446 + 12);
  return bytes;
}
function file(name: string, buffer: Buffer) {
  return { name, mimeType: 'application/octet-stream', buffer };
}
async function connectedAgent(page: Page, capacity: number, readOnly = false) {
  await page.route(agentBase + '**', async route => {
    const path = route.request().url().slice(agentBase.length);
    const value = path === 'health' ? { platform: 'windows', protocolVersion: '0.2' }
      : path === 'access/request' ? { token: grant, scope: 'devices:read' }
      : path === 'devices' ? { devices: [{ id: 'usb-opaque-qa', model: 'USB QA Target', capacityBytes: capacity,
          busType: 'USB', partitionStyle: 'GPT', readOnly }] } : {};
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(value),
      headers: { 'access-control-allow-origin': 'http://127.0.0.1:5173',
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'authorization,content-type' } });
  });
}
async function selectFile(page: Page, name: string, data: Buffer) {
  // A negative assertion can succeed before the React client mounts. Wait for
  // the agent connection effect to complete so upload handlers are active.
  await expect(page.locator('.agent-status strong')).toHaveText(/^(Agent connected|Agent not connected|Access not authorised|Unsupported platform)$/);
  await page.locator('input[type=file]').setInputFiles(file(name, data));
  await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
  await expect(page.getByTestId('image-sha256')).toHaveText(createHash('sha256').update(data).digest('hex'), { timeout: 20_000 });
}

test('ISO signature, local streamed SHA-256 and capacity preflight', async ({ page }) => {
  await connectedAgent(page, 128 * 1024 * 1024);
  await page.goto('/');
  const sample = isoFixture();
  await selectFile(page, 'installer.iso', sample);
  await expect(page.getByText('ISO 9660: recognized')).toBeVisible();
  await expect(page.getByText('BOOTNEXA QA', { exact: false })).toHaveCount(0); // label isn't OS detection
  await page.getByRole('radio', { name: 'Compare image with USB QA Target' }).check();
  await expect(page.getByText('Read-only preliminary checks complete — writing unavailable')).toBeVisible();
  await page.getByRole('textbox', { name: 'Expected SHA-256' })
    .fill(createHash('sha256').update(sample).digest('hex'));
  await expect(page.getByText('Matches the supplied SHA-256.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start writing' })).toBeDisabled();
});

test('bad expected checksum, malformed checksum and undersized USB block preflight', async ({ page }) => {
  await connectedAgent(page, 4096);
  await page.goto('/');
  await selectFile(page, 'fixture.iso', isoFixture());
  await page.getByRole('radio', { name: 'Compare image with USB QA Target' }).check();
  await expect(page.getByText('Image is larger than the target device.')).toBeVisible();
  const field = page.getByRole('textbox', { name: 'Expected SHA-256' });
  await field.fill('not-a-hash');
  await expect(page.getByText('Expected SHA-256 must be exactly 64 hexadecimal characters.')).toBeVisible();
  await field.fill('0'.repeat(64));
  await expect(page.getByText('Checksum mismatch. Do not use this image.')).toBeVisible();
  await expect(page.getByText('Preflight incomplete — physical writing unavailable')).toBeVisible();
});

test('GPT, MBR and unrecognized raw images are distinguished by bytes', async ({ page }) => {
  await page.route(agentBase + '**', route => route.abort('failed'));
  await page.goto('/');
  const mbr = mbrFixture();
  await selectFile(page, 'disk.dd', mbr);
  await expect(page.getByText('MBR raw image: recognized')).toBeVisible();
  const gpt = Buffer.alloc(40 * 512);
  gpt[510] = 0x55; gpt[511] = 0xaa; gpt.write('EFI PART', 512);
  gpt.writeUInt32LE(92, 512 + 12); gpt.writeBigUInt64LE(1n, 512 + 24);
  await selectFile(page, 'disk.img', gpt);
  await expect(page.getByText('GPT raw image: recognized')).toBeVisible();
  await selectFile(page, 'random.img', Buffer.alloc(2048, 42));
  await expect(page.getByText('Unrecognized: not validated')).toBeVisible();
  await expect(page.getByText('Preflight incomplete — physical writing unavailable')).toBeVisible();
});

test('malformed ISO, renamed ZIP and truncated images fail closed', async ({ page }) => {
  await page.route(agentBase + '**', route => route.abort('failed'));
  await page.goto('/');
  const iso = isoFixture(); iso.writeUInt32BE(99999, 16 * 2048 + 84);
  await selectFile(page, 'bad.iso', iso);
  await expect(page.getByText('Unrecognized: not validated')).toBeVisible();
  const zip = Buffer.alloc(512); zip.write('PK\x03\x04', 0, 'binary');
  await selectFile(page, 'disguised.iso', zip);
  await expect(page.getByText('Unsupported: not validated')).toBeVisible();
  await selectFile(page, 'tiny.img', Buffer.from([0x55, 0xaa]));
  await expect(page.getByText('Unrecognized: not validated')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start writing' })).toBeDisabled();
});

test('replacement file invalidates previous analysis and resetting clears checks', async ({ page }) => {
  await connectedAgent(page, 100 * 1024 * 1024);
  await page.goto('/');
  const old = mbrFixture(12 * 1024 * 1024);
  await page.locator('input[type=file]').setInputFiles(file('old.img', old));
  const fresh = isoFixture();
  await selectFile(page, 'fresh.iso', fresh);
  await page.getByRole('radio', { name: 'Compare image with USB QA Target' }).check();
  await expect(page.getByText('Read-only preliminary checks complete — writing unavailable')).toBeVisible();
  await page.getByRole('button', { name: 'Reset' }).click();
  await expect(page.getByTestId('image-sha256')).toHaveCount(0);
  await expect(page.getByText('Preflight incomplete — physical writing unavailable')).toBeVisible();
});

test('read-only target cannot pass the preflight', async ({ page }) => {
  await connectedAgent(page, 512 * 1024 * 1024, true);
  await page.goto('/');
  await selectFile(page, 'image.iso', isoFixture());
  await page.getByRole('radio', { name: 'Compare image with USB QA Target' }).check();
  await expect(page.getByText('Drive reports write protection. Preflight blocked.')).toBeVisible();
  await expect(page.getByText('Preflight incomplete — physical writing unavailable')).toBeVisible();
});

test('multi-chunk SHA-256 matches independent Node reference without uploading bytes', async ({ page }) => {
  await page.route(agentBase + '**', route => route.abort('failed'));
  await page.goto('/');
  const bytes = mbrFixture(9 * 1024 * 1024 + 512);
  await selectFile(page, 'multi.dd', bytes);
  await expect(page.getByText('MBR raw image: recognized')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start writing' })).toBeDisabled();
});

test('zero length and changed file name cannot retain a successful preflight', async ({ page }) => {
  await connectedAgent(page, 128 * 1024 * 1024);
  await page.goto('/');
  await selectFile(page, 'first.iso', isoFixture());
  await page.getByRole('radio', { name: 'Compare image with USB QA Target' }).check();
  await expect(page.getByText('Read-only preliminary checks complete — writing unavailable')).toBeVisible();
  await selectFile(page, 'empty.iso', Buffer.alloc(0));
  await expect(page.getByText('Unrecognized: not validated')).toBeVisible();
  await expect(page.getByText('Preflight incomplete — physical writing unavailable')).toBeVisible();
});
