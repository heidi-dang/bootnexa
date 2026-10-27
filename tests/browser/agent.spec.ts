import { test, expect, type Page } from '@playwright/test';

const agent = 'http://127.0.0.1:43627/v1/';
const token = 'a'.repeat(64);
const headers = {
  'access-control-allow-origin': 'http://127.0.0.1:5173',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type',
};
type Reply = { status?: number; body?: unknown };
async function mockAgent(page: Page, reply: (path: string, method: string) => Reply | undefined) {
  const requests: string[] = [];
  await page.route(agent + '**', async route => {
    const request = route.request();
    const path = request.url().substring(agent.length);
    requests.push(request.method() + ' ' + path);
    const value = request.method() === 'OPTIONS' ? { status: 204 } : reply(path, request.method());
    if (!value) {
      await route.abort('failed');
      return;
    }
    await route.fulfill({ status: value.status || 200, headers, contentType: 'application/json', body: JSON.stringify(value.body ?? {}) });
  });
  return requests;
}

test('agent offline: no drive, no writes, clear reconnect guidance', async ({ page }) => {
  await page.route(agent + '**', route => route.abort('failed'));
  await page.goto('/app/workspace');
  await expect(page.getByText('Agent not connected')).toBeVisible();
  await expect(page.getByText('No USB drives available')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start writing' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Retry connection' })).toBeVisible();
});

test('Windows agent auto-discovery + approval renders actual inventory contract', async ({ page }) => {
  let approved = 0;
  const requests = await mockAgent(page, (path, method) => {
    if (path === 'health') return { body: { platform: 'windows', protocolVersion: '0.2', readOnly: true } };
    if (path === 'access/request' && method === 'POST') {
      approved++;
      return { body: { token, scope: 'devices:read', expiresInSeconds: 1800 } };
    }
    if (path === 'devices') return { body: { readOnly: true, devices: [{
      id: 'usb-fixture', model: 'USB QA Fixture', capacityBytes: 32000000000,
      busType: 'USB', partitionStyle: 'GPT', readOnly: false,
    }] } };
    if (path === 'access/revoke' && method === 'POST') return { status: 204 };
    return undefined;
  });
  await page.goto('/app/workspace');
  await expect(page.getByText('USB QA Fixture')).toBeVisible();
  await expect(page.getByText('Read-only device inventory')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start writing' })).toBeDisabled();
  expect(approved).toBe(1);
  expect(requests).toContain('GET health');
  expect(requests).toContain('POST access/request');
  expect(requests).toContain('GET devices');
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect.poll(() => requests.filter(x => x === 'GET devices').length).toBe(2);
  await page.getByRole('button', { name: 'Revoke access' }).click();
  await expect(page.getByRole('main').getByText('Device access has been revoked.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start writing' })).toBeDisabled();
  expect(requests).toContain('POST access/revoke');
});

test('native denial prevents inventory and disk operations', async ({ page }) => {
  const requests = await mockAgent(page, path => {
    if (path === 'health') return { body: { platform: 'windows', protocolVersion: '0.2' } };
    if (path === 'access/request') return { status: 403, body: { error: 'user_denied' } };
    return undefined;
  });
  await page.goto('/app/workspace');
  await expect(page.getByText('Access not authorised')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Request approval' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start writing' })).toBeDisabled();
  expect(requests).not.toContain('GET devices');
});

test('agent version mismatch is rejected before access prompt', async ({ page }) => {
  const requests = await mockAgent(page, path => path === 'health'
    ? { body: { platform: 'windows', protocolVersion: '0.1' } }
    : undefined);
  await page.goto('/app/workspace');
  await expect(page.getByRole('main').getByText('Agent version mismatch. Update BootNexa Agent.')).toBeVisible();
  expect(requests).not.toContain('POST access/request');
  await expect(page.getByRole('button', { name: 'Start writing' })).toBeDisabled();
});

test('local browser automatically discovers newly started agent on retry', async ({ page }) => {
  let available = false;
  await page.route(agent + '**', async route => {
    if (!available) { await route.abort('failed'); return; }
    const path = route.request().url().substring(agent.length);
    const body = path === 'health' ? { platform: 'windows', protocolVersion: '0.2' }
      : path === 'access/request' ? { token, scope: 'devices:read' }
      : { devices: [], readOnly: true };
    await route.fulfill({ status: 200, headers, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto('/app/workspace');
  await expect(page.getByText('Agent not connected')).toBeVisible();
  available = true;
  await page.getByRole('button', { name: 'Retry connection' }).click();
  await expect(page.getByText('Read-only device inventory')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start writing' })).toBeDisabled();
});
