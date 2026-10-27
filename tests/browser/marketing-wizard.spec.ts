import { test, expect } from '@playwright/test';

test('landing page communicates pre-release state and routes to the guided app', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Bootable media.');
  await expect(page.getByText('Pre-release preview. USB writing is not yet enabled.')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open guided app' })).toHaveAttribute('href', '/app');
  await expect(page.getByRole('link', { name: 'Explore the guided app' })).toHaveAttribute('href', '/app');
  await expect(page.getByRole('heading', { name: /Know your image/ })).toBeVisible();
});

test('FAQ does not claim physical USB writing works', async ({ page }) => {
  await page.goto('/');
  const question = page.getByRole('button', { name: /Can BootNexa write a bootable USB today/ });
  await question.click();
  await expect(page.getByText('Physical USB writing is intentionally disabled pending hardware safety and boot-validation tests.')).toBeVisible();
  await question.click();
  await expect(page.getByText('Physical USB writing is intentionally disabled pending hardware safety and boot-validation tests.')).toHaveCount(0);
});

test('wizard guides each stage but cannot initiate a destructive write', async ({ page }) => {
  const writes: string[] = [];
  await page.route('http://127.0.0.1:43627/**', async route => {
    if (route.request().method() !== 'GET') writes.push(route.request().url());
    await route.abort('failed');
  });
  await page.goto('/app');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('local companion');
  await expect(page.getByText('RELEASE PENDING')).toBeVisible();
  const next = page.getByRole('button', { name: 'Continue' });
  await next.click();
  await expect(page.getByRole('heading', { level: 1 })).toContainText('your permission');
  await next.click();
  await expect(page.getByRole('button', { name: /Choose your local ISO/ })).toBeVisible();
  await next.click();
  await expect(page.getByRole('heading', { level: 1 })).toContainText('target USB');
  await next.click();
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Review what');
  await next.click();
  await expect(page.getByRole('button', { name: 'Create bootable USB' })).toBeDisabled();
  await expect(page.getByText('Bootable USB writing is not available yet')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Explore read-only workspace' })).toHaveAttribute('href','/app/workspace');
  expect(writes).toEqual([]);
});

test('workspace is accessible but physical write remains disabled', async ({ page }) => {
  await page.route('http://127.0.0.1:43627/**', route => route.abort('failed'));
  await page.goto('/app/workspace');
  await expect(page.getByRole('button', { name: 'Start writing' })).toBeDisabled();
  await expect(page.getByText('Disk writing is not yet implemented.')).toBeVisible();
});
