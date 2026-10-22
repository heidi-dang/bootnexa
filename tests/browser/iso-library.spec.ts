import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';

function isoFixture(invalidCatalog=false) {
  const bytes=Buffer.alloc(40*2048);
  const pvd=16*2048;
  bytes[pvd]=1; bytes.write('CD001',pvd+1); bytes[pvd+6]=1;
  bytes.fill(0x20,pvd+40,pvd+72); bytes.write('BOOTNEXA TEST',pvd+40);
  bytes.writeUInt32LE(40,pvd+80);bytes.writeUInt32BE(40,pvd+84);
  bytes.writeUInt16LE(2048,pvd+128);bytes.writeUInt16BE(2048,pvd+130);
  const boot=17*2048;
  bytes[boot]=0;bytes.write('CD001',boot+1);bytes[boot+6]=1;
  bytes.write('EL TORITO SPECIFICATION',boot+7);
  bytes.writeUInt32LE(30,boot+71);
  const term=18*2048;
  bytes[term]=255;bytes.write('CD001',term+1);bytes[term+6]=1;
  const catalog=30*2048;
  bytes[catalog]=1;bytes[catalog+1]=0xef;
  bytes[catalog+30]=0x55;bytes[catalog+31]=0xaa;
  const sum=Array.from({length:16},(_,i)=>bytes.readUInt16LE(catalog+i*2)).reduce((a,b)=>(a+b)&0xffff,0);
  bytes.writeUInt16LE((-sum)&0xffff,catalog+28);
  bytes[catalog+32]=0x88;
  if (invalidCatalog) bytes[catalog+28]^=1;
  return bytes;
}
test('ISO library validates local El Torito UEFI catalog and computes hash without enabling writing',async({page})=>{
  await page.route('http://127.0.0.1:43627/**',route=>route.abort('failed'));
  await page.goto('/');
  await page.getByRole('button',{name:'ISO library'}).click();
  await expect(page.getByRole('heading',{name:'ISO library.'})).toBeVisible();
  const image=isoFixture();
  await page.locator('#iso-library-file').setInputFiles({name:'test.iso',mimeType:'application/octet-stream',buffer:image});
  await expect(page.getByText('Checksum validated')).toBeVisible();
  await expect(page.getByText('Catalog entry only')).toHaveCount(1);
  await expect(page.getByTestId('library-sha256')).toHaveText(createHash('sha256').update(image).digest('hex'));
  await expect(page.getByText('Physical writing authorised')).toBeVisible();
  await expect(page.getByRole('button',{name:'Start writing'})).toHaveCount(0);
});
test('ISO library rejects a tampered catalog while still permitting read-only checksum inspection',async({page})=>{
  await page.goto('/');
  await page.getByRole('button',{name:'ISO library'}).click();
  const image=isoFixture(true);
  await page.locator('#iso-library-file').setInputFiles({name:'bad.iso',mimeType:'application/octet-stream',buffer:image});
  await expect(page.getByRole('alert')).toContainText('checksum failed');
  await expect(page.getByTestId('library-sha256')).toHaveText(createHash('sha256').update(image).digest('hex'));
  await expect(page.getByText('Catalog entry only')).toHaveCount(0);
});
