import { test, expect } from '@playwright/test';
function makeIso(profile:'efi'|'windows'='efi') {
  const image=Buffer.alloc(80*2048);
  const record=(lba:number,size:number,name:Buffer,dir:boolean) => {
    const b=Buffer.alloc(33+name.length+(name.length%2===0?1:0));
    b[0]=b.length;b.writeUInt32LE(lba,2);b.writeUInt32BE(lba,6);
    b.writeUInt32LE(size,10);b.writeUInt32BE(size,14);
    b[25]=dir?2:0;b.writeUInt16LE(1,28);b.writeUInt16BE(1,30);
    b[32]=name.length;name.copy(b,33);
    return b;
  };
  const directory=(lba:number,entries:Buffer[]) => {
    let p=lba*2048;
    for(const entry of entries){entry.copy(image,p);p+=entry.length;}
  };
  const pvd=16*2048;
  image[pvd]=1;image.write('CD001',pvd+1);image[pvd+6]=1;
  image.fill(32,pvd+40,pvd+72);
  record(22,2048,Buffer.from([0]),true).copy(image,pvd+156);
  image[17*2048]=255;image.write('CD001',17*2048+1);image[17*2048+6]=1;
  const root=[record(22,2048,Buffer.from([0]),true),
    record(22,2048,Buffer.from([1]),true),
    record(23,2048,Buffer.from('EFI'),true),
    record(30,16,Buffer.from('README.TXT;1'),false)];
  if(profile==='windows')root.push(record(26,2048,Buffer.from('SOURCES'),true));
  directory(22,root);
  directory(23,[record(23,2048,Buffer.from([0]),true),
    record(22,2048,Buffer.from([1]),true),
    record(24,2048,Buffer.from('BOOT'),true)]);
  directory(24,[record(24,2048,Buffer.from([0]),true),
    record(23,2048,Buffer.from([1]),true),
    record(35,1024,Buffer.from('BOOTX64.EFI;1'),false)]);
  if(profile==='windows')
    directory(26,[record(26,2048,Buffer.from([0]),true),
      record(22,2048,Buffer.from([1]),true),
      record(36,16,Buffer.from('BOOT.WIM;1'),false)]);
  image.write('MZ',35*2048);
  return image;
}
test('ISO library previews a bounded x64 EFI directory tree without offering a disk write',async({page})=>{
  await page.goto('/');
  await page.getByRole('button',{name:'ISO library'}).click();
  await page.locator('#iso-library-file').setInputFiles({
    name:'small-efi.iso',mimeType:'application/octet-stream',buffer:makeIso()});
  await expect(page.getByTestId('iso-profile')).toHaveText('efi_application_virtual_only');
  await expect(page.getByTestId('iso-virtual-eligible')).toHaveText('Developer-only candidate');
  await expect(page.getByTestId('iso-files')).toContainText('EFI/BOOT/BOOTX64.EFI');
  await expect(page.getByText('Physical USB write authorisation')).toBeVisible();
  await expect(page.getByRole('button',{name:/write usb|start writing/i})).toHaveCount(0);
});
test('Windows installer ISO candidate is detected but virtual and physical writing are refused',async({page})=>{
  await page.goto('/');
  await page.getByRole('button',{name:'ISO library'}).click();
  await page.locator('#iso-library-file').setInputFiles({
    name:'windows-candidate.iso',mimeType:'application/octet-stream',buffer:makeIso('windows')});
  await expect(page.getByTestId('iso-profile')).toHaveText('windows_install_candidate');
  await expect(page.getByTestId('iso-virtual-eligible')).toHaveText('Disabled / unsupported');
  await expect(page.getByTestId('windows-install-payload')).toHaveText('Missing or ambiguous');
  await expect(page.getByTestId('iso-virtual-plan')).toContainText('WIM/ESD');
});
test('Windows ISO with a UDF volume signature never claims Setup boot or a physical writer',async({page})=>{
  const image=makeIso('windows');
  for(const [lba,signature] of [[19,'BEA01'],[20,'NSR03'],[21,'TEA01']] as const)
    image.write(signature,lba*2048+1);
  await page.goto('/');
  await page.getByRole('button',{name:'ISO library'}).click();
  await page.locator('#iso-library-file').setInputFiles({
    name:'windows-udf-candidate.iso',mimeType:'application/octet-stream',buffer:image});
  await expect(page.getByTestId('iso-profile')).toHaveText('windows_install_candidate');
  await expect(page.getByTestId('iso-virtual-eligible')).toHaveText('Disabled / unsupported');
  await expect(page.getByTestId('iso-virtual-plan')).toContainText('UDF');
  await expect(page.getByTestId('iso-virtual-plan')).toContainText('Windows Setup boot tested');
  await expect(page.getByRole('button',{name:/write usb|start writing/i})).toHaveCount(0);
});
test('malformed primary-directory extents fail closed in browser planning',async({page})=>{
  const image=makeIso();
  image.writeUInt32LE(0xffffffff,16*2048+156+2);
  await page.goto('/');
  await page.getByRole('button',{name:'ISO library'}).click();
  await page.locator('#iso-library-file').setInputFiles({
    name:'unsafe.iso',mimeType:'application/octet-stream',buffer:image});
  await expect(page.getByTestId('iso-plan-error')).toContainText('unsupported or invalid', {ignoreCase:true});
  await expect(page.getByTestId('iso-virtual-eligible')).toHaveText('Disabled / unsupported');
});
