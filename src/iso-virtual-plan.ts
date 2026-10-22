// Local-only read-only ISO9660 primary-directory compatibility preview.
// No extraction, upload, native IPC calls, USB capabilities, or filesystem writes.
export type VirtualIsoPlan = {
  profile: 'efi_application_virtual_only' | 'windows_install_candidate' |
    'linux_distribution_candidate' | 'unsupported_boot_layout';
  virtualEfiEligible: boolean;
  physicalWriteAuthorized: false;
  windowsSetupVerified: false;
  linuxBootVerified: false;
  fileCount: number;
  totalBytes: number;
  samplePaths: string[];
  reason: string;
};
type IsoRecord = { name:string; offset:number; length:number; isDirectory:boolean };
const BLOCK=2048, MAX_FILES=512, MAX_TREE=60*1048576, MAX_FILE=48*1048576;
const readNumber=(v:DataView,offset:number)=> {
  const little=v.getUint32(offset,true), big=v.getUint32(offset+4,false);
  if (little!==big) throw new Error('ISO extent endian fields disagree.');
  return little;
};
async function read(file:File,offset:number,length:number) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) ||
    offset<0 || length<0 || offset+length>file.size)
    throw new Error('ISO metadata extent is outside the image.');
  const result=new Uint8Array(await file.slice(offset,offset+length).arrayBuffer());
  if (result.length!==length) throw new Error('ISO metadata read was incomplete.');
  return result;
}
function record(b:Uint8Array, imageBytes:number):IsoRecord|null {
  if (b.length<34 || b[0]!==b.length)throw new Error('Malformed ISO directory record.');
  const n=b[32];
  if (n===0 || 33+n>b.length || b[1]!==0 || b[26]!==0 || b[27]!==0 ||
    (b[25]&~2)!==0 || b[28]!==1 || b[29]!==0 || b[30]!==0 || b[31]!==1)
    throw new Error('Unsupported ISO directory feature (multi-extent, interleaving or special record).');
  const nominalEnd=33+n+(n%2===0?1:0);
  if(nominalEnd>b.length || b.subarray(nominalEnd).some(value=>value!==0))
    throw new Error('Rock Ridge/SUSP or extended ISO directory features need separate qualification.');
  const view=new DataView(b.buffer,b.byteOffset,b.byteLength);
  const offset=readNumber(view,2)*BLOCK, length=readNumber(view,10);
  if (!offset || !Number.isSafeInteger(offset+length) || offset+length>imageBytes)
    throw new Error('ISO entry refers to an invalid extent.');
  if(n===1 && (b[33]===0 || b[33]===1))return null;
  if(b.subarray(33,33+n).some(value=>value>127))
    throw new Error('Non-ASCII primary ISO filename requires unsupported Unicode handling.');
  let name=String.fromCharCode(...b.subarray(33,33+n));
  if(name.includes(';')){
    if(!name.endsWith(';1'))throw new Error('Unsupported ISO file version.');
    name=name.slice(0,-2);
  }
  name=name.replace(/\.+$/,'').toUpperCase();
  if(!name || name==='.' || name==='..' || name.length>60 ||
     !/^[A-Z0-9_.-]+$/.test(name))throw new Error('Unsafe or unsupported ISO path.');
  return {name,offset,length,isDirectory:(b[25]&2)!==0};
}
export async function inspectVirtualIsoPlan(file:File):Promise<VirtualIsoPlan> {
  if(file.size<18*BLOCK || file.size>128*1024*1024*1024)
    throw new Error('Image size is outside ISO metadata inspection limits.');
  const pvd=await read(file,16*BLOCK,BLOCK);
  if(pvd[0]!==1 || String.fromCharCode(...pvd.subarray(1,6))!=='CD001' || pvd[6]!==1)
    throw new Error('A supported ISO9660 primary volume descriptor is missing.');
  const rootLen=pvd[156];
  if(rootLen<34 || rootLen>255 || 156+rootLen>BLOCK)
    throw new Error('ISO primary root directory is corrupt.');
  const root=record(pvd.subarray(156,156+rootLen),file.size);
  if(root!==null || pvd[156+32]!==1 || pvd[156+33]!==0 || (pvd[156+25]&2)===0)
    throw new Error('ISO root directory is ambiguous.');
  const rootView=new DataView(pvd.buffer,pvd.byteOffset+156,rootLen);
  const rootOffset=readNumber(rootView,2)*BLOCK, rootSize=readNumber(rootView,10);
  const pending:[string,number,number,number][]=[['',rootOffset,rootSize,0]];
  const used=new Set<string>(),names=new Set<string>();
  const regions:[number,number][]=[[16*BLOCK,20*BLOCK]];
  const paths:string[]=[];
  let totalBytes=0;
  while(pending.length){
    const [prefix,start,size,depth]=pending.pop()!;
    if(depth>8 || size<=0 || size>1048576 || used.has(start+':'+size))
      throw new Error('ISO directory depth, extent or alias exceeds allowed limits.');
    used.add(start+':'+size);regions.push([start,start+size]);
    const bytes=await read(file,start,size);
    for(let pos=0;pos<bytes.length;){
      const len=bytes[pos];
      if(len===0){
        const next=Math.min(bytes.length,(Math.floor(pos/BLOCK)+1)*BLOCK);
        if(bytes.subarray(pos,next).some(value=>value!==0))throw new Error('Invalid ISO sector padding.');
        pos=next;continue;
      }
      if(len<34 || pos+len>bytes.length || Math.floor(pos/BLOCK)!==Math.floor((pos+len-1)/BLOCK))
        throw new Error('ISO directory record crosses sector boundary.');
      const entry=record(bytes.subarray(pos,pos+len),file.size);pos+=len;
      if(!entry)continue;
      const path=prefix?prefix+'/'+entry.name:entry.name;
      if(path.length>240 || names.has(path))throw new Error('ISO path alias or duplicate name.');
      names.add(path);
      if(names.size>MAX_FILES)throw new Error('ISO directory entry count exceeds bounded planner limit.');
      if(entry.isDirectory){
        if(depth>=8)throw new Error('ISO path depth exceeds supported limit.');
        pending.push([path,entry.offset,entry.length,depth+1]);
      } else {
        if(entry.length>MAX_FILE)throw new Error('ISO file exceeds bounded extraction limit.');
        totalBytes+=entry.length;
        if(totalBytes>MAX_TREE || paths.length>=MAX_FILES)
          throw new Error('ISO content exceeds bounded virtual image limits.');
        paths.push(path);
        if(entry.length)regions.push([entry.offset,entry.offset+entry.length]);
      }
    }
  }
  regions.sort((a,b)=>a[0]-b[0]);
  if(regions.some((r,i)=>i>0 && regions[i-1][1]>r[0]))
    throw new Error('ISO entries overlap file or directory metadata.');
  paths.sort();
  const namesSet=new Set(paths);
  const windows=namesSet.has('SOURCES/BOOT.WIM') || namesSet.has('SOURCES/INSTALL.WIM') || namesSet.has('SOURCES/INSTALL.ESD');
  const linux=namesSet.has('CASPER/VMLINUZ') || namesSet.has('ISOLINUX/ISOLINUX.BIN') || namesSet.has('BOOT/GRUB/GRUB.CFG');
  const efi=namesSet.has('EFI/BOOT/BOOTX64.EFI');
  const profile=windows?'windows_install_candidate':linux?'linux_distribution_candidate':
    efi?'efi_application_virtual_only':'unsupported_boot_layout';
  const virtualEfiEligible=efi && !windows && !linux && file.size<=256*1048576;
  const reason=windows?'Windows installer candidate: WIM/ESD, bootloader and Setup not qualified; conversion disabled.':
    linux?'Linux candidate: distribution bootloader/kernel/hybrid ISO profile not qualified; conversion disabled.':
    virtualEfiEligible?'Small x64 EFI layout: eligible for developer-only file-backed virtual conversion, not physical USB.':
    'No qualifying x64 EFI application or virtual image capacity exceeds supported limits.';
  return {profile,virtualEfiEligible,physicalWriteAuthorized:false,windowsSetupVerified:false,
    linuxBootVerified:false,fileCount:paths.length,totalBytes,samplePaths:paths.slice(0,8),reason};
}
