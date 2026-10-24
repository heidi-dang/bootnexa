//! Developer-only safe, virtual media CLI; never accepts a target disk,
//! existing output file, partition handle, or USB device path.
use bootnexa_agent::{
    alpine_iso::VerifiedAlpineVirtual,
    hybrid_iso::VirtualHybrid,
    iso_inspect::inspect,
    iso_tree::{classify, enumerate},
    partition_layout::Scheme,
    swm_qualification, udf_structure, udf_tree,
    virtual_boot_media::VirtualBootMedia,
    windows_iso,
    windows_large_virtual::LargeSparseDisk,
    windows_media_plan,
};
use serde_json::json;
use std::{
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::Read,
    path::PathBuf,
};
use uuid::Uuid;
fn run() -> Result<(), Box<dyn Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice(){
        [op,gib] if op=="qualify-large-windows-fat32" =>{
            let capacity:u32=gib.parse()?;
            let mut disk=LargeSparseDisk::new(capacity)?;
            let proof=disk.format_payload_fat32()?;
            println!("{}",serde_json::to_string(&proof)?);
        }
        [op,gib,source,expected] if op=="stage-large-windows-payload-demo" =>{
            let capacity:u32=gib.parse()?;
            if !fs::symlink_metadata(source)?.file_type().is_file() {
                return Err("synthetic file must be a real regular file".into());
            }
            let mut input=File::open(source)?;
            let mut disk=LargeSparseDisk::new(capacity)?;
            let _=disk.format_payload_fat32()?;
            let report=disk.stage_synthetic_payload(&mut input,expected)?;
            println!("{}",serde_json::to_string(&report)?);
        }
        [op,gib,source] if op=="stage-large-windows-efi-demo" =>{
            let capacity:u32=gib.parse()?;
            let mut disk=LargeSparseDisk::new(capacity)?;
            let report=disk.stage_efi_test(std::path::Path::new(source))?;
            println!("{}",serde_json::to_string(&report)?);
        }
        [op,gib] if op=="qualify-large-windows-gpt" =>{
            // Anonymous sparse GPT/FAT32 EFI qualification only.
            // Never writes a physical device, exports a disk, or formats NTFS.
            let capacity:u32=gib.parse()?;
            let mut disk=LargeSparseDisk::new(capacity)?;
            println!("{}",serde_json::to_string(&disk.verify()?)?);
        }
        [op,source] if op=="inspect-iso" =>{
            let mut file=File::open(source)?;
            let meta=file.metadata()?;
            if !meta.is_file(){return Err("ISO input must be a regular file".into());}
            let report=inspect(&mut file,meta.len())?;
            println!("{}",serde_json::to_string(&report)?);
        }
        [op, source, output_dir] if op == "build-alpine-virtual" => {
            // Only the two independently pinned official Alpine virt 3.24.1/3.24.2 x86_64 releases.
            // Exactly-zero physical write authority, file output only.
            let mut input=File::open(source)?;
            if !input.metadata()?.is_file() {
                return Err("Linux ISO input must be a regular file".into());
            }
            let mut image=VerifiedAlpineVirtual::from_verified_iso(&mut input)?;
            let dir=PathBuf::from(output_dir);
            if !fs::symlink_metadata(&dir)?.file_type().is_dir() {
                return Err("output directory must exist and not be a symlink/device".into());
            }
            let dir=fs::canonicalize(dir)?;
            let path=dir.join(format!("bootnexa-alpine-virtual-{}.img",Uuid::new_v4().simple()));
            let mut output=OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
            if !output.metadata()?.is_file(){return Err("output must be a regular file".into());}
            let digest=match image.export_to_regular_file(&mut output) {
                Ok(value)=>value,
                Err(error)=>{
                    drop(output);
                    let _=fs::remove_file(&path);
                    return Err(error.into());
                }
            };
            println!("{}",json!({
                "virtualOnly":true,"physicalWriteAuthorized":false,
                "outputPath":path.to_string_lossy(),"outputSha256":digest,
                "media":image.report()}));
        }
        [op, source, output_dir] if op == "build-hybrid-virtual" => {
            // An experimental dual-format GPT/ISO image, not a generalized
            // Linux installer ISO and NEVER a physical-device target.
            let mut input=File::open(source)?;
            if !input.metadata()?.is_file(){
                return Err("hybrid input must be a regular file".into());
            }
            let mut hybrid=VirtualHybrid::from_iso_file(&mut input)?;
            let dir=PathBuf::from(output_dir);
            if !fs::symlink_metadata(&dir)?.file_type().is_dir(){
                return Err("virtual output parent must be an existing real directory".into());
            }
            let dir=fs::canonicalize(dir)?;
            let destination=dir.join(format!("bootnexa-hybrid-virtual-{}.img",Uuid::new_v4().simple()));
            let mut output=OpenOptions::new().read(true).write(true).create_new(true).open(&destination)?;
            if !output.metadata()?.is_file(){return Err("virtual output must be a regular file".into());}
            // On failed copying, remove this *new* file rather than leave a
            // potentially partial image as a usable-looking output.
            let digest=match hybrid.export_to_regular_file(&mut output) {
                Ok(digest)=>digest,
                Err(e)=>{
                    drop(output);
                    let _=fs::remove_file(&destination);
                    return Err(e.into());
                }
            };
            println!("{}",json!({"outputPath":destination.to_string_lossy(),
                "outputSha256":digest,"media":hybrid.report(),
                "virtualOnly":true,"physicalWriteAuthorized":false}));
        }
        [op, source] if op == "inspect-udf-tree" => {
            let mut input=File::open(source)?;
            let metadata=input.metadata()?;
            if !metadata.is_file() {
                return Err("UDF image source must be a regular file".into());
            }
            let report=udf_tree::inspect(&mut input,metadata.len())?;
            println!("{}",serde_json::to_string(&report)?);
        }
        [op, source] if op == "inspect-udf-structure" => {
            let mut input = File::open(source)?;
            let metadata = input.metadata()?;
            if !metadata.is_file() { return Err("UDF source must be a regular file".into()); }
            let report = udf_structure::inspect(&mut input, metadata.len())?;
            println!("{}", serde_json::to_string(&report)?);
        }
        [op, source] if op == "plan-windows-media" => {
            let mut input = File::open(source)?;
            let metadata = input.metadata()?;
            if !metadata.is_file() {
                return Err("Windows ISO source must be a regular file".into());
            }
            let inspection = windows_iso::inspect(&mut input, metadata.len())?;
            let plan = windows_media_plan::plan(&inspection);
            println!("{}", json!({"inspection":inspection,"layoutPlan":plan}));
        }
        [op,source,swm_dir,output_parent] if op=="build-windows-swm-demo" =>{
            use std::path::Path;
            let parent=Path::new(output_parent);
            if !fs::symlink_metadata(parent)?.file_type().is_dir(){
                return Err("demo output parent must be an existing real directory".into());
            }
            let destination_parent=fs::canonicalize(parent)?;
            let mut disk=VirtualBootMedia::new(192*1024*1024,Scheme::Gpt)?;
            let media=disk.populate_windows_swm_demo(Path::new(source),Path::new(swm_dir))?;
            let path=destination_parent.join(format!("bootnexa-windows-swm-demo-{}.img",Uuid::new_v4().simple()));
            let mut output=OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
            let result=disk.export_to_regular_file(&mut output);
            let digest=match result {
                Ok(hash)=>{
                    if output.metadata()?.len()!=192*1024*1024 {
                        drop(output);
                        let _=fs::remove_file(&path);
                        return Err("virtual demo exported wrong number of bytes".into());
                    }
                    hash
                }
                Err(error)=>{
                    drop(output);
                    let _=fs::remove_file(&path);
                    return Err(error.into());
                }
            };
            println!("{}",json!({
                "virtualOnly":true,"physicalWriteAuthorized":false,
                "installerCompatibleVerified":false,"windowsSetupBootVerified":false,
                "syntheticSmallFileDemonstrationOnly":true,
                "diskBytes":192*1024*1024u64,"outputSha256":digest,
                "outputPath":path.to_string_lossy(),"media":media
            }));
        }
        [op,source,parent] if op=="split-wim-virtual" =>{
            let report=swm_qualification::qualify_split(
                std::path::Path::new(source),std::path::Path::new(parent),3800)?;
            println!("{}",serde_json::to_string(&report)?);
        }
        [op,source,parent,mib] if op=="split-wim-virtual" =>{
            let target:u32=mib.parse()?;
            let report=swm_qualification::qualify_split(
                std::path::Path::new(source),std::path::Path::new(parent),target)?;
            println!("{}",serde_json::to_string(&report)?);
        }
        [op, source] if op == "inspect-windows-iso" => {
            let mut source = File::open(source)?;
            let metadata = source.metadata()?;
            if !metadata.is_file() {
                return Err("Windows ISO source must be a regular file".into());
            }
            let report = windows_iso::inspect(&mut source, metadata.len())?;
            println!("{}", serde_json::to_string(&report)?);
        }
        [op, source, output_dir] if op == "stage-windows-virtual-cdrom" => {
            // Developer-only bit-exact virtual CD-ROM artifact. No USB, GPT, FAT32,
            // WIM splitting, setup execution or physical write authority.
            let mut input = File::open(source)?;
            let metadata = input.metadata()?;
            if !metadata.is_file() {
                return Err("Windows ISO source must be a regular file".into());
            }
            let dir = PathBuf::from(output_dir);
            if !fs::symlink_metadata(&dir)?.file_type().is_dir() {
                return Err("destination must be an existing real directory".into());
            }
            let dir = fs::canonicalize(dir)?;
            let name = format!("bootnexa-windows-virtual-cdrom-{}.iso", Uuid::new_v4().simple());
            let path = dir.join(name);
            let mut output = OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
            let result = windows_iso::stage_virtual_cdrom(&mut input, &mut output, metadata.len());
            match result {
                Ok((report, digest)) => {
                    let finalize = (|| -> Result<(), Box<dyn Error>> {
                        output.sync_all()?;
                        if output.metadata()?.len() != metadata.len() {
                            return Err("virtual CD-ROM output is not sector-identical".into());
                        }
                        Ok(())
                    })();
                    if let Err(error) = finalize {
                        drop(output);
                        let _ = fs::remove_file(&path);
                        return Err(error);
                    }
                    println!("{}", json!({"virtualOnly":true,
                        "physicalWriteAuthorized":false,
                        "windowsSetupBootVerified":false,
                        "virtualCdromOnly":true,
                        "imageBytes":metadata.len(),
                        "outputPath":path.to_string_lossy(),
                        "outputSha256":digest,"media":report}));
                }
                Err(error) => {
                    drop(output);
                    let _ = fs::remove_file(&path);
                    return Err(error.into());
                }
            }
        }
        [op, source] if op == "plan-iso" => {
            let mut input=File::open(source)?;
            let metadata=input.metadata()?;
            if !metadata.is_file(){return Err("ISO source must be a regular file".into());}
            let tree=enumerate(&mut input,metadata.len())?;
            println!("{}",json!({"readOnly":true,"physicalWriteAuthorized":false,
                "plan":classify(&tree),"files":tree.files}));
        }
        [op, source, output_dir] if op == "build-udf-small-virtual" => {
            // Limited UDF -> anonymous GPT/FAT32 *regular-file* demonstration.
            // Does not create real Windows installer media or authorize USB.
            let mut input=File::open(source)?;
            let metadata=input.metadata()?;
            if !metadata.is_file() || metadata.len()>256*1024*1024 {
                return Err("UDF demonstration input must be a <=256MiB regular file".into());
            }
            let dir=PathBuf::from(output_dir);
            if !fs::symlink_metadata(&dir)?.file_type().is_dir() {
                return Err("virtual output parent must be an existing real directory".into());
            }
            let dir=fs::canonicalize(dir)?;
            let mut disk=VirtualBootMedia::new(96*1024*1024,Scheme::Gpt)?;
            let report=disk.populate_restricted_udf_virtual(&mut input,metadata.len())?;
            let destination=dir.join(format!("bootnexa-udf-demo-{}.img",Uuid::new_v4().simple()));
            let mut output=OpenOptions::new().read(true).write(true).create_new(true).open(&destination)?;
            let result=disk.export_to_regular_file(&mut output);
            let digest=match result {
                Ok(digest)=>{
                    let finalize=output.sync_all().and_then(|_|output.metadata());
                    match finalize {
                        Ok(meta) if meta.is_file() && meta.len()==96*1024*1024 => digest,
                        _ =>{
                            drop(output);
                            let _=fs::remove_file(&destination);
                            return Err("virtual output finalization failed".into());
                        }
                    }
                }
                Err(error)=>{
                    drop(output);
                    let _=fs::remove_file(&destination);
                    return Err(error.into());
                }
            };
            println!("{}",json!({
                "virtualOnly":true,"physicalWriteAuthorized":false,
                "windowsSetupBootVerified":false,"installerCompatible":false,
                "udfProfile":"restricted_small_virtual_demo",
                "sourceBytes":metadata.len(),"outputPath":destination.to_string_lossy(),
                "outputSha256":digest,"media":report
            }));
        }
        [op, source, output_dir] if op == "build-from-iso" => {
            let mut input=File::open(source)?;
            let metadata=input.metadata()?;
            if !metadata.is_file(){return Err("ISO source must be a regular file".into());}
            if metadata.len()>256*1024*1024 {
                return Err("virtual ISO input exceeds 256MiB qualification cap".into());
            }
            let tree=enumerate(&mut input,metadata.len())?;
            let plan=classify(&tree);
            if !plan.virtual_efi_eligible {
                return Err(format!("ISO is not qualified for virtual EFI extraction: {}",plan.reason).into());
            }
            let dir=PathBuf::from(output_dir);
            if !fs::symlink_metadata(&dir)?.file_type().is_dir(){
                return Err("destination must be an existing real directory".into());
            }
            let dir=fs::canonicalize(dir)?;
            let mut disk=VirtualBootMedia::new(96*1024*1024,Scheme::Gpt)?;
            let report=disk.populate_from_iso(&mut input,&tree)?;
            let destination=dir.join(format!("bootnexa-virtual-{}.img",Uuid::new_v4().simple()));
            let mut output=OpenOptions::new().read(true).write(true).create_new(true).open(&destination)?;
            if !output.metadata()?.is_file(){return Err("virtual output must be a regular file".into());}
            let digest=disk.export_to_regular_file(&mut output)?;
            println!("{}",json!({"virtualOnly":true,"physicalWriteAuthorized":false,
                "outputPath":destination.to_string_lossy(),"outputSha256":digest,
                "sourcePlan":plan,"media":report}));
        }
        [op,source,output_dir,scheme] if op=="build-virtual" =>{
            let scheme=match scheme.as_str() {
                "gpt"=>Scheme::Gpt,"mbr"=>Scheme::Mbr,_=>return Err("layout must be gpt or mbr".into())
            };
            // Read-only application source. Never accepts an output device.
            let file=File::open(source)?;
            let meta=file.metadata()?;
            if !meta.is_file() || meta.len()<256 || meta.len()>8*1024*1024 {
                return Err("EFI source must be a bounded regular file".into());
            }
            let mut bytes=Vec::with_capacity(meta.len() as usize);
            file.take(8*1024*1024+1).read_to_end(&mut bytes)?;
            if bytes.len()>8*1024*1024 {return Err("EFI source exceeds 8MiB limit".into());}
            let dir=PathBuf::from(output_dir);
            if !fs::symlink_metadata(&dir)?.file_type().is_dir() {
                return Err("destination must be a real directory, not a symlink or device".into());
            }
            let dir=fs::canonicalize(dir)?;
            if !dir.is_dir(){return Err("virtual media output parent is not a directory".into());}
            let mut disk=VirtualBootMedia::new(96*1024*1024,scheme)?;
            let report=disk.add_efi_application(&bytes)?;
            // Names generated by BootNexa; create_new refuses pre-existing
            // files, symlinks, device nodes, and their target names.
            let name=format!("bootnexa-virtual-{}.img",Uuid::new_v4().simple());
            let destination=dir.join(name);
            let mut output=OpenOptions::new().read(true).write(true).create_new(true).open(&destination)?;
            if !output.metadata()?.is_file() {return Err("virtual output must be a regular file".into());}
            let digest=disk.export_to_regular_file(&mut output)?;
            println!("{}",json!({
                "virtualOnly":true,"physicalWriteAuthorized":false,
                "outputPath":destination.to_string_lossy(),
                "outputSha256":digest,"media":report
            }));
        }
        _=>return Err("usage: bootnexa-media inspect-iso <ISO> | inspect-udf-structure <UDF-ISO> | inspect-udf-tree <restricted-UDF-ISO> | split-wim-virtual <WIM> <existing-output-directory> [part-size-MiB] | qualify-large-windows-gpt <1-24-GiB> | qualify-large-windows-fat32 <1-24-GiB> | stage-large-windows-payload-demo <1-24-GiB> <synthetic-file> <expected-sha256> | stage-large-windows-efi-demo <1-24-GiB> <synthetic-x64-efi-file> | build-windows-swm-demo <synthetic-source-directory> <verified-swm-directory> <existing-output-directory> | inspect-windows-iso <ISO> | plan-windows-media <ISO> | stage-windows-virtual-cdrom <supported-plain-ISO9660-ISO> <existing-output-directory> | plan-iso <ISO> | build-udf-small-virtual <restricted-UDF-ISO> <real-output-directory> | build-from-iso <small-qualified-ISO> <real-output-directory> | build-hybrid-virtual <restricted-dual-format-ISO> <real-output-directory> | build-alpine-virtual <verified-Alpine-virt-3.24.1-or-3.24.2-x86_64.iso> <real-output-directory> | build-virtual <EFI-file> <real-output-directory> gpt|mbr".into())
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("virtual media operation rejected: {error}");
        std::process::exit(1);
    }
}
