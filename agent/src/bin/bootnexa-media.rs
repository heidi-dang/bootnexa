//! Developer-only safe, virtual media CLI; never accepts a target disk,
//! existing output file, partition handle, or USB device path.
use bootnexa_agent::{
    alpine_iso::VerifiedAlpineVirtual,
    hybrid_iso::VirtualHybrid,
    iso_inspect::inspect,
    iso_tree::{classify, enumerate},
    partition_layout::Scheme,
    virtual_boot_media::VirtualBootMedia,
    windows_iso,
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
        _=>return Err("usage: bootnexa-media inspect-iso <ISO> | inspect-windows-iso <ISO> | stage-windows-virtual-cdrom <supported-plain-ISO9660-ISO> <existing-output-directory> | plan-iso <ISO> | build-from-iso <small-qualified-ISO> <real-output-directory> | build-hybrid-virtual <restricted-dual-format-ISO> <real-output-directory> | build-alpine-virtual <verified-Alpine-virt-3.24.1-or-3.24.2-x86_64.iso> <real-output-directory> | build-virtual <EFI-file> <real-output-directory> gpt|mbr".into())
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("virtual media operation rejected: {error}");
        std::process::exit(1);
    }
}
