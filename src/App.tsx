import { useRef, useState, type ChangeEvent, type DragEvent } from 'react';
import { Activity, AlertTriangle, ArrowRight, BookOpen, Check, ChevronDown, CircleHelp, Clock3, CloudDownload, Command, Cpu, Disc3, FileArchive, FileUp, HardDrive, Info, Layers3, Menu, Monitor, Moon, RotateCcw, Settings2, ShieldCheck, SlidersHorizontal, Sparkles, Sun, Usb, X } from 'lucide-react';

type Page = 'Create USB' | 'ISO library' | 'Backup & restore' | 'Diagnostics' | 'Activity' | 'Settings';
type Theme = 'dark' | 'light';
const pages: { name: Page; icon: typeof Usb }[] = [
  { name: 'Create USB', icon: Usb },
  { name: 'ISO library', icon: Disc3 },
  { name: 'Backup & restore', icon: Layers3 },
  { name: 'Diagnostics', icon: Activity },
  { name: 'Activity', icon: Clock3 },
  { name: 'Settings', icon: Settings2 }
];
const formatBytes = (bytes: number) => bytes >= 1073741824 ? (bytes / 1073741824).toFixed(2) + ' GB' : (bytes / 1048576).toFixed(1) + ' MB';

function App() {
  const [page, setPage] = useState<Page>('Create USB');
  const [theme, setTheme] = useState<Theme>('dark');
  const [openMenu, setOpenMenu] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [partition, setPartition] = useState('GPT');
  const [target, setTarget] = useState('UEFI (non CSM)');
  const [filesystem, setFilesystem] = useState('FAT32');
  const [cluster, setCluster] = useState('Default');
  const [verify, setVerify] = useState(true);
  const [showFixed, setShowFixed] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const chooseFile = (candidate?: File) => {
    if (!candidate) return;
    const allowed = /\.(iso|img|ima|vhd|vhdx|ffu|gz|xz|zip)$/i;
    if (!allowed.test(candidate.name)) { window.alert('Please select a supported disk image (ISO, IMG, IMA, VHD, VHDX, FFU, GZ, XZ or ZIP).'); return; }
    setFile(candidate);
  };
  const onFileChange = (event: ChangeEvent<HTMLInputElement>) => chooseFile(event.target.files?.[0]);
  const onDrop = (event: DragEvent<HTMLDivElement>) => { event.preventDefault(); setDragging(false); chooseFile(event.dataTransfer.files?.[0]); };
  const updatePartition = (value: string) => { setPartition(value); setTarget(value === 'GPT' ? 'UEFI (non CSM)' : 'BIOS or UEFI-CSM'); };
  const showMain = page === 'Create USB';
  return (
    <div className={'app ' + theme}>
      <div className="ambient ambient-one" /><div className="ambient ambient-two" />
      <aside className={'sidebar ' + (openMenu ? 'sidebar-open' : '')} aria-label="Primary navigation">
        <div className="brand"><img src="/logo.svg" alt="" width="42" height="42"/><div><strong>Boot<span>Nexa</span></strong><small>DESKTOP WORKSPACE</small></div><button className="menu-close icon-button" onClick={() => setOpenMenu(false)} aria-label="Close menu"><X size={18}/></button></div>
        <div className="sidebar-label">WORKSPACE</div>
        <nav className="navigation">{pages.map(({name, icon: Icon}) => <button key={name} className={'nav-item ' + (page === name ? 'active' : '')} aria-current={page === name ? 'page' : undefined} onClick={() => { setPage(name); setOpenMenu(false); }}><Icon size={18}/><span>{name}</span>{name === 'Create USB' && <span className="nav-live" />}</button>)}</nav>
        <div className="sidebar-spacer"/>
        <div className="agent-status"><div className="status-row"><span className="status-dot offline"/><strong>Agent not connected</strong></div><p>Install the local agent to enable device access and USB writing.</p><a href="https://github.com/heidi-dang/bootnexa#how-it-works" target="_blank" rel="noreferrer">How it works <ArrowRight size={14}/></a></div>
        <div className="sidebar-footer"><span>PREVIEW BUILD</span><span>v0.1.0</span></div>
      </aside>
      {openMenu && <button className="mobile-overlay" onClick={() => setOpenMenu(false)} aria-label="Dismiss menu"/>}
      <div className="main-shell">
        <header className="topbar"><div className="top-left"><button className="icon-button mobile-menu" onClick={() => setOpenMenu(true)} aria-label="Open navigation"><Menu size={20}/></button><div className="breadcrumb">Workspace <span>/</span> <strong>{page}</strong></div></div><div className="top-actions"><span className="preview-pill"><span className="status-dot amber"/> UI preview</span><button className="icon-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} title={'Switch to ' + (theme === 'dark' ? 'light' : 'dark') + ' theme'} aria-label="Toggle theme">{theme === 'dark' ? <Sun size={18}/> : <Moon size={18}/>}</button><a className="icon-button" href="https://github.com/heidi-dang/bootnexa#readme" aria-label="Help" title="Read documentation" target="_blank" rel="noreferrer"><CircleHelp size={18}/></a><div className="avatar">BN</div></div></header>
        <main className="content">
          {showMain ? <>
            <div className="page-heading"><div><div className="eyebrow"><Sparkles size={14}/> A BETTER WAY TO BOOT</div><h1>Create bootable USB <span>media.</span></h1><p>One clear workflow for installation drives, disk images, and recovery media.</p></div><span className="stage-label"><span className="status-dot amber"/> PREVIEW / NOT READY TO WRITE</span></div>
            <div className="stepper" aria-label="Creation steps"><div className="step selected"><span>1</span><strong>Select</strong></div><div className="step-divider"/><div className="step"><span>2</span><strong>Configure</strong></div><div className="step-divider"/><div className="step"><span>3</span><strong>Write</strong></div><div className="step-divider"/><div className="step"><span>4</span><strong>Verify</strong></div></div>
            <div className="work-grid">
              <div className="work-main">
                <section className="panel"><div className="section-title"><span className="number">01</span><div><h2>Target drive</h2><p>Choose the USB device you want to prepare.</p></div><button className="icon-button refresh" title="Device discovery requires the local agent" aria-label="Refresh drives" disabled><RotateCcw size={17}/></button></div><div className="empty-device"><div className="empty-icon"><Usb size={22}/></div><div><strong>No USB drives available</strong><span>Connect the native agent to discover physical drives.</span></div><span className="device-badge">OFFLINE</span></div><div className="notice"><Info size={16}/><span>For your safety, system disks are excluded from the device picker by default.</span></div></section>
                <section className="panel"><div className="section-title"><span className="number">02</span><div><h2>Boot image</h2><p>Choose an ISO or a compatible disk image.</p></div></div><input type="file" ref={fileInput} onChange={onFileChange} accept=".iso,.img,.ima,.vhd,.vhdx,.ffu,.gz,.xz,.zip" className="visually-hidden" aria-label="Choose boot image"/><div className={'drop-zone ' + (dragging ? 'drag-over' : '')} role="button" tabIndex={0} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.current?.click(); } }} onClick={() => fileInput.current?.click()} onDragEnter={e => { e.preventDefault(); setDragging(true); }} onDragOver={e => e.preventDefault()} onDragLeave={e => { e.preventDefault(); setDragging(false); }} onDrop={onDrop}><div className="upload-icon">{file ? <FileArchive size={23}/> : <FileUp size={23}/>}</div>{file ? <><strong>{file.name}</strong><span>{formatBytes(file.size)} · Click to replace image</span></> : <><strong>Drop your ISO here, or <em>browse files</em></strong><span>ISO, IMG, IMA, VHD, VHDX, FFU, GZ, XZ, ZIP</span></>}</div><p className="helper"><ShieldCheck size={15}/> Selected images stay on your computer. Nothing is uploaded to a server.</p></section>
                <section className="panel"><div className="section-title"><span className="number">03</span><div><h2>Boot configuration</h2><p>Control the target firmware and disk layout.</p></div></div><div className="form-grid"><label>Partition scheme<select value={partition} onChange={e => updatePartition(e.target.value)}><option>GPT</option><option>MBR</option></select></label><label>Target system<select value={target} onChange={e => setTarget(e.target.value)}><option>UEFI (non CSM)</option><option>BIOS or UEFI-CSM</option></select></label><label>File system<select value={filesystem} onChange={e => setFilesystem(e.target.value)}><option>FAT32</option><option>NTFS</option><option>exFAT</option></select></label><label>Cluster size<select value={cluster} onChange={e => setCluster(e.target.value)}><option>Default</option><option>4096 bytes</option><option>8192 bytes</option><option>16384 bytes</option></select></label></div><button className="advanced-toggle" onClick={() => setAdvanced(!advanced)} aria-expanded={advanced}><SlidersHorizontal size={17}/> Advanced settings <ChevronDown className={advanced ? 'rotated' : ''} size={16}/></button>{advanced && <div className="advanced-options"><label className="toggle-row"><span><strong>Verify after writing</strong><small>Compare the completed image against the source.</small></span><input type="checkbox" checked={verify} onChange={e => setVerify(e.target.checked)}/></label><label className="toggle-row"><span><strong>Show fixed disks</strong><small>Dangerous operation; requires separate agent authorisation.</small></span><input type="checkbox" checked={showFixed} onChange={e => setShowFixed(e.target.checked)}/></label></div>}</section>
              </div>
              <div className="work-side">
                <section className="panel image-summary"><div className="aside-title"><h2>Image overview</h2><span className="subtle-tag">LOCAL</span></div><div className="image-visual"><div className="visual-orbit orbit-a"/><div className="visual-orbit orbit-b"/><div className="image-center"><Disc3 size={43}/></div></div><h3>{file ? file.name : 'Your next boot starts here.'}</h3><p>{file ? 'Image selected · Analysis requires native agent integration.' : 'Select a boot image to inspect its compatibility and prepare a drive.'}</p><div className="summary-data"><div><span>Image status</span><strong>{file ? 'Selected' : 'Not selected'}</strong></div><div><span>Detected OS</span><strong>Pending analysis</strong></div><div><span>Boot mode</span><strong>Not verified</strong></div><div><span>File size</span><strong>{file ? formatBytes(file.size) : '—'}</strong></div></div></section>
                <section className="panel trust-panel"><div className="trust-icon"><ShieldCheck size={20}/></div><div><h3>Your drives. Your control.</h3><p>The native agent will perform disk operations locally with explicit confirmation. No cloud ISO uploads.</p></div></section>
                <section className="shortcuts"><div><Cpu size={16}/> Native agent <span>Coming later</span></div><div><Monitor size={16}/> Platform <span>Windows first</span></div><div><BookOpen size={16}/> Documentation <a href="https://github.com/heidi-dang/bootnexa/tree/main/doc" target="_blank" rel="noreferrer">Read roadmap <ArrowRight size={13}/></a></div></section>
              </div>
            </div>
            <div className="action-bar"><div><div className="bar-heading"><AlertTriangle size={16}/> Disk writing is not yet implemented.</div><span>This preview supports image selection and interface settings, not physical USB operations.</span></div><div className="action-controls"><button className="secondary-button" onClick={() => { setFile(null); setAdvanced(false); if(fileInput.current) fileInput.current.value=''; }}>Reset</button><button className="primary-button" disabled title="Requires the native BootNexa Agent and a validated target drive">Start writing <ArrowRight size={18}/></button></div></div>
          </> : <div className="placeholder-page"><div className="eyebrow"><Command size={14}/> BOOTNEXA WORKSPACE</div><div className="placeholder-icon">{page === 'ISO library' ? <CloudDownload size={36}/> : page === 'Backup & restore' ? <HardDrive size={36}/> : page === 'Diagnostics' ? <Activity size={36}/> : page === 'Activity' ? <Clock3 size={36}/> : <Settings2 size={36}/>}</div><h1>{page}</h1><p>This feature is specified in the implementation roadmap and will become available in a future milestone. The navigation and visual shell are functional; device operations are not simulated.</p><a href="https://github.com/heidi-dang/bootnexa/blob/main/doc/ROADMAP.md" target="_blank" rel="noreferrer">View implementation roadmap <ArrowRight size={17}/></a><button onClick={() => setPage('Create USB')} className="secondary-button">Back to Create USB</button></div>}
        </main>
        <footer className="footer"><span><span className="status-dot amber"/> BootNexa UI Preview · No device is being accessed</span><span>Built for confidence at every step <Check size={14}/></span></footer>
      </div>
    </div>
  );
}
export default App;
