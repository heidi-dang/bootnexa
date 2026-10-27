import { useRef, useState, type ChangeEvent } from 'react';
import { AlertTriangle, ArrowLeft, ArrowRight, BadgeCheck, Check, ChevronRight, CircleCheck, Disc3, Download, FileCheck2, FileUp, HardDrive, Info, LockKeyhole, Monitor, RefreshCw, ShieldCheck, Usb } from 'lucide-react';
import { useAgent } from './agent';
import { useImageAnalysis } from './use-image-analysis';
import { evaluatePreflight } from './image-preflight';
import './wizard.css';

const steps = [
  { name: 'Get the agent', detail: 'Local Windows companion', icon: Download },
  { name: 'Connect safely', detail: 'Read-only consent', icon: LockKeyhole },
  { name: 'Choose an image', detail: 'Local inspection', icon: Disc3 },
  { name: 'Select your USB', detail: 'Read-only device inventory', icon: Usb },
  { name: 'Safety review', detail: 'Verify before writing', icon: ShieldCheck },
  { name: 'Write & verify', detail: 'Release-gated', icon: FileCheck2 },
];

export default function SetupWizard() {
  const [step,setStep]=useState(0);
  const [file,setFile]=useState<File|null>(null);
  const [targetId,setTargetId]=useState<string|null>(null);
  const [expectedHash,setExpectedHash]=useState('');
  const picker=useRef<HTMLInputElement>(null);
  const agentApi=useAgent();
  const { analysis,cancel,retry }=useImageAnalysis(file);
  const detected=analysis.status==='complete'?analysis.result:null;
  const connected=agentApi.agent.phase==='connected';
  const chosen=connected?agentApi.agent.devices.find(d=>d.id===targetId):undefined;
  const preflight=evaluatePreflight(file,detected,chosen,expectedHash);
  const selectFile=(event:ChangeEvent<HTMLInputElement>)=>{
    const candidate=event.target.files?.[0]??null;
    setFile(candidate);
    setExpectedHash('');
    event.target.value='';
  };
  return <div className="wiz"><div className="wiz-shell">
    <aside className="wiz-aside">
      <a href="/" className="wiz-logo" aria-label="BootNexa home"><span><Disc3 size={22}/></span> boot<em>nexa</em></a>
      <div className="wiz-aside-heading"><span>GUIDED SETUP</span><h2>Let's get you<br/>ready.</h2><p>Six clear stages. One careful step at a time.</p></div>
      <nav className="wiz-progress" aria-label="Setup stages">{steps.map(({name,detail,icon:Icon},i)=><div className={'wiz-progress-item '+(step===i?'wiz-current':step>i?'wiz-previous':'')} key={name}><div className="wiz-step-marker">{step>i?<Check size={15}/>:<Icon size={17}/>}</div><div><strong>{name}</strong><small>{detail}</small></div>{step===i&&<ChevronRight size={15} className="wiz-chevron"/>}</div>)}</nav>
      <div className="wiz-aside-bottom"><ShieldCheck size={23}/><div><strong>Safety comes first</strong><p>Read-only preparation. No silent disk writes or simulated successful creation.</p></div></div>
    </aside>
    <main className="wiz-main">
      <header className="wiz-topbar"><span>BootNexa <ChevronRight size={13}/> Guided setup</span><span className="wiz-top-status"><i/> PRE-RELEASE</span><a href="/app/workspace">Preparation workspace <ArrowRight size={15}/></a></header>
      <div className="wiz-stage">
        <div className="wiz-mobile-progress">STEP {step+1} OF {steps.length}<div className="wiz-bar"><span style={{width:String((step+1)/steps.length*100)+'%'}}/></div></div>
        <div className="wiz-overline"><strong>{String(step+1).padStart(2,'0')}</strong> / {steps.length} · {steps[step].name.toUpperCase()}</div>
        {step===0&&<>
          <h1>Start with your<br/><em>local companion.</em></h1><p className="wiz-intro">BootNexa Agent runs on your Windows PC. It is designed for consent-based device discovery, so you stay in control of which information the web app can see.</p>
          <div className="wiz-install-card"><div className="wiz-install-icon"><Monitor size={29}/></div><div><span>WINDOWS COMPANION</span><h3>BootNexa Agent</h3><p>We have not confirmed a publicly available signed installer. Check the release channel and never run an unverified download.</p><a href="https://github.com/heidi-dang/bootnexa/releases" target="_blank" rel="noopener noreferrer">View official release channel <ArrowRight size={16}/></a></div><small>RELEASE PENDING</small></div>
          <div className="wiz-instructions"><h3>When the signed release is available</h3><p><b>1</b> Download the Windows agent from the verified release page.</p><p><b>2</b> Install and launch it on your own Windows computer.</p><p><b>3</b> Return to BootNexa and approve the local connection.</p></div>
        </>}
        {step===1&&<>
          <h1>Connect with<br/><em>your permission.</em></h1><p className="wiz-intro">BootNexa looks for an agent on your own computer. Windows asks you to approve read-only USB access before your drives are displayed.</p>
          <div className="wiz-connection"><div className="wiz-connection-icon"><Monitor size={38}/></div><div><span>LOCAL AGENT STATUS</span><h3>{connected?'Agent connected':agentApi.agent.phase==='approval'?'Waiting for your approval':agentApi.agent.phase==='searching'?'Searching for local agent…':'Agent not connected'}</h3><p role="status">{agentApi.agent.message}</p><div className="wiz-inline-actions"><button onClick={()=>void agentApi.connect()} disabled={agentApi.agent.phase==='searching'||agentApi.agent.phase==='approval'}><RefreshCw size={16}/> Retry connection</button>{connected&&<button onClick={()=>void agentApi.revoke()}>Revoke access</button>}</div></div></div>
          <div className="wiz-note"><Info size={19}/><span>The agent is reached at <code>127.0.0.1</code>, on your own computer. Its Windows consent prompt cannot be skipped.</span></div>
        </>}
        {step===2&&<>
          <h1>Choose an image.<br/><em>Know what it is.</em></h1><p className="wiz-intro">Select a local ISO or compatible disk image. Supported images are inspected and SHA-256-hashed in your browser.</p>
          <input ref={picker} type="file" accept=".iso,.img,.ima,.dd,.vhd,.vhdx,.ffu,.gz,.xz,.zip" className="wiz-hidden" aria-label="Choose image file" onChange={selectFile}/>
          <button className="wiz-file-picker" onClick={()=>picker.current?.click()}><span><FileUp size={31}/></span><strong>{file?.name??'Choose your local ISO or disk image'}</strong><small>{file?(file.size/1048576).toFixed(1)+' MiB · Change file':'Browse files on your computer · No cloud upload'}</small></button>
          {file&&<div className="wiz-analysis" aria-live="polite">
            {analysis.status==='working'&&<><strong>Hashing locally — {Math.round(analysis.progress*100)}%</strong><progress value={analysis.progress*100} max={100}/><button onClick={cancel}>Cancel</button></>}
            {analysis.status==='failed'&&<><strong>Inspection failed: {analysis.error}</strong><button onClick={retry}>Retry</button></>}
            {analysis.status==='cancelled'&&<><strong>Inspection cancelled.</strong><button onClick={retry}>Restart</button></>}
            {detected&&<><div className="wiz-analysis-title"><BadgeCheck size={18}/><strong>{detected.kind} · {detected.supported?'Recognized':'Not validated'}</strong></div><p>{detected.description}</p><small>SHA-256</small><code>{detected.sha256}</code></>}
          </div>}
          <div className="wiz-note"><ShieldCheck size={19}/><span>Image files are inspected locally. File selection does not transmit your ISO to BootNexa servers.</span></div>
        </>}
        {step===3&&<>
          <h1>Choose your<br/><em>target USB.</em></h1><p className="wiz-intro">View eligible removable drives from your approved agent. Selection is strictly for read-only comparison, never permission to erase.</p>
          {!connected?<div className="wiz-empty"><Usb size={31}/><h3>No connected agent</h3><p>{agentApi.agent.message}</p><button onClick={()=>setStep(1)}>Return to connection <ArrowLeft size={16}/></button></div>:<>
            <div className="wiz-drives-heading"><span>REMOVABLE DEVICES · {agentApi.agent.devices.length}</span><button onClick={()=>void agentApi.refresh()}><RefreshCw size={15}/> Refresh drives</button></div>
            {agentApi.agent.devices.length===0?<div className="wiz-empty"><Usb size={31}/><h3>No eligible drives detected</h3><p>Connect a removable USB drive to your Windows PC, then refresh.</p></div>:<div className="wiz-drives">{agentApi.agent.devices.map(d=><label key={d.id} className={'wiz-drive '+(targetId===d.id?'wiz-drive-selected':'')}><input type="radio" name="wizard-readonly-device" checked={targetId===d.id} onChange={()=>setTargetId(d.id)}/><HardDrive size={25}/><div><strong>{d.model}</strong><small>{(d.capacityBytes/1073741824).toFixed(1)} GiB · {d.busType} · {d.partitionStyle}</small></div><em>READ ONLY</em></label>)}</div>}
          </>}
          <div className="wiz-note"><AlertTriangle size={19}/><span>Neither drive discovery nor drive selection authorizes a physical write.</span></div>
        </>}
        {step===4&&<>
          <h1>Review what<br/><em>you know.</em></h1><p className="wiz-intro">Review your local preparation evidence. Passing a read-only preflight does not guarantee that the ISO will boot.</p>
          <div className="wiz-summary"><div><small>IMAGE</small><strong>{file?.name??'No image selected'}</strong></div><div><small>USB DEVICE</small><strong>{chosen?.model??'No approved drive selected'}</strong></div></div>
          <label className="wiz-field-label" htmlFor="expected-wizard-sha">Publisher SHA-256 (optional)</label><input id="expected-wizard-sha" className="wiz-hash-input" value={expectedHash} onChange={e=>setExpectedHash(e.target.value)} maxLength={80} placeholder="Enter independently published 64-character checksum" spellCheck={false}/>
          <div className="wiz-checks">{preflight.checks.map(item=><div key={item.label}><span className={item.ok?'wiz-check-ok':''}>{item.ok?<Check size={16}/>:<Info size={16}/>}</span><div><strong>{item.label}</strong><p>{item.detail}</p></div></div>)}</div>
          <div className="wiz-note"><ShieldCheck size={19}/><span>{preflight.headline} This release cannot issue a physical USB write plan.</span></div>
        </>}
        {step===5&&<>
          <h1>Safety first.<br/><em>Always.</em></h1><p className="wiz-intro">Physical USB writing is still under real-device qualification. When it is ready, this step will require explicit device identity checks, destructive-action consent, full readback and boot evidence.</p>
          <div className="wiz-final-card"><div className="wiz-final-lock"><LockKeyhole size={37}/></div><div><span>SAFETY RELEASE GATE</span><h3>Bootable USB writing is not available yet</h3><p>You can use the workspace to inspect images and read removable drive information. This preview cannot erase or write to a USB device.</p><button disabled aria-disabled="true">Create bootable USB <ArrowRight size={18}/></button></div></div>
          <a className="wiz-workspace-link" href="/app/workspace">Explore read-only workspace <ArrowRight size={17}/></a>
        </>}
        <div className="wiz-navigation"><button onClick={()=>setStep(s=>Math.max(0,s-1))} disabled={step===0} className="wiz-back"><ArrowLeft size={17}/> Back</button><span>Step {step+1} of {steps.length}</span>{step<5?<button className="wiz-next" onClick={()=>setStep(s=>Math.min(5,s+1))}>Continue <ArrowRight size={17}/></button>:<a className="wiz-next" href="/app/workspace">Open workspace <ArrowRight size={17}/></a>}</div>
      </div>
      <footer className="wiz-footer"><span><CircleCheck size={15}/> Your images stay on this device</span><div><a href="/">Home</a><a href="https://github.com/heidi-dang/bootnexa/releases" target="_blank" rel="noopener noreferrer">Release channel <ArrowRight size={13}/></a></div></footer>
    </main>
  </div></div>;
}