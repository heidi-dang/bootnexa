import { useEffect, useState } from 'react';
import { Disc3, FileUp, Info, ShieldCheck } from 'lucide-react';
import { inspectIsoBoot, type IsoBootEvidence } from './iso-boot-evidence';
import { inspectVirtualIsoPlan, type VirtualIsoPlan } from './iso-virtual-plan';
import { useImageAnalysis } from './use-image-analysis';
import { identifyVerifiedLinuxVirtualIso } from './known-linux-images';
function sizeLabel(bytes: number) {
  return bytes >= 1048576 ? (bytes / 1048576).toFixed(1) + ' MiB' : bytes + ' bytes';
}
export function IsoLibrary() {
  const [file, setFile] = useState<File | null>(null);
  const [evidence, setEvidence] = useState<IsoBootEvidence | null>(null);
  const [error, setError] = useState('');
  const [virtualPlan, setVirtualPlan] = useState<VirtualIsoPlan | null>(null);
  const [virtualPlanError, setVirtualPlanError] = useState('');
  const { analysis, retry, cancel } = useImageAnalysis(file);
  useEffect(() => {
    setEvidence(null);
    setError('');
    setVirtualPlan(null);
    setVirtualPlanError('');
    if (!file) return;
    let active = true;
    inspectIsoBoot(file)
      .then(value => { if (active) setEvidence(value); })
      .catch(reason => { if (active) setError(reason instanceof Error ? reason.message : 'ISO metadata could not be validated.'); });
    inspectVirtualIsoPlan(file)
      .then(value => { if (active) setVirtualPlan(value); })
      .catch(reason => { if (active) setVirtualPlanError(reason instanceof Error ? reason.message : 'ISO directory layout not supported.'); });
    return () => { active = false; };
  }, [file]);
  const details = analysis.status === 'complete' ? analysis.result : null;
  const knownLinux = details && file ? identifyVerifiedLinuxVirtualIso(file.size,details.sha256) : null;
  return <div className="iso-library-view">
    <div className="page-heading">
      <div><div className="eyebrow"><Disc3 size={14}/> LOCAL MEDIA INTELLIGENCE</div>
        <h1>ISO <span>library.</span></h1>
        <p>Inspect local ISO metadata, catalogue boot records, and calculate SHA-256 without uploading the image.</p>
      </div>
      <span className="stage-label"><ShieldCheck size={14}/> INSPECTION ONLY</span>
    </div>
    <div className="work-grid">
      <div className="work-main">
        <section className="panel">
          <div className="section-title"><span className="number">01</span><div><h2>Choose an ISO</h2>
            <p>Local file structure inspection; no installation or disk modification.</p></div></div>
          <label className="drop-zone" htmlFor="iso-library-file">
            <span className="upload-icon"><FileUp size={23}/></span>
            <strong>{file ? file.name : 'Browse for an ISO image'}</strong>
            <span>{file ? sizeLabel(file.size) : 'Choose a local ISO image to inspect'}</span>
          </label>
          <input id="iso-library-file" type="file" accept=".iso" className="visually-hidden"
            onChange={event => { const selected = event.target.files?.[0]; setFile(selected && /\.iso$/i.test(selected.name) ? selected : null); event.target.value = ''; }}/>
          {analysis.status === 'working' && <div className="analysis-state" role="status">
            <strong>Computing local SHA-256: {Math.round(analysis.progress * 100)}%</strong>
            <progress value={analysis.progress * 100} max={100} aria-label="ISO hash progress"/>
            <button type="button" onClick={cancel}>Cancel hashing</button>
          </div>}
          {analysis.status === 'failed' && <p role="alert">Local analysis failed: {analysis.error} <button onClick={retry}>Retry</button></p>}
          {error && <p role="alert" className="preflight-pending">{error}</p>}
          <p className="helper"><ShieldCheck size={15}/> No image bytes leave your browser. Bootable USB writing remains disabled.</p>
        </section>
        <section className="panel" aria-label="ISO boot catalog evidence">
          <div className="section-title"><span className="number">02</span><div><h2>Boot catalog assessment</h2>
            <p>Limited ISO9660/UDF recognition and El Torito header validation. Not a firmware boot test.</p></div></div>
          <div className="summary-data">
            <div><span>ISO9660 descriptor</span><strong>{!file ? 'No image' : error ? 'Invalid' : evidence?.iso9660 ? 'Observed' : 'Not verified'}</strong></div>
            <div><span>UDF recognition signature</span><strong>{evidence?.udfSignature ? 'Observed' : 'Not verified'}</strong></div>
            <div><span>El Torito catalog</span><strong>{evidence?.catalogVerified ? 'Checksum validated' : 'Not verified'}</strong></div>
            <div><span>UEFI x64 boot support</span><strong>{evidence?.uefiCatalogEntry ? 'Catalog entry only' : 'Not verified'}</strong></div>
            <div><span>Legacy BIOS boot</span><strong>{evidence?.biosCatalogEntry ? 'Catalog entry only' : 'Not verified'}</strong></div>
            <div><span>Hybrid MBR</span><strong>{evidence?.hybridMbrCandidate ? 'Candidate only' : 'Not established'}</strong></div>
            <div><span>Physical writing authorised</span><strong>No</strong></div>
          </div>
          {evidence && <p className="notice" role="status"><Info size={16}/>{evidence.warning}</p>}
        </section>
        <section className="panel" aria-label="Virtual media compatibility plan" data-testid="iso-virtual-plan">
          <div className="section-title"><span className="number">03</span><div><h2>Virtual media compatibility</h2>
            <p>Bounded read-only directory traversal; preparation is not a supported disk-writing operation.</p></div></div>
          <div className="summary-data">
            <div><span>Detected media profile</span><strong data-testid="iso-profile">{knownLinux?.profile ?? virtualPlan?.profile ?? 'Not qualified'}</strong></div>
            <div><span>Virtual EFI conversion</span><strong data-testid="iso-virtual-eligible">{knownLinux ? 'Verified virtual profile (CLI only)' : virtualPlan?.virtualEfiEligible ? 'Developer-only candidate' : 'Disabled / unsupported'}</strong></div>
            <div><span>Files inspected</span><strong>{knownLinux ? 'Not extracted (raw ISO)' : virtualPlan?.fileCount ?? '—'}</strong></div>
            <div><span>Recognised file bytes</span><strong>{knownLinux ? sizeLabel(knownLinux.imageBytes) : virtualPlan ? sizeLabel(virtualPlan.totalBytes) : '—'}</strong></div>
            <div><span>OS boot evidence</span><strong>{knownLinux ? 'QEMU Linux login (pinned ISO only)' : 'Not verified'}</strong></div>
            <div><span>Physical USB write authorisation</span><strong>No</strong></div>
          </div>
          {knownLinux && <p className="notice" role="status" data-testid="iso-verified-linux-profile">
            Exact publisher-pinned SHA-256 matches {knownLinux.profile}. Its exact-version virtual-disk copy is qualified through the QEMU/OVMF Linux-login CI gate. Physical USB boot, installation and other Alpine images are not qualified. Use the developer CLI for virtual copying; this page never writes a disk.
          </p>}
          {!knownLinux && virtualPlan && <p className="notice" role="status">{virtualPlan.reason}</p>}
          {virtualPlanError && !knownLinux && <p className="helper" data-testid="iso-plan-error">Unsupported or invalid directory structure: {virtualPlanError}</p>}
          {!knownLinux && virtualPlan && virtualPlan.samplePaths.length>0 && <div className="hash-row">
            <strong>Recognised files (first {virtualPlan.samplePaths.length})</strong>
            <ul data-testid="iso-files">{virtualPlan.samplePaths.map(path=><li key={path}><code>{path}</code></li>)}</ul>
          </div>}
          <p className="helper">Production Windows/Linux ISO conversion, installer boot, WIM splitting and physical USB creation remain disabled. Qualified virtual copying is available only in the developer CLI.</p>
        </section>
      </div>
      <div className="work-side">
        <section className="panel">
          <div className="aside-title"><h2>Image summary</h2><span className="subtle-tag">LOCAL ONLY</span></div>
          <div className="summary-data">
            <div><span>Name</span><strong>{file?.name || 'Not selected'}</strong></div>
            <div><span>Size</span><strong>{file ? sizeLabel(file.size) : '—'}</strong></div>
            <div><span>Signature</span><strong>{details?.kind || 'Not inspected'}</strong></div>
            <div><span>SHA-256</span><strong>{details ? 'Computed' : 'Pending'}</strong></div>
            <div><span>Publisher-pinned Linux profile</span><strong>{knownLinux ? 'Exact digest match' : 'Not matched'}</strong></div>
          </div>
          {details && <div className="hash-row" style={{ overflowWrap: 'anywhere', fontSize: '11px' }}><code data-testid="library-sha256">{details.sha256}</code></div>}
          <p className="helper">No ISO extraction, WIM modifications, UEFI signing, partition writes or image installation is performed.</p>
        </section>
      </div>
    </div>
  </div>;
}
