import { ArrowRight, ArrowUpRight, BadgeCheck, Check, ChevronRight, CircleHelp, Disc3, Download, Fingerprint, HardDrive, LockKeyhole, Menu, Monitor, ShieldCheck, Usb, X, Zap } from 'lucide-react';
import { useState } from 'react';
import './marketing.css';

const steps = [
  { n: '01', title: 'Install your local agent', description: 'A Windows companion designed to keep device access on your computer. Signed downloads are still undergoing release qualification.' },
  { n: '02', title: 'Connect with consent', description: 'Approve the local connection yourself. BootNexa can inspect eligible USB devices without granting write access.' },
  { n: '03', title: 'Inspect your image', description: 'Choose your ISO, calculate its SHA-256 locally and review filesystem and firmware constraints.' },
  { n: '04', title: 'Verify before writing', description: 'Review the safety preflight. Actual USB writing remains unavailable until independent real-device qualification passes.' },
];

const faq = [
  { q: 'Can BootNexa write a bootable USB today?', a: 'Not yet. The browser workspace supports image inspection, hashing, drive discovery and read-only preflight. Physical USB writing is intentionally disabled pending hardware safety and boot-validation tests.' },
  { q: 'Does my ISO get uploaded to your servers?', a: 'No. The existing browser image inspector hashes local file bytes in your browser. The native agent is intended to operate on your own computer. We do not offer a cloud ISO upload service.' },
  { q: 'Which operating system is supported?', a: 'The current native agent integration targets Windows for read-only USB-device discovery. Other platforms and real USB writing are not yet production-qualified.' },
  { q: 'Where can I download the agent?', a: 'The signed installer release is not publicly confirmed. The guided app links to the release channel and clearly marks installer availability rather than offering an unverified download.' },
];

function ProductPreview() {
  return <div className="mk-product" aria-label="Illustration of BootNexa's read-only preparation workspace">
    <div className="mk-product-glow" />
    <div className="mk-product-top"><div className="mk-product-brand"><span className="mk-product-brandmark"><Disc3 size={15}/></span> bootnexa <span className="mk-preview-chip">INTERACTIVE PREVIEW</span></div><div className="mk-window-dots"><i/><i/><i/></div></div>
    <div className="mk-product-body">
      <div className="mk-product-kicker">NEW PREPARATION</div>
      <div className="mk-product-heading">Make every step count.</div>
      <div className="mk-progress-dots"><span className="mk-dot-active">01 <small>Choose</small></span><span>02 <small>Inspect</small></span><span>03 <small>Review</small></span></div>
      <div className="mk-image-card"><div className="mk-image-symbol"><Disc3 size={25}/></div><div><strong>Windows installation image</strong><span>Local SHA-256 inspection</span></div><BadgeCheck size={18} className="mk-good"/></div>
      <div className="mk-drive-card"><div className="mk-drive-icon"><Usb size={21}/></div><div><strong>USB device discovery</strong><span>Agent approval required</span></div><span className="mk-readonly">READ ONLY</span></div>
      <div className="mk-product-foot"><ShieldCheck size={15}/> Writing is disabled until safety qualification is complete</div>
    </div>
    <div className="mk-floating"><span><Check size={15}/></span><div><strong>Clarity at every step</strong><small>Local-first. Consent-based.</small></div></div>
  </div>;
}

export default function Marketing() {
  const [menuOpen,setMenuOpen]=useState(false);
  const [activeFaq,setActiveFaq]=useState<number|null>(0);
  return <div className="mk">
    <a className="mk-skip" href="#main">Skip to main content</a>
    <header className="mk-header">
      <nav className="mk-nav" aria-label="Main navigation">
        <a href="/" className="mk-logo" aria-label="BootNexa home"><span className="mk-logo-symbol"><Disc3 size={20}/></span><span>boot<span className="mk-blue">nexa</span></span></a>
        <div className={'mk-nav-links '+(menuOpen?'mk-nav-open':'')}>
          <a href="#features" onClick={()=>setMenuOpen(false)}>Features</a>
          <a href="#how-it-works" onClick={()=>setMenuOpen(false)}>How it works</a>
          <a href="#safety" onClick={()=>setMenuOpen(false)}>Safety</a>
          <a href="#faq" onClick={()=>setMenuOpen(false)}>FAQ</a>
        </div>
        <a className="mk-nav-cta" href="/app">Open guided app <ArrowUpRight size={16}/></a>
        <button className="mk-menu-button" onClick={()=>setMenuOpen(v=>!v)} aria-expanded={menuOpen} aria-label={menuOpen?'Close menu':'Open menu'}>{menuOpen?<X size={22}/>:<Menu size={22}/>}</button>
      </nav>
    </header>
    <main id="main">
      <section className="mk-hero">
        <div className="mk-hero-copy">
          <div className="mk-eyebrow"><span className="mk-eyebrow-dot"/> Introducing a more thoughtful way to prepare USB media <span className="mk-eyebrow-arrow">↗</span></div>
          <h1>Bootable media.<br/><span>Without the</span><br/><em>guesswork.</em></h1>
          <p className="mk-hero-desc">From your first ISO to the final safety check, BootNexa brings image inspection, your local Windows agent and clear instructions into one beautifully simple workflow.</p>
          <div className="mk-hero-actions"><a className="mk-btn-primary" href="/app">Explore the guided app <ArrowRight size={18}/></a><a className="mk-btn-quiet" href="#how-it-works">See how it works <ChevronRight size={17}/></a></div>
          <div className="mk-hero-proof"><span><ShieldCheck size={17}/> Local-first image inspection</span><span><LockKeyhole size={17}/> Explicit device consent</span></div>
          <p className="mk-release-note"><span className="mk-release-dot"/> Pre-release preview. USB writing is not yet enabled.</p>
        </div>
        <ProductPreview/>
      </section>
      <div className="mk-trustbar"><span>BUILT FOR CLARITY AND CONTROL</span><div><span><Fingerprint size={18}/> SHA-256 verification</span><span><Monitor size={18}/> Windows local agent</span><span><HardDrive size={18}/> Read-only device discovery</span><span><ShieldCheck size={18}/> Safety-first defaults</span></div></div>
      <section id="features" className="mk-section mk-features">
        <div className="mk-section-head"><span className="mk-section-label">01 / THE WORKSPACE</span><h2>Less friction.<br/><em>More confidence.</em></h2><p>Everything you need to understand what you’re preparing—before a drive is ever modified.</p></div>
        <div className="mk-feature-grid">
          <article className="mk-feature mk-feature-primary"><div className="mk-feature-icon"><Disc3 size={23}/></div><div><span>IMAGE INTELLIGENCE</span><h3>Know your image<br/>before you begin.</h3><p>Inspect local ISO and disk-image structure, calculate a SHA-256 fingerprint and spot unsupported formats.</p></div><div className="mk-fingerprint"><div className="mk-fingerprint-label">SHA-256 <BadgeCheck size={16}/></div><div className="mk-hash-lines"><i/><i/><i/><i/><i/></div><div className="mk-fingerprint-foot"><span>LOCAL INSPECTION</span><span>NO IMAGE UPLOAD</span></div></div></article>
          <article className="mk-feature mk-feature-small"><div className="mk-feature-icon"><Usb size={23}/></div><span>DEVICE DISCOVERY</span><h3>Your drives.<br/>Your control.</h3><p>See eligible removable drives through a consent-based Windows companion, with read-only discovery and no implicit write permission.</p></article>
          <article className="mk-feature mk-feature-small"><div className="mk-feature-icon"><ShieldCheck size={23}/></div><span>SAFETY BY DESIGN</span><h3>Check twice.<br/>Trust evidence.</h3><p>Review source hashes, filesystem assumptions and target details. Unverified destructive actions stay unavailable.</p></article>
        </div>
      </section>
      <section id="how-it-works" className="mk-section mk-how"><div className="mk-section-head mk-how-head"><span className="mk-section-label">02 / YOUR JOURNEY</span><h2>A clear path from<br/><em>download to preparation.</em></h2><p>One guided experience. No mystery steps, no misleading completion screens.</p></div><div className="mk-steps">{steps.map(s=><article className="mk-journey-step" key={s.n}><span className="mk-step-num">{s.n}</span><div><h3>{s.title}</h3><p>{s.description}</p></div><ArrowUpRight size={20}/></article>)}</div><a href="/app" className="mk-inline-link">Start the guided experience <ArrowRight size={18}/></a></section>
      <section id="safety" className="mk-safety"><div className="mk-safety-icon"><LockKeyhole size={25}/></div><div className="mk-safety-copy"><span className="mk-section-label">03 / BUILT ON TRUST</span><h2>Your data stays yours.<br/>Your decisions stay yours.</h2><p>Local image inspection, explicit agent approval and no silent disk writes. The actual writing engine is still under real-device qualification, and we’ll say so until it is ready.</p><div className="mk-safety-tags"><span><Check size={14}/> Local ISO hashing</span><span><Check size={14}/> Read-only drive inventory</span><span><Check size={14}/> No misleading write button</span></div></div><div className="mk-safety-orbit"><div><ShieldCheck size={66}/></div></div></section>
      <section id="faq" className="mk-section mk-faq"><div className="mk-section-head"><span className="mk-section-label">04 / GOOD TO KNOW</span><h2>Questions, <em>answered.</em></h2></div><div className="mk-faq-list">{faq.map((item,i)=><div className="mk-faq-item" key={item.q}><button aria-expanded={activeFaq===i} onClick={()=>setActiveFaq(activeFaq===i?null:i)}><span>{item.q}</span><span className="mk-faq-toggle">{activeFaq===i?'−':'+'}</span></button>{activeFaq===i&&<p>{item.a}</p>}</div>)}</div></section>
      <section className="mk-final"><span className="mk-section-label">YOUR NEXT BOOT STARTS HERE</span><h2>Get prepared.<br/><em>Stay in control.</em></h2><p>Explore a better way to inspect your media, connect your local agent and understand every step.</p><a href="/app" className="mk-btn-primary">Open BootNexa <ArrowRight size={18}/></a><small>Pre-release · Physical USB writing is disabled</small></section>
    </main>
    <footer className="mk-footer"><a href="/" className="mk-logo"><span className="mk-logo-symbol"><Disc3 size={18}/></span><span>boot<span className="mk-blue">nexa</span></span></a><span>Made for more confident media preparation.</span><div><a href="/app">Guided app</a><a href="https://github.com/heidi-dang/bootnexa/releases" target="_blank" rel="noreferrer">Release channel <ArrowUpRight size={12}/></a></div><span>© {new Date().getFullYear()} BootNexa. Preview software.</span></footer>
  </div>;
}