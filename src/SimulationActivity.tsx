import { useCallback, useEffect, useState } from 'react';
import { Clock3, RefreshCw, ShieldCheck } from 'lucide-react';
import { loadSimulationJobs, type SimulatedJob } from './agent';

export function SimulationActivity({ connected }: { connected: boolean }) {
  const [jobs, setJobs] = useState<SimulatedJob[]>([]);
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(false);
  const refresh = useCallback(async () => {
    if (!connected) { setJobs([]); setStatus('Connect the read-only Windows agent to view local simulation history.'); return; }
    setLoading(true);
    try { setJobs(await loadSimulationJobs()); setStatus('Showing local simulation history only.'); }
    catch (error) { setJobs([]); setStatus(error instanceof Error ? error.message : 'History unavailable.'); }
    finally { setLoading(false); }
  }, [connected]);
  useEffect(() => { void refresh(); }, [refresh]);
  return <section className="activity-page" aria-label="Simulation activity">
    <div className="eyebrow"><Clock3 size={14}/> BOOTNEXA ACTIVITY</div>
    <h1>Simulation activity</h1>
    <p>Review local, read-only virtual media jobs. No physical USB operation can be initiated here.</p>
    <div className="activity-controls"><span><ShieldCheck size={17}/> SIMULATION ONLY · NO DISK ACCESS</span>
      <button type="button" onClick={() => { void refresh(); }} disabled={loading}><RefreshCw size={15}/> Refresh history</button></div>
    <p role="status" className="activity-status">{loading ? 'Loading local history…' : status}</p>
    <div className="activity-jobs">
      {jobs.length === 0 && !loading && <p>No simulation records available.</p>}
      {jobs.map(job => <article className="activity-job" key={job.id} data-testid="simulation-job">
        <div><strong>{job.phase.replaceAll('_',' ')}</strong><span>Virtual job {job.id.slice(0,8)}</span></div>
        <div><span>Progress</span><strong>{job.completedBytes.toLocaleString()} / {job.expectedBytes.toLocaleString()} bytes</strong></div>
        <div><span>Verified</span><strong>{job.verifiedBytes.toLocaleString()} bytes</strong></div>
        <div><span>Result</span><strong>{job.failureCode || (job.flushSimulated ? 'Simulated flush recorded' : 'Pending')}</strong></div>
        <small>{new Date(job.updatedAtMs).toLocaleString()} · This is not evidence of a physical USB write.</small>
      </article>)}
    </div>
  </section>;
}
