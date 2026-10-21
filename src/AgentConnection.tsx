import { ArrowRight, CheckCircle2, HardDrive, LockKeyhole, RefreshCw, ShieldAlert, Usb } from 'lucide-react';
import type { useAgent } from './agent';
type AgentApi = ReturnType<typeof useAgent>;

export function AgentConnection({ api }: { api: AgentApi }) {
  const { agent, connect, revoke } = api;
  const connected = agent.phase === 'connected';
  return <div className="agent-status" aria-live="polite">
    <div className="status-row"><span className={'status-dot ' + (connected ? 'connected-dot' : agent.phase === 'approval' ? 'amber' : 'offline')}/><strong>{connected ? 'Agent connected' : agent.phase === 'searching' ? 'Finding local agent' : agent.phase === 'approval' ? 'Approval requested' : agent.phase === 'denied' ? 'Access not authorised' : agent.phase === 'unsupported' ? 'Unsupported platform' : 'Agent not connected'}</strong></div>
    <p>{agent.message}</p>
    {agent.phase === 'denied' || agent.phase === 'offline' || agent.phase === 'error' ?
      <button className="agent-link" type="button" onClick={() => void connect()}><ArrowRight size={14}/> {agent.phase === 'denied' ? 'Request approval' : 'Retry connection'}</button> : null}
    {connected ? <button className="agent-link" type="button" onClick={() => void revoke()}><LockKeyhole size={14}/> Revoke access</button> : null}
  </div>;
}

export function DiscoveredDevices({ api, selectedId, onSelect }: { api: AgentApi; selectedId: string | null; onSelect: (id: string) => void }) {
  const { agent, refresh, connect } = api;
  if (agent.phase !== 'connected') {
    return <div className="empty-device"><div className="empty-icon"><Usb size={22}/></div><div><strong>{agent.phase === 'approval' ? 'Waiting for your approval' : 'No USB drives available'}</strong><span>{agent.message}</span></div><span className="device-badge">{agent.phase === 'approval' ? 'CONSENT' : 'OFFLINE'}</span></div>;
  }
  return <div className="discovery">
    <div className="device-toolbar"><span><CheckCircle2 size={15}/> Read-only device inventory</span><button type="button" onClick={() => void refresh()}><RefreshCw size={14}/> Refresh</button></div>
    {agent.devices.length ? agent.devices.map(d => <label className={"device-found device-choice " + (selectedId === d.id ? "chosen-device" : "")} key={d.id}><input type="radio" name="preview-target" aria-label={"Compare image with " + d.model} checked={selectedId === d.id} onChange={() => onSelect(d.id)}/>
      <div className="empty-icon"><HardDrive size={20}/></div>
      <div><strong>{d.model}</strong><span>{(d.capacityBytes / 1073741824).toFixed(1)} GiB · {d.busType} · {d.partitionStyle}{d.readOnly ? ' · Write-protected' : ''}</span></div>
      <span className="device-badge">VIEW ONLY</span>
    </label>) : <div className="empty-device"><div className="empty-icon"><Usb size={22}/></div><div><strong>No eligible USB drives detected</strong><span>Insert a removable USB drive and refresh the list.</span></div></div>}
    <div className="notice"><ShieldAlert size={15}/> This selection is for read-only image comparison. It never authorises disk writing.</div>
    <button className="visually-hidden" type="button" onClick={() => void connect()}>Reconnect</button>
  </div>;
}
