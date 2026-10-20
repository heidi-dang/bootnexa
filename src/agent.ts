import { useCallback, useEffect, useState } from 'react';

const BASE = 'http://127.0.0.1:43627/v1';
export type Device = {
  id: string;
  model: string;
  capacityBytes: number;
  busType: string;
  partitionStyle: string;
  readOnly: boolean;
};
type Phase = 'searching' | 'offline' | 'approval' | 'connected' | 'denied' | 'unsupported' | 'error';
type Agent = { phase: Phase; message: string; devices: Device[]; platform?: string };

let token: string | null = null;
let inflight: Promise<Agent> | null = null;
const empty: Agent = { phase: 'searching', message: 'Searching for the local agent…', devices: [] };
async function fetchDevices(): Promise<Device[]> {
  if (!token) throw new Error('Not approved');
  const res = await fetch(`${BASE}/devices`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: 'no-store',
    signal: AbortSignal.timeout(10000),
  });
  if (res.status === 401) { token = null; throw new Error('Session expired — reconnect to approve access.'); }
  if (!res.ok) throw new Error(`Device discovery unavailable (HTTP ${res.status}).`);
  const json = await res.json() as { devices: Device[] };
  return json.devices;
}
async function discover(onPhase: (phase: Agent) => void): Promise<Agent> {
  let response: Response;
  try {
    response = await fetch(`${BASE}/health`, { cache: 'no-store', signal: AbortSignal.timeout(2500) });
    if (!response.ok) throw new Error('Unreachable');
  } catch {
    return { phase: 'offline', message: 'Install and run BootNexa Agent to discover USB devices.', devices: [] };
  }
  let health: { platform: string; protocolVersion: string };
  try { health = await response.json(); }
  catch { return { phase: 'error', message: 'Unexpected agent response.', devices: [] }; }
  if (health.protocolVersion !== '0.2') return { phase: 'error', message: 'Agent version mismatch. Update BootNexa Agent.', devices: [] };
  if (health.platform !== 'windows') return { phase: 'unsupported', platform: health.platform, message: 'The read-only disk inventory currently requires Windows.', devices: [] };
  if (!token) {
    onPhase({ phase: 'approval', message: 'Approve read-only USB access in the Windows prompt.', devices: [], platform: health.platform });
    try {
      const request = await fetch(`${BASE}/access/request`, { method: 'POST', cache: 'no-store' });
      if (request.status === 403 || request.status === 429) return { phase: 'denied', message: 'Access was denied. You can request approval again.', devices: [] };
      if (!request.ok) return { phase: 'error', message: `Could not request access (HTTP ${request.status}).`, devices: [] };
      const grant = await request.json() as { token: string; scope: string };
      if (grant.scope !== 'devices:read' || !/^[a-f0-9]{64}$/.test(grant.token)) throw new Error('Invalid agent grant');
      token = grant.token;
    } catch {
      return { phase: 'error', message: 'Local approval could not be completed. Check the agent and browser permissions.', devices: [] };
    }
  }
  try {
    const devices = await fetchDevices();
    return { phase: 'connected', message: 'Read-only USB device discovery approved.', devices, platform: health.platform };
  } catch (error) {
    return { phase: 'error', message: error instanceof Error ? error.message : 'Device discovery failed.', devices: [] };
  }
}
export function useAgent() {
  const [agent, setAgent] = useState<Agent>(empty);
  const connect = useCallback(() => {
    if (!inflight) inflight = discover(setAgent).finally(() => { inflight = null; });
    return inflight.then(setAgent);
  }, []);
  useEffect(() => {
    void connect();
  }, [connect]);
  useEffect(() => {
    // Discover an agent started after the webpage. Do not repeatedly prompt
    // after the user explicitly denied access or revoked a grant.
    if (agent.phase !== 'offline') return;
    const handle = setInterval(() => { void connect(); }, 5000);
    return () => clearInterval(handle);
  }, [agent.phase, connect]);
  const refresh = useCallback(async () => {
    if (!token) { await connect(); return; }
    try { const devices = await fetchDevices(); setAgent(old => ({ ...old, devices, phase: 'connected', message: 'Drive list refreshed.' })); }
    catch (e) { setAgent(old => ({ ...old, phase: 'error', message: e instanceof Error ? e.message : 'Discovery failed', devices: [] })); }
  }, [connect]);
  const revoke = useCallback(async () => {
    if (token) {
      const previous = token;
      token = null;
      try {
        const response = await fetch(`${BASE}/access/revoke`, { method: 'POST', headers: { Authorization: `Bearer ${previous}` }, signal: AbortSignal.timeout(3000) });
        if (!response.ok) throw new Error('Revocation failed');
        setAgent({ phase: 'denied', message: 'Device access has been revoked.', devices: [] });
      } catch {
        setAgent({ phase: 'error', message: 'Local session cleared, but agent revocation was not confirmed. Restart the agent to revoke all sessions.', devices: [] });
      }
    }
  }, []);
  return { agent, connect, refresh, revoke };
}
