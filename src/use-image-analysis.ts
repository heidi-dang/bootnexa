import { useEffect, useRef, useState } from 'react';
import type { ImageResult, AnalysisEvent } from './image-worker';

export type AnalysisState = {
  file: File | null;
  status: 'idle' | 'working' | 'complete' | 'failed' | 'cancelled';
  progress: number;
  result: ImageResult | null;
  error: string;
};
const empty: AnalysisState = { file: null, status: 'idle', progress: 0, result: null, error: '' };

export function useImageAnalysis(file: File | null) {
  const [state, setState] = useState<AnalysisState>(empty);
  const [attempt, setAttempt] = useState(0);
  const active = useRef<Worker | null>(null);
  useEffect(() => {
    if (!file) { setState(empty); return; }
    const worker = new Worker(new URL('./image-worker.ts', import.meta.url), { type: 'module' });
    active.current = worker;
    const id = attempt + 1;
    setState({ file, status: 'working', progress: 0, result: null, error: '' });
    worker.onmessage = (event: MessageEvent<AnalysisEvent>) => {
      const message = event.data;
      if (message.id !== id || active.current !== worker) return;
      if (message.type === 'progress') {
        setState(old => old.file === file ? { ...old, progress: message.total ? message.done / message.total : 0 } : old);
      } else if (message.type === 'result') {
        setState({ file, status: 'complete', progress: 1, result: message.result, error: '' });
        worker.terminate();
        if (active.current === worker) active.current = null;
      } else {
        setState({ file, status: 'failed', progress: 0, result: null, error: message.message });
        worker.terminate();
        if (active.current === worker) active.current = null;
      }
    };
    worker.onerror = () => {
      if (active.current !== worker) return;
      setState({ file, status: 'failed', progress: 0, result: null, error: 'Image analysis worker failed.' });
      worker.terminate();
      if (active.current === worker) active.current = null;
    };
    worker.postMessage({ type: 'analyze', id, file });
    return () => {
      worker.terminate();
      if (active.current === worker) active.current = null;
    };
  }, [file, attempt]);
  const cancel = () => {
    active.current?.terminate();
    active.current = null;
    setState({ file, status: 'cancelled', progress: 0, result: null, error: '' });
    // Explicit cancellation must not be undone by auto-restarting the effect.
  };
  const retry = () => setAttempt(a => a + 1);
  return { analysis: state.file === file ? state : { ...empty, file, status: file ? 'working' as const : 'idle' as const }, cancel, retry };
}
