import { useEffect, useRef, useState } from 'react';
import { api } from '../services/api';
import type { AnalysisResult } from '../types';

export type Tab = 'URL' | 'MESSAGE' | 'QR' | 'DOCUMENT';

export const TABS: Tab[] = ['URL', 'MESSAGE', 'QR', 'DOCUMENT'];
const TAB_LABELS: Record<Tab, string> = { URL: 'URL', MESSAGE: 'MESSAGE', QR: 'QR', DOCUMENT: 'DOC' };

/** Pipeline steps shown while an analysis is in flight (PRD §22). */
export const PIPELINE_STEPS: Record<Tab, string[]> = {
  URL: ['VALIDATING INPUT', 'EXTRACTING SIGNALS', 'CHECKING THREAT INTELLIGENCE', 'RUNNING ANALYSIS', 'BUILDING EVIDENCE', 'CALCULATING ASSESSMENT'],
  MESSAGE: ['VALIDATING INPUT', 'EXTRACTING LANGUAGE SIGNALS', 'ROUTING EMBEDDED URLS', 'CHECKING THREAT INTELLIGENCE', 'RUNNING ML SIGNAL', 'CALCULATING ASSESSMENT'],
  QR: ['UPLOADING IMAGE', 'DECODING PAYLOAD', 'ROUTING PAYLOAD', 'CHECKING THREAT INTELLIGENCE', 'BUILDING EVIDENCE', 'CALCULATING ASSESSMENT'],
  DOCUMENT: ['UPLOADING FILE', 'COMPUTING SHA-256', 'COMPARING REFERENCE', 'BUILDING EVIDENCE', 'CALCULATING ASSESSMENT'],
};

export function PipelineProgress({ tab }: { tab: Tab }) {
  const steps = PIPELINE_STEPS[tab];
  const [done, setDone] = useState(0);
  useEffect(() => {
    setDone(0);
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) return;
    const t = window.setInterval(() => setDone((d) => Math.min(d + 1, steps.length - 1)), 900);
    return () => window.clearInterval(t);
  }, [tab, steps.length]);
  return (
    <div className="surface-raised rounded-lg p-4" role="status" aria-live="polite" aria-label="Analysis in progress">
      <ol className="space-y-2 text-xs font-mono">
        {steps.map((s, i) => (
          <li key={s} className="flex items-center gap-2.5">
            <span aria-hidden="true" className={i < done ? 'text-emerald-400' : i === done ? 'text-amber-300' : 'text-mist-500'}>
              {i < done ? '✓' : i === done ? '◌' : '○'}
            </span>
            <span className={i <= done ? 'text-mist-100' : 'text-mist-500'}>{s}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

interface FormProps {
  onResult: (r: AnalysisResult) => void;
  onBusy: (busy: boolean) => void;
}

function useBusy(onBusy: (busy: boolean) => void) {
  const [busy, setBusyState] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const setBusy = (b: boolean) => {
    setBusyState(b);
    onBusy(b);
  };
  return { busy, setBusy, error, setError };
}

const inputCls =
  'w-full bg-ink-950 border border-white/10 rounded-lg px-3.5 py-2.5 text-sm text-mist-100 placeholder:text-mist-500 focus:border-white/25 outline-none';
const btnCls =
  'inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-md bg-mist-100 text-ink-950 text-sm font-semibold hover:bg-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed min-h-[44px]';
const errCls = 'text-sm text-red-300 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2';
const hintCls = 'text-xs text-mist-500';

export function UrlForm({ onResult, onBusy }: FormProps) {
  const [url, setUrl] = useState('');
  const { busy, setBusy, error, setError } = useBusy(onBusy);
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault(); setError(null); setBusy(true);
        try { onResult(await api.analyzeUrl(url.trim())); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
      }}
      className="space-y-3"
    >
      <label htmlFor="ts-url" className="block text-xs font-mono tracking-widest text-mist-300">PASTE A URL</label>
      <input
        id="ts-url" value={url} onChange={(e) => setUrl(e.target.value)}
        placeholder="https://example.com/..." inputMode="url" autoComplete="off" spellCheck={false}
        aria-describedby="ts-url-help" className={`${inputCls} font-mono`}
      />
      <p id="ts-url-help" className={hintCls}>
        Example: <button type="button" className="underline hover:text-mist-300" onClick={() => setUrl('https://example.com/login')}>https://example.com/login</button>
      </p>
      <button disabled={busy || !url.trim()} className={btnCls}>
        {busy ? 'Analyzing…' : <>Analyze URL <span aria-hidden="true">→</span></>}
      </button>
      {error && <p role="alert" className={errCls}>{error}</p>}
    </form>
  );
}

export function MessageForm({ onResult, onBusy }: FormProps) {
  const [text, setText] = useState('');
  const { busy, setBusy, error, setError } = useBusy(onBusy);
  const urls = (text.match(/https?:\/\/[^\s)>\]]+/g) || []).slice(0, 5);
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault(); setError(null); setBusy(true);
        try { onResult(await api.analyzeMessage(text)); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
      }}
      className="space-y-3"
    >
      <label htmlFor="ts-msg" className="block text-xs font-mono tracking-widest text-mist-300">PASTE SUSPICIOUS MESSAGE</label>
      <textarea
        id="ts-msg" value={text} onChange={(e) => setText(e.target.value)} rows={6}
        placeholder="Paste the full message text…" spellCheck={false} className={`${inputCls} resize-y min-h-[140px]`}
      />
      {urls.length > 0 && (
        <p className={hintCls} aria-live="polite">
          {urls.length} URL{urls.length > 1 ? 's' : ''} detected — {urls.length > 1 ? 'they' : 'it'} will be routed through URL analysis:{' '}
          <span className="font-mono text-mist-300 break-all">{urls[0]}</span>
        </p>
      )}
      <button disabled={busy || !text.trim()} className={btnCls}>
        {busy ? 'Analyzing…' : <>Analyze message <span aria-hidden="true">→</span></>}
      </button>
      {error && <p role="alert" className={errCls}>{error}</p>}
    </form>
  );
}

export function QrForm({ onResult, onBusy }: FormProps) {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const { busy, setBusy, error, setError } = useBusy(onBusy);
  const objUrl = useRef<string | null>(null);
  useEffect(() => () => { if (objUrl.current) URL.revokeObjectURL(objUrl.current); }, []);
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault(); if (!file) return; setError(null); setBusy(true);
        try { onResult(await api.analyzeQr(file)); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
      }}
      className="space-y-3"
    >
      <span id="ts-qr-label" className="block text-xs font-mono tracking-widest text-mist-300">UPLOAD QR IMAGE · PNG / JPG / WEBP</span>
      <div className="border border-dashed border-white/15 rounded-lg p-6 text-center" role="group" aria-labelledby="ts-qr-label">
        {preview ? (
          <img src={preview} alt="Selected QR code preview" className="mx-auto max-h-44 rounded" />
        ) : (
          <p className="text-sm text-mist-500">Upload a QR image with the complete code visible.</p>
        )}
        <label className="mt-4 inline-flex cursor-pointer px-5 py-2.5 rounded-md border border-white/15 text-sm font-semibold hover:bg-white/5 transition-colors min-h-[44px] items-center">
          Choose file
          <input
            type="file" accept="image/png,image/jpeg,image/webp" className="sr-only"
            onChange={(e) => {
              const f = e.target.files?.[0] ?? null;
              setFile(f);
              if (objUrl.current) URL.revokeObjectURL(objUrl.current);
              objUrl.current = f ? URL.createObjectURL(f) : null;
              setPreview(objUrl.current);
            }}
          />
        </label>
        {file && <p className="mt-2 text-xs text-mist-300 font-mono break-all">{file.name}</p>}
      </div>
      <button disabled={busy || !file} className={btnCls}>
        {busy ? 'Decoding…' : <>Analyze payload <span aria-hidden="true">→</span></>}
      </button>
      {error && <p role="alert" className={errCls}>{error}</p>}
    </form>
  );
}

export function DocumentForm({ onResult, onBusy }: FormProps) {
  const [file, setFile] = useState<File | null>(null);
  const [ref, setRef] = useState('');
  const { busy, setBusy, error, setError } = useBusy(onBusy);
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault(); if (!file) return; setError(null); setBusy(true);
        try { onResult(await api.analyzeDocument(file, ref.trim() || undefined)); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
      }}
      className="space-y-3"
    >
      <span id="ts-doc-label" className="block text-xs font-mono tracking-widest text-mist-300">UPLOAD DOCUMENT · PDF / PNG / JPG / TXT / CSV / DOCX / ZIP · ≤10 MB</span>
      <label className="flex cursor-pointer items-center justify-center gap-2 border border-dashed border-white/15 rounded-lg p-5 text-sm hover:bg-white/5 transition-colors min-h-[44px]" aria-labelledby="ts-doc-label">
        {file ? <span className="font-mono text-xs break-all">{file.name}</span> : <span className="text-mist-500">Choose file</span>}
        <input type="file" className="sr-only" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
      </label>
      <label htmlFor="ts-sha" className="block text-xs font-mono tracking-widest text-mist-300">OPTIONAL REFERENCE SHA-256</label>
      <input
        id="ts-sha" value={ref} onChange={(e) => setRef(e.target.value)}
        placeholder="e3b0c44…" spellCheck={false} autoComplete="off" className={`${inputCls} font-mono`}
      />
      <button disabled={busy || !file} className={btnCls}>
        {busy ? 'Hashing…' : <>Verify integrity <span aria-hidden="true">→</span></>}
      </button>
      {error && <p role="alert" className={errCls}>{error}</p>}
      <p className={hintCls}>Integrity match ≠ issuer authenticity. A hash only proves the file is unchanged versus the reference.</p>
    </form>
  );
}

export function InputSelector({ tab, setTab }: { tab: Tab; setTab: (t: Tab) => void }) {
  const listRef = useRef<HTMLDivElement>(null);
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    e.preventDefault();
    const i = TABS.indexOf(tab);
    const next = TABS[(i + (e.key === 'ArrowRight' ? 1 : TABS.length - 1)) % TABS.length];
    setTab(next);
    listRef.current?.querySelector<HTMLButtonElement>(`[data-tab="${next}"]`)?.focus();
  };
  return (
    <div ref={listRef} role="tablist" aria-label="Analyzer input type" onKeyDown={onKeyDown} className="flex gap-1.5 flex-wrap">
      {TABS.map((t) => (
        <button
          key={t} role="tab" data-tab={t} aria-selected={tab === t} aria-controls={`panel-${t}`} id={`tab-${t}`}
          onClick={() => setTab(t)}
          className={`px-4 py-2 rounded-md text-xs font-mono font-semibold tracking-wider border min-h-[40px] transition-colors ${
            tab === t
              ? 'bg-mist-100 text-ink-950 border-mist-100'
              : 'bg-transparent text-mist-300 border-white/10 hover:border-white/25 hover:text-mist-100'
          }`}
        >
          {TAB_LABELS[t]}
        </button>
      ))}
    </div>
  );
}
