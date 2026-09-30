import { useState } from 'react';
import { api } from '../services/api';
import type { AnalysisResult } from '../types';

export type Tab = 'URL' | 'MESSAGE' | 'QR' | 'DOCUMENT';

export function InputSelector({ tab, setTab }: { tab: Tab; setTab: (t: Tab) => void }) {
  const tabs: Tab[] = ['URL', 'MESSAGE', 'QR', 'DOCUMENT'];
  const labels: Record<Tab, string> = { URL: 'Analyze URL', MESSAGE: 'Analyze Message', QR: 'Analyze QR', DOCUMENT: 'Analyze Document' };
  return (
    <div className="flex gap-2 flex-wrap">
      {tabs.map((t) => (
        <button key={t} onClick={() => setTab(t)}
          className={`px-4 py-2 rounded-lg text-sm font-medium border ${tab === t ? 'bg-shield-600 text-white border-shield-600' : 'bg-white text-slate-700 border-slate-300 hover:border-shield-500'}`}>
          {labels[t]}
        </button>
      ))}
    </div>
  );
}

function useBusy() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return { busy, setBusy, error, setError };
}

export function UrlForm({ onResult }: { onResult: (r: AnalysisResult) => void }) {
  const [url, setUrl] = useState('');
  const { busy, setBusy, error, setError } = useBusy();
  return (
    <form onSubmit={async (e) => {
      e.preventDefault(); setError(null); setBusy(true);
      try { onResult(await api.analyzeUrl(url)); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
    }} className="space-y-3">
      <label className="block text-sm font-medium">URL to verify</label>
      <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/some/path"
        className="w-full border rounded-lg px-3 py-2 text-sm" />
      <button disabled={busy || !url.trim()} className="px-4 py-2 rounded-lg bg-shield-600 text-white text-sm disabled:opacity-50">
        {busy ? 'Analyzing…' : 'Verify URL'}
      </button>
      {error && <p className="text-sm text-red-600">{error}</p>}
    </form>
  );
}

export function MessageForm({ onResult }: { onResult: (r: AnalysisResult) => void }) {
  const [text, setText] = useState('');
  const { busy, setBusy, error, setError } = useBusy();
  return (
    <form onSubmit={async (e) => {
      e.preventDefault(); setError(null); setBusy(true);
      try { onResult(await api.analyzeMessage(text)); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
    }} className="space-y-3">
      <label className="block text-sm font-medium">Paste suspicious message</label>
      <textarea value={text} onChange={(e) => setText(e.target.value)} rows={6}
        placeholder="Your account will be blocked… verify at http://…"
        className="w-full border rounded-lg px-3 py-2 text-sm" />
      <button disabled={busy || !text.trim()} className="px-4 py-2 rounded-lg bg-shield-600 text-white text-sm disabled:opacity-50">
        {busy ? 'Analyzing…' : 'Verify message'}
      </button>
      {error && <p className="text-sm text-red-600">{error}</p>}
    </form>
  );
}

export function QrForm({ onResult }: { onResult: (r: AnalysisResult) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const { busy, setBusy, error, setError } = useBusy();
  return (
    <form onSubmit={async (e) => {
      e.preventDefault(); if (!file) return; setError(null); setBusy(true);
      try { onResult(await api.analyzeQr(file)); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
    }} className="space-y-3">
      <label className="block text-sm font-medium">Upload QR image (png/jpg/webp)</label>
      <input type="file" accept="image/*" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" />
      <button disabled={busy || !file} className="px-4 py-2 rounded-lg bg-shield-600 text-white text-sm disabled:opacity-50">
        {busy ? 'Decoding…' : 'Decode & verify'}
      </button>
      {error && <p className="text-sm text-red-600">{error}</p>}
    </form>
  );
}

export function DocumentForm({ onResult }: { onResult: (r: AnalysisResult) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [ref, setRef] = useState('');
  const { busy, setBusy, error, setError } = useBusy();
  return (
    <form onSubmit={async (e) => {
      e.preventDefault(); if (!file) return; setError(null); setBusy(true);
      try { onResult(await api.analyzeDocument(file, ref.trim() || undefined)); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
    }} className="space-y-3">
      <label className="block text-sm font-medium">Upload document (pdf/png/jpg/txt/csv/docx/zip, ≤10 MB)</label>
      <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" />
      <label className="block text-sm font-medium">Reference SHA-256 (optional, for tamper check)</label>
      <input value={ref} onChange={(e) => setRef(e.target.value)} placeholder="e3b0c44…" className="w-full border rounded-lg px-3 py-2 text-sm font-mono" />
      <button disabled={busy || !file} className="px-4 py-2 rounded-lg bg-shield-600 text-white text-sm disabled:opacity-50">
        {busy ? 'Hashing…' : 'Check integrity'}
      </button>
      {error && <p className="text-sm text-red-600">{error}</p>}
      <p className="text-xs text-slate-500">Integrity match ≠ issuer authenticity. Hash only proves the file is unchanged vs the reference.</p>
    </form>
  );
}
