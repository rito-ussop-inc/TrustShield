import { useEffect, useRef } from 'react';

/**
 * Cinematic scroll-driven hero (PRD §10–15).
 * Uses a tall wrapper + sticky stage (no body scroll-lock), rAF-smoothed
 * progress written directly to DOM refs (no React re-renders per frame).
 * Reduced-motion users get a static hero with identical content.
 */

interface Stage {
  start: number;
  end: number;
}

const STAGES: Stage[] = [
  { start: 0.0, end: 0.22 }, // TRUSTSHIELD
  { start: 0.2, end: 0.42 }, // assumed
  { start: 0.4, end: 0.62 }, // tested
  { start: 0.6, end: 0.8 }, // input types
  { start: 0.78, end: 0.93 }, // pipeline
  { start: 0.91, end: 1.01 }, // verdict + CTA
];

function stageAlpha(s: number, { start, end }: Stage): number {
  const fade = 0.05;
  if (s < start || s > end) return 0;
  const inA = Math.min(1, (s - start) / fade);
  const outA = Math.min(1, (end - s) / fade);
  const a = Math.min(inA, outA);
  return a * a * (3 - 2 * a); // smoothstep
}

function useStaticHero(): boolean {
  return (
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

function PipelineDiagram() {
  return (
    <div aria-hidden="true" className="flex items-center justify-center gap-1.5 sm:gap-3 text-[10px] sm:text-xs font-mono text-mist-300 flex-wrap">
      {['DIGITAL INPUT', 'SIGNALS', 'EVIDENCE', 'TRUST ASSESSMENT'].map((t, i) => (
        <span key={t} className="flex items-center gap-1.5 sm:gap-3">
          <span className="px-2.5 py-1.5 rounded border border-white/15 bg-white/5">{t}</span>
          {i < 3 && <span className="text-mist-500">↓</span>}
        </span>
      ))}
    </div>
  );
}

export function TrustShieldHero() {
  const wrapRef = useRef<HTMLDivElement>(null);
  const stageRefs = useRef<Array<HTMLDivElement | null>>([]);
  const bgRef = useRef<HTMLDivElement>(null);
  const barRef = useRef<HTMLDivElement>(null);
  const hintRef = useRef<HTMLDivElement>(null);
  const staticMode = useStaticHero();

  useEffect(() => {
    if (staticMode) return;
    const wrap = wrapRef.current;
    if (!wrap) return;
    let raf = 0;
    let target = 0;
    let smooth = 0;
    let disposed = false;

    const measure = () => {
      const r = wrap.getBoundingClientRect();
      const total = r.height - window.innerHeight;
      target = total <= 0 ? 1 : Math.min(1, Math.max(0, -r.top / total));
    };

    const frame = () => {
      if (disposed) return;
      smooth += (target - smooth) * 0.12;
      if (Math.abs(target - smooth) < 0.0005) smooth = target;
      const s = smooth;
      stageRefs.current.forEach((el, i) => {
        if (!el) return;
        const a = stageAlpha(s, STAGES[i]);
        el.style.opacity = a.toFixed(3);
        el.style.transform = `translateY(${(22 * (1 - a)).toFixed(1)}px) scale(${(0.97 + 0.03 * a).toFixed(3)})`;
        el.style.filter = a > 0.01 ? `blur(${((1 - a) * 10).toFixed(1)}px)` : 'none';
        el.style.visibility = a <= 0.001 ? 'hidden' : 'visible';
        el.setAttribute('aria-hidden', a < 0.5 ? 'true' : 'false');
      });
      if (bgRef.current) {
        bgRef.current.style.opacity = (0.55 + s * 0.45).toFixed(3);
        bgRef.current.style.transform = `scale(${(1 + s * 0.08).toFixed(3)})`;
      }
      if (barRef.current) barRef.current.style.transform = `scaleX(${s.toFixed(3)})`;
      if (hintRef.current) hintRef.current.style.opacity = s < 0.04 ? '1' : '0';
      raf = requestAnimationFrame(frame);
    };

    measure();
    raf = requestAnimationFrame(frame);
    window.addEventListener('scroll', measure, { passive: true });
    window.addEventListener('resize', measure);
    return () => {
      disposed = true;
      cancelAnimationFrame(raf);
      window.removeEventListener('scroll', measure);
      window.removeEventListener('resize', measure);
    };
  }, [staticMode]);

  if (staticMode) {
    return (
      <section aria-label="TrustShield introduction" className="relative min-h-[100dvh] flex items-center justify-center text-center px-4">
        <div className="max-w-3xl space-y-6 pt-14">
          <h1 className="text-6xl sm:text-7xl font-extrabold tracking-tighter">TRUSTSHIELD</h1>
          <p className="tracking-[0.3em] text-sm text-mist-300">VERIFY BEFORE YOU TRUST.</p>
          <p className="text-mist-300 max-w-xl mx-auto">Analyze digital inputs. See the evidence. Make an informed decision.</p>
          <a href="#analyze" className="inline-flex items-center gap-2 bg-mist-100 text-ink-950 font-semibold px-6 py-3 rounded-md">
            Analyze an input <span aria-hidden="true">→</span>
          </a>
        </div>
      </section>
    );
  }

  return (
    <div ref={wrapRef} className="relative" style={{ height: '460vh' }} aria-label="TrustShield introduction">
      <div className="sticky top-0 h-[100dvh] overflow-hidden flex items-center justify-center">
        {/* Restrained abstract backdrop: grid + pipeline trace */}
        <div ref={bgRef} aria-hidden="true" className="absolute inset-0 hero-stage">
          <svg className="absolute inset-0 w-full h-full opacity-[0.16]" preserveAspectRatio="xMidYMid slice" viewBox="0 0 1200 800">
            <defs>
              <pattern id="ts-grid" width="48" height="48" patternUnits="userSpaceOnUse">
                <path d="M48 0H0v48" fill="none" stroke="rgba(255,255,255,0.35)" strokeWidth="1" />
              </pattern>
            </defs>
            <rect width="1200" height="800" fill="url(#ts-grid)" />
            <g stroke="rgba(148,163,184,0.5)" strokeWidth="1.5" fill="none">
              <path d="M200 640 C 400 560, 420 420, 600 400 S 800 360, 1000 180" />
              <path d="M200 640 C 380 600, 500 520, 640 520 S 840 480, 1000 180" opacity="0.45" />
            </g>
            <g fill="rgba(242,244,248,0.75)">
              <circle cx="200" cy="640" r="5" />
              <circle cx="600" cy="400" r="5" />
              <circle cx="1000" cy="180" r="6" />
            </g>
            <g fontFamily="monospace" fontSize="20" fill="rgba(155,164,178,0.9)">
              <text x="216" y="646">INPUT</text>
              <text x="616" y="406">EVIDENCE</text>
              <text x="890" y="160">ASSESSMENT</text>
            </g>
          </svg>
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,transparent_35%,#05070D_78%)]" />
        </div>

        {/* Stages share one centered slot */}
        <div className="relative z-10 w-full max-w-4xl px-4 text-center flex items-center justify-center min-h-[60vh]">
          <div ref={(el) => { stageRefs.current[0] = el; }} className="hero-stage absolute inset-x-0 px-4" style={{ opacity: 1 }}>
            <h1 className="text-7xl sm:text-8xl font-extrabold tracking-tighter">TRUSTSHIELD</h1>
            <p className="mt-5 tracking-[0.35em] text-xs sm:text-sm text-mist-300">VERIFY BEFORE YOU TRUST.</p>
          </div>

          <div ref={(el) => { stageRefs.current[1] = el; }} className="hero-stage absolute inset-x-0 px-4" style={{ opacity: 0 }}>
            <p className="text-4xl sm:text-6xl font-extrabold tracking-tight leading-tight">DIGITAL TRUST<br />IS OFTEN ASSUMED.</p>
          </div>

          <div ref={(el) => { stageRefs.current[2] = el; }} className="hero-stage absolute inset-x-0 px-4" style={{ opacity: 0 }}>
            <p className="text-4xl sm:text-6xl font-extrabold tracking-tight leading-tight">BUT TRUST<br />CAN BE TESTED.</p>
          </div>

          <div ref={(el) => { stageRefs.current[3] = el; }} className="hero-stage absolute inset-x-0 px-4" style={{ opacity: 0 }}>
            <p className="text-xs tracking-[0.3em] text-mist-300 mb-6">FOUR INPUTS · ONE ASSESSMENT</p>
            <div className="grid grid-cols-2 gap-3 max-w-xl mx-auto text-left">
              {[
                ['URL', 'Inspect links and domains.'],
                ['QR', 'Decode and analyze QR payloads.'],
                ['MESSAGE', 'Detect phishing and pressure tactics.'],
                ['DOCUMENT', 'Check integrity against a reference.'],
              ].map(([t, d]) => (
                <div key={t} className="surface-raised rounded-lg px-4 py-3.5">
                  <div className="font-mono text-sm font-bold">{t}</div>
                  <div className="text-xs text-mist-300 mt-1">{d}</div>
                </div>
              ))}
            </div>
          </div>

          <div ref={(el) => { stageRefs.current[4] = el; }} className="hero-stage absolute inset-x-0 px-4 space-y-6" style={{ opacity: 0 }}>
            <p className="text-xs tracking-[0.3em] text-mist-300">FROM INPUT TO EVIDENCE</p>
            <PipelineDiagram />
          </div>

          <div ref={(el) => { stageRefs.current[5] = el; }} className="hero-stage absolute inset-x-0 px-4 space-y-6" style={{ opacity: 0 }}>
            <p className="text-4xl sm:text-6xl font-extrabold tracking-tight">VERIFY BEFORE<br />YOU TRUST.</p>
            <div>
              <a href="#analyze" className="inline-flex items-center gap-2 bg-mist-100 text-ink-950 font-semibold px-7 py-3 rounded-md hover:bg-white transition-colors">
                Analyze an input <span aria-hidden="true">→</span>
              </a>
            </div>
          </div>
        </div>

        <div ref={hintRef} aria-hidden="true" className="absolute bottom-8 inset-x-0 text-center transition-opacity duration-500">
          <p className="text-[11px] tracking-[0.3em] text-mist-300">SCROLL TO VERIFY</p>
          <p className="text-mist-500 mt-1 animate-bounce">↓</p>
        </div>

        <div aria-hidden="true" className="absolute bottom-0 inset-x-0 h-0.5 bg-white/10">
          <div ref={barRef} className="h-full bg-mist-100 origin-left" style={{ transform: 'scaleX(0)' }} />
        </div>
      </div>
    </div>
  );
}
