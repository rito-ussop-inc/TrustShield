import { useEffect, useRef, type ReactNode } from 'react';

/** Fade-up reveal on first intersection; static when reduced motion. */
export function Reveal({ children, className = '' }: { children: ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      el.style.opacity = '1';
      el.style.transform = 'none';
      return;
    }
    el.style.opacity = '0';
    el.style.transform = 'translateY(18px)';
    el.style.transition = 'opacity 600ms ease, transform 600ms ease';
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            el.style.opacity = '1';
            el.style.transform = 'none';
            io.disconnect();
          }
        });
      },
      { threshold: 0.15 }
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return <div ref={ref} className={className}>{children}</div>;
}

function SectionHead({ kicker, title, body }: { kicker: string; title: string; body?: string }) {
  return (
    <Reveal className="max-w-2xl">
      <p className="text-xs font-mono tracking-[0.25em] text-mist-500">{kicker}</p>
      <h2 className="mt-2 text-3xl sm:text-4xl font-extrabold tracking-tight">{title}</h2>
      {body && <p className="mt-3 text-mist-300 text-sm sm:text-base leading-relaxed">{body}</p>}
    </Reveal>
  );
}

const CAPABILITIES: Array<[string, string, string]> = [
  ['URL', 'Inspect links and domains.', 'M8 5h8M8 12h8M8 19h5M5 3h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z'],
  ['QR', 'Decode and analyze QR payloads.', 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h3v3h-3zM20 14v6h-6'],
  ['MESSAGE', 'Detect social-engineering signals.', 'M4 5h16v11H9l-5 4V5zM8 9h8M8 12h5'],
  ['DOCUMENT', 'Check file integrity vs a reference.', 'M7 3h7l5 5v13H7zM14 3v5h5M10 13h6M10 17h6'],
];

function Icon({ d }: { d: string }) {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="w-5 h-5 text-mist-100" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <path d={d} />
    </svg>
  );
}

export function ProductOverview() {
  return (
    <section aria-labelledby="overview-h" className="max-w-shell mx-auto px-4 sm:px-6 py-20 sm:py-28">
      <SectionHead
        kicker="WHAT TRUSTSHIELD DOES"
        title="TRUST IS A CLAIM. EVIDENCE IS THE TEST."
        body="TrustShield analyzes digital inputs for suspicious patterns, threat-intelligence signals, language cues, and integrity indicators before you act on them."
      />
      <div className="mt-10 grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {CAPABILITIES.map(([t, d, path]) => (
          <Reveal key={t}>
            <div className="surface rounded-xl p-5 h-full">
              <Icon d={path} />
              <h3 className="mt-3 font-mono font-bold text-sm tracking-wider">{t}</h3>
              <p className="mt-1.5 text-sm text-mist-300">{d}</p>
            </div>
          </Reveal>
        ))}
      </div>
    </section>
  );
}

const STEPS: Array<[string, string, string]> = [
  ['01 — INPUT', 'URL / QR / MESSAGE / DOCUMENT', 'Submit one digital input for assessment.'],
  ['02 — ANALYSIS', 'Signals, not verdicts', 'The system extracts structural, language, and integrity signals.'],
  ['03 — EVIDENCE', 'Rules + ML + threat intel', 'Signals are combined with model outputs and available threat intelligence.'],
  ['04 — ASSESSMENT', 'Level, score, evidence, action', 'You receive a risk level, score, evidence trail, and recommended next step.'],
];

export function HowItWorks() {
  return (
    <section id="how" aria-labelledby="how-h" className="border-t border-white/5 scroll-mt-14">
      <div className="max-w-shell mx-auto px-4 sm:px-6 py-20 sm:py-28">
        <SectionHead kicker="HOW IT WORKS" title="FROM INPUT TO EVIDENCE." />
        <ol className="mt-10 grid sm:grid-cols-2 lg:grid-cols-4 gap-3 list-none">
          {STEPS.map(([t, s, d]) => (
            <li key={t}>
              <Reveal>
                <div className="surface rounded-xl p-5 h-full">
                  <p className="font-mono text-xs text-mist-500">{t}</p>
                  <h3 className="mt-2 font-bold">{s}</h3>
                  <p className="mt-1.5 text-sm text-mist-300">{d}</p>
                </div>
              </Reveal>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}

export function TrustArchitecture() {
  const rows: Array<[string, string[]]> = [
    ['USER INPUT', ['URL', 'QR', 'MESSAGE', 'DOCUMENT']],
    ['INPUT PROCESSING', ['Validate', 'Normalize']],
    ['ANALYZER LAYER', ['RULES', 'ML', 'THREAT INTEL']],
    ['EVIDENCE ENGINE', ['Findings', 'Evidence']],
    ['TRUST ENGINE', ['Risk level', 'Score']],
    ['RECOMMENDATION', ['Action', 'Limitations']],
  ];
  return (
    <section aria-labelledby="arch-h" className="border-t border-white/5">
      <div className="max-w-shell mx-auto px-4 sm:px-6 py-20 sm:py-28">
        <SectionHead
          kicker="ARCHITECTURE"
          title="INPUT → ANALYSIS → EVIDENCE → DECISION SUPPORT."
          body="No magical verdicts. Every assessment carries its evidence trail and stated limitations."
        />
        <Reveal className="mt-10">
          <div className="surface rounded-xl p-5 sm:p-8 overflow-x-auto">
            <ol className="min-w-[560px] space-y-1 list-none" aria-label="Trust engine pipeline">
              {rows.map(([stage, chips], i) => (
                <li key={stage}>
                  <div className="flex items-center gap-3">
                    <span className="w-40 shrink-0 font-mono text-xs text-mist-300">{stage}</span>
                    <div className="flex flex-wrap gap-1.5">
                      {chips.map((c) => (
                        <span key={c} className="text-[11px] font-mono px-2.5 py-1 rounded border border-white/15 bg-white/5">{c}</span>
                      ))}
                    </div>
                  </div>
                  {i < rows.length - 1 && <div aria-hidden="true" className="ml-40 pl-1 text-mist-500 text-xs py-0.5">↓</div>}
                </li>
              ))}
            </ol>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

const STACK: Array<[string, string]> = [
  ['FRONTEND', 'React / TypeScript / Tailwind'],
  ['BACKEND', 'Python / FastAPI'],
  ['ANALYSIS', 'Deterministic rules + calibrated ML'],
  ['THREAT INTELLIGENCE', 'PhishTank · URLhaus · Google Web Risk (via backend)'],
  ['DOCUMENTS', 'SHA-256 integrity verification'],
  ['QR', 'Server-side payload decoding'],
  ['DATA', 'SQLite persistence for analysis history'],
];

export function TechnologySection() {
  return (
    <section id="technology" aria-labelledby="tech-h" className="border-t border-white/5 scroll-mt-14">
      <div className="max-w-shell mx-auto px-4 sm:px-6 py-20 sm:py-28">
        <SectionHead kicker="TECHNOLOGY" title="ONLY WHAT IS ACTUALLY IMPLEMENTED." />
        <dl className="mt-10 grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {STACK.map(([t, d]) => (
            <Reveal key={t}>
              <div className="surface rounded-xl p-5 h-full">
                <dt className="font-mono text-xs tracking-widest text-mist-500">{t}</dt>
                <dd className="mt-2 text-sm">{d}</dd>
              </div>
            </Reveal>
          ))}
        </dl>
      </div>
    </section>
  );
}

export function Footer() {
  return (
    <footer id="about" aria-label="About TrustShield" className="border-t border-white/10 scroll-mt-14">
      <div className="max-w-shell mx-auto px-4 sm:px-6 py-12 grid gap-8 md:grid-cols-3">
        <div>
          <p className="font-bold tracking-widest text-sm">◈ TRUSTSHIELD</p>
          <p className="mt-2 text-xs tracking-[0.25em] text-mist-500">VERIFY BEFORE YOU TRUST.</p>
          <p className="mt-3 text-sm text-mist-300 max-w-xs">
            Evidence-backed trust assessment for URLs, messages, QR codes, and documents.
          </p>
        </div>
        <div className="text-sm">
          <p className="font-mono text-xs tracking-widest text-mist-500 mb-3">PRODUCT</p>
          <div className="flex flex-col gap-2 text-mist-300">
            <a href="#analyze" className="hover:text-mist-100 w-fit">Analyze</a>
            <a href="#how" className="hover:text-mist-100 w-fit">How It Works</a>
            <a href="#technology" className="hover:text-mist-100 w-fit">Technology</a>
          </div>
        </div>
        <div className="text-sm">
          <p className="font-mono text-xs tracking-widest text-mist-500 mb-3">SAFETY NOTE</p>
          <p className="text-mist-300 text-sm leading-relaxed">
            No automated analysis can guarantee an unknown input is safe. Never enter credentials
            from an unverified link — verify through an independent official channel.
          </p>
        </div>
      </div>
    </footer>
  );
}
