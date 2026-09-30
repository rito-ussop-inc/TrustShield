import { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';

const LINKS = [
  { href: '/#analyze', label: 'Analyze' },
  { href: '/#how', label: 'How It Works' },
  { href: '/#technology', label: 'Technology' },
  { href: '/#about', label: 'About' },
];

export function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  useEffect(() => {
    setOpen(false);
  }, [location.pathname]);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 transition-colors duration-300 border-b ${
        scrolled || open
          ? 'bg-ink-950/90 backdrop-blur border-white/10'
          : 'bg-transparent border-transparent'
      }`}
    >
      <nav aria-label="Primary" className="max-w-shell mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2 font-bold tracking-widest text-sm" aria-label="TrustShield home">
          <span aria-hidden="true" className="text-mist-100">◈</span>
          <span>TRUSTSHIELD</span>
        </Link>

        <div className="hidden md:flex items-center gap-7 text-sm text-mist-300">
          {LINKS.map((l) => (
            <a key={l.href} href={l.href} className="hover:text-mist-100 transition-colors">
              {l.label}
            </a>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <a
            href="/#analyze"
            className="hidden sm:inline-flex items-center gap-1.5 text-sm font-semibold bg-mist-100 text-ink-950 px-4 py-1.5 rounded-md hover:bg-white transition-colors"
          >
            Analyze Now <span aria-hidden="true">→</span>
          </a>
          <button
            className="md:hidden p-2 -mr-2 text-mist-100"
            aria-expanded={open}
            aria-label={open ? 'Close menu' : 'Open menu'}
            onClick={() => setOpen((v) => !v)}
          >
            <span aria-hidden="true" className="text-lg leading-none">{open ? '✕' : '☰'}</span>
          </button>
        </div>
      </nav>

      {open && (
        <div className="md:hidden border-t border-white/10 bg-ink-950/95 backdrop-blur px-4 py-3 space-y-1">
          {LINKS.map((l) => (
            <a
              key={l.href}
              href={l.href}
              className="block py-2 text-sm text-mist-300 hover:text-mist-100"
              onClick={() => setOpen(false)}
            >
              {l.label}
            </a>
          ))}
          <a
            href="/#analyze"
            className="block mt-1 text-sm font-semibold bg-mist-100 text-ink-950 px-4 py-2 rounded-md text-center"
            onClick={() => setOpen(false)}
          >
            Analyze Now →
          </a>
        </div>
      )}
    </header>
  );
}
