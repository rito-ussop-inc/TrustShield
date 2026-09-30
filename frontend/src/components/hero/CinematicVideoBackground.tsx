import { useEffect, useRef, useState } from 'react';

/**
 * Scroll-synchronized cinematic video layers (hero video integration brief).
 *
 * Two fixed full-viewport layers behind page content (content stays z-10).
 *
 * HERO (desktop): /videos/trustshield-hero.mp4 is preloaded into memory
 * (blob) so seeks are local, then PAUSED and scrubbed:
 * currentTime = smoothed page progress mapped 0→1 from page top to the
 * #analyze section. Seeks are throttled (min interval + delta threshold)
 * and the file uses 0.5 s keyframes, so scrubbing stays fluid. The hero
 * layer fades to 0 exactly as the analyzer arrives.
 *
 * AMBIENT (desktop): /videos/trustshield-ambient.mp4 crossfades in as the
 * hero layer exits and loops quietly behind the rest of the page
 * (analyzer, how-it-works, technology, footer) at low opacity. No scrub,
 * no controls — pure backdrop. It only decodes while actually visible.
 *
 * Mobile: hero loop only (no scrub, no ambient) to save bandwidth.
 * Missing/failed asset, reduced motion, or data-saver → renders nothing;
 * the existing grid/CSS background carries the page.
 *
 * Assets live in frontend/public/videos/ (never hotlinked).
 */

const HERO_SRC = '/videos/trustshield-hero.mp4';
const HERO_POSTER = '/videos/trustshield-hero-poster.jpg';
const AMBIENT_SRC = '/videos/trustshield-ambient.mp4';

const LERP = 0.16;
const SEEK_MIN_INTERVAL_MS = 60;
const SEEK_DELTA_S = 0.08;
const AMBIENT_CAP = 0.38;

function clamp01(v: number): number {
  return Math.min(1, Math.max(0, v));
}

/** Hero layer: subdued at title, present mid-story, gone at analyzer. */
export function videoLayerOpacity(progress: number, compact: boolean): number {
  const cap = compact ? 0.32 : 0.85;
  let o: number;
  if (progress < 0.12) {
    o = 0.42 + (progress / 0.12) * 0.2; // 0.42 → 0.62
  } else if (progress < 0.72) {
    o = 0.62 + ((progress - 0.12) / 0.6) * 0.23; // → 0.85
  } else {
    o = 0.85 * (1 - (progress - 0.72) / 0.28); // fade → 0 at analyzer
  }
  return Math.min(cap, Math.max(0, o));
}

/** Ambient layer: silent until the hero exits, then a steady low wash. */
export function ambientLayerOpacity(progress: number, compact: boolean): number {
  if (compact) return 0;
  if (progress < 0.72) return 0;
  return Math.min(AMBIENT_CAP, ((progress - 0.72) / 0.28) * AMBIENT_CAP);
}

export function CinematicVideoBackground() {
  const heroLayerRef = useRef<HTMLDivElement>(null);
  const ambientLayerRef = useRef<HTMLDivElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const ambientRef = useRef<HTMLVideoElement>(null);
  const [failed, setFailed] = useState(false);
  const [ready, setReady] = useState(false);

  const reduced =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const saveData =
    typeof navigator !== 'undefined' &&
    (navigator as Navigator & { connection?: { saveData?: boolean } }).connection?.saveData === true;
  const compact =
    typeof window !== 'undefined' && window.matchMedia('(max-width: 767px)').matches;

  const disabled = reduced || saveData || failed;

  // Preload the hero file into a blob URL so every seek hits local bytes.
  useEffect(() => {
    if (disabled || compact) return;
    const video = videoRef.current;
    if (!video) return;
    let objectUrl: string | null = null;
    let cancelled = false;
    video.pause();
    fetch(HERO_SRC)
      .then((r) => {
        if (!r.ok) throw new Error(`hero video ${r.status}`);
        return r.blob();
      })
      .then((b) => {
        if (cancelled) return;
        objectUrl = URL.createObjectURL(b);
        video.src = objectUrl;
        video.load();
      })
      .catch(() => {
        /* keep direct src — seeks still work, just less smooth */
      });
    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [disabled, compact]);

  useEffect(() => {
    if (disabled) return;
    const video = videoRef.current;
    const heroLayer = heroLayerRef.current;
    const ambientLayer = ambientLayerRef.current;
    const ambient = ambientRef.current;
    if (!video || !heroLayer) return;

    let raf = 0;
    let target = 0;
    let smooth = 0;
    let lastSeek = 0;
    let ambientPlaying = false;
    let disposed = false;

    const measure = () => {
      const anchor = document.getElementById('analyze');
      const anchorTop = anchor
        ? anchor.getBoundingClientRect().top + window.scrollY
        : document.body.scrollHeight;
      // Progress completes as the analyzer section reaches mid-viewport.
      const end = Math.max(1, anchorTop - window.innerHeight * 0.55);
      target = clamp01(window.scrollY / end);
    };

    const setAmbientPlaying = (want: boolean) => {
      if (!ambient || compact || ambientPlaying === want) return;
      ambientPlaying = want;
      if (want) {
        ambient.play().catch(() => {
          ambientPlaying = false;
        });
      } else {
        ambient.pause();
      }
    };

    const frame = (now: number) => {
      if (disposed) return;
      smooth += (target - smooth) * LERP;
      if (Math.abs(target - smooth) < 0.0004) smooth = target;

      if (!compact) {
        // Throttled scrub of the paused timeline.
        const dur = video.duration;
        if (dur && Number.isFinite(dur) && video.readyState >= 2 && !document.hidden) {
          const want = smooth * dur;
          if (
            Math.abs(video.currentTime - want) > SEEK_DELTA_S &&
            now - lastSeek > SEEK_MIN_INTERVAL_MS
          ) {
            lastSeek = now;
            try {
              video.currentTime = want;
            } catch {
              /* seek while loading — next frame retries */
            }
          }
        }
        if (!video.paused) video.pause();
        setAmbientPlaying(smooth > 0.6 && smooth < 1.2);
      }

      const ho = videoLayerOpacity(smooth, compact);
      heroLayer.style.opacity = ho.toFixed(3);
      heroLayer.style.visibility = ho <= 0.004 ? 'hidden' : 'visible';

      if (ambientLayer) {
        const ao = ambientLayerOpacity(smooth, compact);
        ambientLayer.style.opacity = ao.toFixed(3);
        ambientLayer.style.visibility = ao <= 0.004 ? 'hidden' : 'visible';
        if (ao <= 0.004) setAmbientPlaying(false);
      }

      raf = requestAnimationFrame(frame);
    };

    const onVis = () => {
      // When returning to the tab, resync without a jump.
      if (!document.hidden) measure();
    };

    measure();
    raf = requestAnimationFrame(frame);
    window.addEventListener('scroll', measure, { passive: true });
    window.addEventListener('resize', measure);
    document.addEventListener('visibilitychange', onVis);
    return () => {
      disposed = true;
      cancelAnimationFrame(raf);
      window.removeEventListener('scroll', measure);
      window.removeEventListener('resize', measure);
      document.removeEventListener('visibilitychange', onVis);
    };
  }, [disabled, compact]);

  if (disabled) return null;

  return (
    <>
      <div
        ref={heroLayerRef}
        aria-hidden="true"
        className="pointer-events-none fixed inset-0 z-0"
        style={{ opacity: 0, visibility: 'hidden' }}
      >
        <video
          ref={videoRef}
          className="absolute inset-0 h-full w-full object-cover object-center"
          src={HERO_SRC}
          poster={HERO_POSTER}
          muted
          playsInline
          preload={compact ? 'metadata' : 'auto'}
          disablePictureInPicture
          webkit-playsinline="true"
          {...(compact ? { autoPlay: true, loop: true } : {})}
          onCanPlay={() => setReady(true)}
          onError={() => setFailed(true)}
        />
        {/* Dark integration overlay: video stays subordinate to content. */}
        <div
          className="absolute inset-0 transition-opacity duration-700"
          style={{
            opacity: ready ? 1 : 0,
            background:
              'linear-gradient(180deg, rgba(5,7,13,0.78) 0%, rgba(5,7,13,0.42) 38%, rgba(5,7,13,0.55) 68%, rgba(5,7,13,0.92) 100%)',
          }}
        />
      </div>

      {!compact && (
        <div
          ref={ambientLayerRef}
          aria-hidden="true"
          className="pointer-events-none fixed inset-0 z-0"
          style={{ opacity: 0, visibility: 'hidden' }}
        >
          <video
            ref={ambientRef}
            className="absolute inset-0 h-full w-full object-cover object-center"
            src={AMBIENT_SRC}
            muted
            playsInline
            loop
            preload="none"
            disablePictureInPicture
            webkit-playsinline="true"
            onError={() => {
              /* ambient is decorative — hero story continues regardless */
              if (ambientLayerRef.current) ambientLayerRef.current.style.display = 'none';
            }}
          />
          <div
            className="absolute inset-0"
            style={{
              background:
                'linear-gradient(180deg, rgba(5,7,13,0.72) 0%, rgba(5,7,13,0.55) 50%, rgba(5,7,13,0.8) 100%)',
            }}
          />
        </div>
      )}
    </>
  );
}
