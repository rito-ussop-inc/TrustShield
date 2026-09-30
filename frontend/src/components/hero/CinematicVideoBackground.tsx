import { useEffect, useRef, useState } from 'react';

/**
 * Scroll-synchronized cinematic video layer (hero video integration brief).
 *
 * - Fixed full-viewport layer behind page content (z-0); content stays z-10.
 * - Desktop: video is PAUSED and scrubbed (currentTime = smoothed page
 *   progress mapped 0→1 from page top to the #analyze section). No controls.
 * - Mobile / constrained: subtle muted autoplay loop at capped opacity, no scrub.
 * - Fades to 0 exactly as the user reaches ANALYZE DIGITAL INPUT; the
 *   analyzer and everything after run on the normal UI.
 * - Missing/failed asset, reduced motion, or data-saver → renders nothing;
 *   the existing grid/CSS background carries the page.
 *
 * Asset: /videos/trustshield-hero.mp4 (see public/videos/README.md).
 * Never points at Pinterest or any remote page at runtime.
 */

const SRC = '/videos/trustshield-hero.mp4';
const POSTER = '/videos/trustshield-hero-poster.jpg';

function clamp01(v: number): number {
  return Math.min(1, Math.max(0, v));
}

/** Layer opacity curve: subdued at title, present mid-story, gone at analyzer. */
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

export function CinematicVideoBackground() {
  const layerRef = useRef<HTMLDivElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
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

  useEffect(() => {
    if (disabled) return;
    const video = videoRef.current;
    const layer = layerRef.current;
    if (!video || !layer) return;

    let raf = 0;
    let target = 0;
    let smooth = 0;
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

    const frame = () => {
      if (disposed) return;
      smooth += (target - smooth) * 0.09;
      if (Math.abs(target - smooth) < 0.0004) smooth = target;

      if (!compact) {
        // Scrub the paused timeline (seek only past a threshold to avoid thrash).
        const dur = video.duration;
        if (dur && Number.isFinite(dur) && video.readyState >= 2 && !document.hidden) {
          const want = smooth * dur;
          if (Math.abs(video.currentTime - want) > 0.12) {
            try {
              video.currentTime = want;
            } catch {
              /* seek while loading — next frame retries */
            }
          }
        }
      }

      const o = videoLayerOpacity(smooth, compact);
      layer.style.opacity = o.toFixed(3);
      layer.style.visibility = o <= 0.004 ? 'hidden' : 'visible';
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
    <div
      ref={layerRef}
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0"
      style={{ opacity: 0, visibility: 'hidden' }}
    >
      <video
        ref={videoRef}
        className="absolute inset-0 h-full w-full object-cover object-center"
        src={SRC}
        poster={POSTER}
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
  );
}
