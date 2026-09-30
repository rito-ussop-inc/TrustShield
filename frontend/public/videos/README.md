# TrustShield hero video asset

The cinematic homepage layer (`CinematicVideoBackground.tsx`) expects the
production video file here:

```text
frontend/public/videos/trustshield-hero.mp4
```

It is referenced at runtime as `/videos/trustshield-hero.mp4`.
An optional poster frame may be placed at:

```text
frontend/public/videos/trustshield-hero-poster.jpg
```

## How to supply it

1. Download the approved Pinterest reference video to your machine
   (the pin URL is a **design reference only** — never hotlink it).
2. Transcode to a web-friendly MP4 if needed, e.g.:
   `ffmpeg -i input.mp4 -c:v libx264 -crf 23 -preset slow -movflags +faststart -vf scale=1920:-2 -an trustshield-hero.mp4`
   (keep it modest — hero of a few MB, not tens of MB).
3. Copy the file to this folder and restart `npm run dev`.

## Behavior without the file

If the file is absent or fails to load, the component hides itself and the
page falls back to the existing dark grid/CSS background. The site remains
fully functional — no controls, errors, or blank screens are shown.

## Note on version control

Large `*.mp4` / `*.webm` files in this folder are git-ignored by default so
the repo does not bloat. The current `trustshield-hero.mp4` (~1.7 MB, audio
stripped, badge removed) is force-tracked as a deliberate exception so the
site works out of the box.
