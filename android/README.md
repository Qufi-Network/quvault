# Veyns Quantum Vault — Android APK (TWA)

The APK is a **Trusted Web Activity**: a thin Android shell that opens the live
`https://quvault-one.vercel.app` fullscreen, with no browser URL bar once Digital Asset
Links verify. It does **not** bundle the wallet code — the wallet is the deployed site, so the
app updates whenever the site deploys. All of the palm-approval, time-window and
BTC/ETH/BSC behaviour is the same code served to a browser.

## Identity

- Package: `io.veyns.quvault`
- Signing key: `android/veyns-release.keystore`, alias `veyns` (gitignored; back it up)
- Key SHA-256 is published at `public/.well-known/assetlinks.json`

## Build (run from the repo root)

Prerequisites, all confirmed present on the build machine except the Android SDK, which
Bubblewrap downloads on first run:
- JDK 17 (`JAVA_HOME` set)
- `@bubblewrap/cli` installed globally
- **The site must already be deployed** so Bubblewrap can read the live manifest + icons,
  and so `/.well-known/assetlinks.json` is reachable.

```bash
set -a; . ./android/signing.env; set +a          # loads keystore passwords for a non-interactive build
bubblewrap build --skipPwaValidation
```

Output: `app-release-signed.apk` in the repo root. Install with `adb install` or sideload.

## Why deployment comes first

`twa-manifest.json` points `webManifestUrl` and `iconUrl` at the live domain. Bubblewrap
fetches those during the build. Until `public/` (manifest, icons, the new wallet UI) and
`public/.well-known/assetlinks.json` are live, the build either fails to fetch the manifest or
produces an app that wraps a stale site and shows a URL bar.
