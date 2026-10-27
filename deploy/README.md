# BootNexa public preview deployment — Caddy + Cloudflare Tunnel

**Target:** `https://bootnexa.tnaprovider.com.au` (marketing homepage), `/app` (six-stage guide), and `/app/workspace` (existing read-only preparation workspace).

**Release classification: PUBLIC PRE-RELEASE PREVIEW.** The Windows native agent has only read-only device inventory. BootNexa does **not** yet support physical USB writing or a real bootable-media release. Do not describe the website as an operational USB-writing production release, publish unsigned agent downloads, or enable write APIs.

## Mandatory deployment preflight

1. Obtain a fresh, reviewed, fully passing GitHub workflow run for the **exact** Git commit. Confirm `npm ci`, `npm run build`, Playwright route/safety tests, and native safety regression checks. Never deploy a worktree with unknown modifications.
2. On the existing GCloud host, inspect `caddy version`, `caddy validate --config <existing-caddyfile>`, `cloudflared tunnel list`, `cloudflared tunnel info <existing-tunnel-id>`, `cloudflared tunnel ingress validate` and existing routes. Back up the Caddyfile, tunnel config and current site symlink. **Do not overwrite the Caddyfile, replace the tunnel, create a second conflicting DNS record, or alter any existing hostnames**.
3. Verify ownership and current DNS for `bootnexa.tnaprovider.com.au`. Check for existing A, AAAA, CNAME and tunnel routes; preserve anything already in service. Only add a DNS route when the hostname is free and you have verified which existing Cloudflare Tunnel serves this host. Do not expose the origin port on public network interfaces.
4. Deploy only the Vite static site to an immutable release directory, then atomically change `/srv/bootnexa/current` after validating assets. Require `index.html` and its hashed asset files. Keep the previously working release for immediate rollback.
5. Import `deploy/Caddyfile.bootnexa.example` into the existing Caddy configuration **after** checking port `127.0.0.1:17834` is available. It binds to loopback and supplies SPA fallback, browser security headers, compression and immutable cache for versioned assets. The path `/app/workspace` resolves to the same Vite `index.html`.
6. Add a single cloudflared ingress rule **before** the catch-all rule:
   ```yaml
   - hostname: bootnexa.tnaprovider.com.au
     service: http://127.0.0.1:17834
   ```
   Use the existing tunnel's route (for example `cloudflared tunnel route dns <verified-existing-tunnel-id> bootnexa.tnaprovider.com.au`), not a new unreviewed tunnel. Validate both Caddy and the complete cloudflared ingress config before reload. This command changes DNS, so do not run it merely as a check.
7. Reload each existing service using the host's actual deployment method, not a guessed service name. Check Caddy and tunnel logs after reload; do not restart unrelated applications.

## CI-qualified build

```sh
git fetch origin
git checkout --detach <reviewed-merged-main-commit-sha>
npm ci
npm run build
# inspect dist/index.html and dist/assets; compare source SHA to CI run
```

An atomic deployment typically copies `dist/` to `/srv/bootnexa/releases/<commit-sha>/` and changes a `current` symlink. Exact ownership/service accounts/permissions must be derived from the live VM rather than assumed.

## Post-deployment acceptance

Check both loopback and external hostname, including HTTPS, certificate, hostname, routing, caching, content-security policies, DNS and responsive pages:

```sh
curl -fsSI http://127.0.0.1:17834/
curl -fsSI http://127.0.0.1:17834/app
curl -fsSI http://127.0.0.1:17834/app/workspace
curl -fsSI https://bootnexa.tnaprovider.com.au/
curl -fsSI https://bootnexa.tnaprovider.com.au/app
curl -fsSI https://bootnexa.tnaprovider.com.au/app/workspace
```

Browser acceptance: root hero renders, **Open guided app** resolves to `/app`, all six guide stages render, release channel is explicitly unverified if no signed release exists, offline agent state is understandable, real agent connection uses Windows native approval when available, `/app/workspace` retains read-only preflight, and both write actions are disabled. Verify neither cloud server nor agent writes, formats, repartitions, or uploads the selected ISO.

**Origin binding:** Windows native agent defaults to `https://bootnexa.tnaprovider.com.au`, must still bind its API only to `127.0.0.1:43627`, and must require a user-visible Windows approval prompt. For developer localhost, explicitly configure `BOOTNEXA_ALLOWED_ORIGIN=http://127.0.0.1:5173`. A signed, reviewed agent release is still a separate prerequisite to an actual public agent download. HTTPS-to-loopback fetch may require browser private-network permission; verify it on real Windows browsers rather than assuming every browser permits it.

**Rollback:** restore the prior `current` symlink and reload Caddy; if tunnel routing/DNS was newly introduced, restore the prior configs and remove only the new verified route. Do not alter other TNA Provider services.

## Evidence and completion rules

Record source Git SHA, CI run URL, static build SHA, Caddy validation result, tunnel ID and existing DNS state, external TLS response, all 3 route status codes, browser smoke, and rollback result. Until these are measured, deployment is **not verified**.

**BootNexa functional completion is a separate gate.** Real USB device writes, Windows Setup guest installation, firmware/hardware interoperability, full-device readback, safe cancellation, device identity re-verification, signing and rescue tests must pass before any public "Create bootable USB" control can be enabled.
