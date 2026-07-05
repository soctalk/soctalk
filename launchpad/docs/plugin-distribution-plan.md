# Plan: plugin distribution via download-all-on-init (v2, post-review)

Revised after an adversarial review. The central change from v1: verification
is enforced at **execution time**, not just at install time, and discovery
distinguishes trusted plugins from dev plugins. Install-time-only verification
is worthless here because `Start` execs whatever is on disk without re-checking
(`client.go:84`) and reads the env allow-list from an editable `plugin.yaml`
(`manifest.go:49`).

## Goal

Ship a lean CLI that, on first run, downloads all first-party plugins for its
own platform, verifies them, and installs them into a managed store where
discovery finds them. No `LAUNCHPAD_PLUGIN_DIR` needed, no fat binary, no
multi-module refactor.

## Scope

- Download-all on init (not lazy — later option; the design must not preclude it).
- Version-pinned to the CLI's own release.
- Verified at install **and before every spawn** against a locally cached,
  signature-verified record.
- Idempotent, resumable, concurrency-safe.
- Offline/pre-seeded fallback.

## Non-goals

- Lazy/on-intent download; third-party registries; background auto-update.
- Sandboxing plugin execution (see threat model — explicitly out of scope for v1).

## Threat model (explicit)

What signing does and does not buy, stated so the plan does not overclaim:

- **In scope:** integrity + authenticity of what we distribute. Defends against
  a tampered release asset, a MITM on download, and post-install edits to the
  binary, the manifest, or the env policy.
- **Out of scope:** sandboxing. A first-party plugin is trusted code; once
  verified and run it executes as the launchpad user, can use the network, read
  accessible files, and use any secret handed to it via `ExtraEnv`. **v1 accepts
  "first-party plugin compromise = user compromise."** Separate-user / container
  / seccomp isolation is future work, noted, not built.
- **Secrets:** `ExtraEnv` (host creds, `TAILSCALE_API_KEY`) is deliberately
  exposed to the plugin that needs it. The `Manifest.Env` allow-list governs
  *inherited ambient* env; `ExtraEnv` is *operator-injected* secret policy from
  host/network config. These are two policies and the plan keeps them distinct.

## Trust model

Single signed root, authoritative at both install and spawn. A signed
`index.json` carries, per plugin: version, protocol, supported platforms, the
SHA-256 of each artifact, and the exact manifest fields (`env`, `license`,
`homepage`). One minisign signature (verified against a public key embedded in
the CLI) covers binary integrity **and** the security-critical env policy. The
CLI caches the verified index and treats **that cache**, never the on-disk
`plugin.yaml`, as authority at execution time.

Chain: embedded pubkey → verified index (cached) → per-artifact SHA-256 →
binary on disk. Every link checked before exec.

## The index

Release asset `index.json` keyed to tag `launchpad-v<version>`, detached sig
`index.json.minisig`.

```json
{
  "schema_version": 1,
  "launchpad_version": "0.2.0",
  "protocol_version": "1",
  "expires": "2026-10-01T00:00:00Z",
  "plugins": [
    {
      "name": "qemu",
      "version": "0.2.0",
      "protocol": "1",
      "substrate": "local",
      "platforms": ["linux/amd64", "linux/arm64"],
      "description": "QEMU/KVM on a Linux host",
      "env": ["SSH_AUTH_SOCK", "HOME", "TAILSCALE_API_KEY"],
      "license": "MIT",
      "homepage": "https://github.com/soctalk/soctalk",
      "artifacts": [
        { "os": "linux", "arch": "amd64",
          "url": "https://github.com/soctalk/soctalk/releases/download/launchpad-v0.2.0/qemu_linux_amd64",
          "sha256": "…", "size": 12345678 }
      ]
    }
  ]
}
```

Self-consistent: `protocol` and `platforms` are present per plugin; no separate
manifest hash because the manifest *fields* are signed inline. The CLI
synthesizes `plugin.yaml` deterministically from the signed entry, but never
trusts that synthesized file at exec time — it re-derives from the cached index.

`platforms` lets a plugin declare where it is even meaningful (`wsl2` →
Windows, `qemu` → Linux). Download-all skips artifacts not built for the host
and does **not** hard-fail a plugin that has no artifact for this platform.

## Signing and verification

- **minisign** (single ed25519 key). Private key held only in a protected
  release environment; **public key embedded in the CLI**. No trust-on-first-use.
- **Index expiry** (`expires`): the CLI rejects an index past its expiry, so a
  stolen key cannot serve a frozen malicious index indefinitely without periodic
  re-signing by whoever still holds the key.
- **Key compromise, honest stance:** an embedded single key cannot be revoked
  for already-shipped CLIs beyond cutting a new release; existing installs keep
  trusting it. v1 documents this limit and mitigates with expiry. A TUF-style
  root/targets split with key IDs, thresholds, and rotation is the future path if
  the product needs real revocation.
- Client verify order: fetch index + sig → verify sig with embedded pubkey →
  check `expires` and `launchpad_version`/`protocol` compat → per artifact:
  download to temp → SHA-256 vs index → stage.

## Spawn-time verification and discovery provenance

This is the part v1 got wrong. Changes to the plugin host:

- **Provenance on manifests.** Discovery tags each loaded plugin as `managed`
  (came from the verified store, index-backed) or `dev` (from
  `LAUNCHPAD_PLUGIN_DIR`, unsigned). `DiscoverPlugins` currently searches
  `LAUNCHPAD_PLUGIN_DIR` → XDG → `~/.launchpad` first-name-wins (`manifest.go:95`),
  which lets an unsigned plugin shadow a signed one. New rule: a `dev` plugin may
  not silently shadow a `managed` one, and `dev` plugins are inert for `up`/UI/
  secret-bearing paths unless `--allow-unsigned` (or `LAUNCHPAD_DEV=1`) is set.
- **Verify before exec.** `pluginhost.Start` (or a wrapper the callers use)
  re-checks a `managed` plugin's binary SHA-256 against the cached verified
  index immediately before `exec`, and builds the env allow-list from the
  **index entry**, not the on-disk `plugin.yaml`. A tampered binary/manifest/
  env fails the spawn. All spawn sites go through this: `up` (`orchestrator.go:181`),
  UI platform discovery (`platforms.go:77`), probe (`probe.go:89`), `plugin run`
  (`main.go:275`).
- **ExtraEnv boundary.** Keep `ExtraEnv` as operator-injected secrets, but make
  the boundary explicit and, where cheap, validate `ExtraEnv` keys against a
  declared per-plugin secret set so a typo/injection can't smuggle arbitrary env.

## Publishing pipeline (net-new, not incremental)

There is no `.github` workflow today and the `Makefile` builds only qemu+vmware
while 11 plugin modules exist. This milestone is a new multi-module build/release
system, scoped accordingly.

On a `launchpad-v*` tag, in a **protected release environment**:
1. Cross-build CLI + every plugin for `{linux,darwin,windows}×{amd64,arm64}`
   with `CGO_ENABLED=0`. The **matrix build itself is the cgo guard** (a `grep
   import "C"` is only a fast pre-check, not the guarantee).
2. Inject the release version via `-ldflags` into the CLI's version variable
   (move it out of a hardcoded const so tag and binary agree; test tag==version).
3. Name artifacts `<name>_<os>_<arch>[.exe]`.
4. Generate `index.json` (Go generator: per-artifact SHA + size, `env`/`protocol`/
   `platforms` from each plugin's checked-in `plugin.yaml`, stamp version/expiry).
5. **Sign as a gated step:** manual approval, no signing of PR/untrusted code,
   least-privilege token, emit provenance/SBOM.
6. Upload binaries, artifacts, `index.json`, `.minisig`, and an offline bundle.

## CLI implementation

New package `cli/internal/pluginstore`:

- `FetchIndex(ctx)` — derive URL from injected version, download + verify + expiry
  check, return parsed `Index`; cache the verified bytes under the store.
- `Sync(ctx, opts)`:
  - Acquire a **plugin-root lockfile** (guards concurrent `Sync` across processes).
  - For each plugin's matching platform artifact: verify the **actual
    filesystem** (binary SHA vs index, manifest present, perms) before skipping —
    `installed.json` is a cache hint, never authority.
  - Download → SHA check → stage the **whole plugin dir** in a temp dir → fsync →
    publish atomically (rename the dir, or versioned dir + atomic pointer) so a
    new binary is never visible with an old manifest, and a crash leaves the old
    version intact.
  - Update `installed.json` atomically (temp + rename), dir-fsync.
  - Bounded parallelism for downloads; single writer for metadata.
  - Skip (don't fail) plugins with no artifact for this platform; report them.
- `VerifyForSpawn(name)` — used by the host before exec (see above).

Commands: `launchpad init`, `launchpad plugin sync|list [--available]`,
global `--no-auto-sync`, `--allow-unsigned`. First-run: `ui`/`up` run `Sync`
if the store is empty or version-mismatched, streaming progress.

## Failure modes and UX

Network down → name the offline path. Bad signature / expired index → hard fail,
install nothing. SHA mismatch → discard, one retry, then fail that plugin,
others proceed. Non-writable store → clear error with resolved path. Partial →
resume. Platform with no artifact → skip + report, never block a usable plugin.

## Offline / air-gapped

Pre-seeded managed store is honored (verify-before-skip still applies).
`launchpad plugin sync --from <tar|dir>` verifies against the same signed index.
The tar path is **hardened**: reject `..`, absolute paths, symlinks, hardlinks,
device files, duplicate entries; enforce per-file and total size caps; extract
to a staging dir and verify before publish.

## Testing (adversarial, not just happy path)

Unit: index parse; minisign verify with a throwaway keypair; expiry rejection;
SHA verify; atomic dir publish; verify-before-skip; verify-before-spawn.
Adversarial/integration (`httptest` + fake signed index): flipped byte in
artifact or index rejected; tampered post-install binary/manifest/env rejected at
spawn; edited `installed.json` ignored; `dev` plugin cannot shadow `managed`;
concurrent `Sync` (lock holds); crash after each write boundary leaves a
consistent store; bad redirects/URLs; missing/extra artifacts; Windows
`.exe` naming; tar traversal/symlink/oversize; version/protocol mismatch.

## Milestones

- **M1 — host trust hardening.** Provenance in discovery, `VerifyForSpawn` at
  every spawn site, `ExtraEnv` boundary. This is prerequisite and independent of
  downloading; it also improves today's dev/`LAUNCHPAD_PLUGIN_DIR` setup.
- **M2 — `pluginstore` core.** Index schema + minisign verify + expiry + `Sync`
  (download-all, verify-before-skip, lock, atomic dir publish) with the
  adversarial test suite. `init` / `plugin sync|list`.
- **M3 — release pipeline.** Multi-module cross-build matrix, ldflag version,
  index generator, gated signing, provenance, first real tagged release.
- **M4 — first-run auto-sync** in `ui`/`up` + progress UX.
- **M5 — offline bundle** + hardened `sync --from`.

## Risks and open decisions

1. **minisign vs cosign** — minisign for v1 (embeddable pubkey, no OIDC); cosign/
   TUF is the path if real revocation becomes a requirement. Confirm.
2. **Revocation limit** — v1 mitigates key compromise with index expiry only;
   no per-CLI revocation. Confirm acceptable, or pull TUF forward.
3. **Sandboxing deferred** — v1 accepts "plugin compromise = user compromise."
   Confirm.
4. **M1 ordering** — hardening the spawn/discovery path first means touching the
   host before any download code exists; it is the right order but front-loads
   protocol/host changes. Confirm.
5. **Binary sizes** — cloud plugins carry AWS/Azure SDKs; all-download ~150–300 MB.
   Accepted under the download-all decision; revisit if lazy loading is prioritized.
