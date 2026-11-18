# `cws-source-proof`

**Zero-code-upload SHA-256 source-tree manifest generator & GitHub Action for Chrome Web Store extension M&A provenance.**

- **Zero npm dependencies** (`"dependencies": {}` — uses only Node.js `>= 20` built-ins: `node:crypto`, `node:fs`, `node:path`, `node:url`)
- **Zero proprietary code uploaded** — hashes relative POSIX file paths, byte sizes, detected languages, and comment-stripped relative `import` / `export` / `require` edges locally on your machine or CI runner
- **Safe by default** — skips symbolic links via `lstatSync`, excludes `.env` / `.env.*` / `.npmrc` / `*.pem` / `*.key` / `*.sqlite*` / `*.db*`, and ignores `node_modules/` and build output directories (`dist/`, `build/`, `out/`, `.output/`, `.plasmo/`, `extension/`)
- **MIT Licensed** — inspect the entire codebase in under 60 seconds

**Live Hub & Documentation:**
- Open-Source Hub & Attestation Docs: [https://b2b-audit-dropzone-production.up.railway.app/open-source/cws-source-proof](https://b2b-audit-dropzone-production.up.railway.app/open-source/cws-source-proof)
- Public Chrome Extension Surface Directory: [https://b2b-audit-dropzone-production.up.railway.app/directory](https://b2b-audit-dropzone-production.up.railway.app/directory)

---

## Why Sellers & Buyers Use `cws-source-proof`

When selling a Chrome Extension or micro-SaaS on Acquire.com, Flippa, or Microns, buyers want proof that your private TypeScript/React Git repository actually builds the live extension published on the Chrome Web Store — while sellers rightly refuse to hand raw proprietary source code to strangers before a signed LOI or escrow agreement.

`cws-source-proof` bridges that gap in two transparent tiers:

| Verification Tier | What Leaves Your Repo | Provenance Label | Best For |
| :--- | :--- | :--- | :--- |
| **Tier 1 — Free CLI / GitHub Action** | Only SHA-256 file digests, byte sizes, and relative module graph (`source-proof.json`) | **`Self-Attested Hash Manifest (Zero Code Uploaded)`** | Pre-LOI marketplace listings, public README badges, and CI release provenance |
| **Tier 2 — `$1,500` Independent Escrow Zip Audit** | Private repository `.zip` inspected under NDA / escrow against the live Chrome Web Store `.crx` | **Independent Escrow Zip Audit** | Final M&A technical due diligence before closing wire transfer |

> **Important Provenance Note:** A `Source-Proof Manifest` is a **`Self-Attested Hash Manifest (Zero Code Uploaded)`** generated on the seller's machine or GitHub Actions runner. It proves deterministic repository structure and pre-build module topology (with optional GitHub Actions OIDC repository binding), whereas full line-by-line source compilation parity and secret/security inspection require the **`$1,500 Independent Escrow Zip Audit`** (never legal or regulatory certification).

---

## Quickstart 1: Run Locally via Node.js (Zero Install)

Download the standalone single-file CLI or run from a clone:

```bash
curl -fsSL https://b2b-audit-dropzone-production.up.railway.app/download/cws-source-proof-cli.mjs -o cws-source-proof-cli.mjs
node cws-source-proof-cli.mjs . --out source-proof.json
```

Publish a live **Self-Attested Hash Manifest (Zero Code Uploaded)** against your 32-character Chrome Web Store extension ID:

```bash
node cws-source-proof-cli.mjs . \
  --out source-proof.json \
  --attest-ext-id <your-32-char-cws-extension-id> \
  --repo-label your-org/your-extension
```

---

## Quickstart 2: GitHub Action (With Ambient OIDC Provenance)

Add `.github/workflows/source-proof.yml` to your extension repository:

```yaml
name: Source-Proof Attestation

on:
  release:
    types: [published]
  workflow_dispatch:

permissions:
  contents: read
  id-token: write # Enables cryptographic GitHub OIDC provenance binding

jobs:
  attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate & Publish Source-Proof Manifest
        id: proof
        uses: tsujisound/cws-source-proof@v1
        with:
          repo-dir: "."
          out-file: "source-proof.json"
          extension-id: "abcdefghijklmnopabcdefghijklmnop"
          publish-attestation: "true"

      - name: Upload Manifest Artifact
        uses: actions/upload-artifact@v4
        with:
          name: source-proof-manifest
          path: source-proof.json
```

---

## Embed Your README Badge

Once attested, embed your live badge in your repository `README.md` or marketplace listing:

```markdown
[![Self-Attested Source-Proof](https://b2b-audit-dropzone-production.up.railway.app/badge/source-proof/<32-char-extension-id>.svg)](https://b2b-audit-dropzone-production.up.railway.app/source-proof/<32-char-extension-id>)
```

---

## Programmatic ESM API

```js
import {
  generateSourceProofManifest,
  submitSourceProofAttestation,
} from "cws-source-proof";

const manifest = generateSourceProofManifest("./my-extension-repo", {
  extraIgnoredDirs: ["storybook-static"],
});

console.log(manifest.rootSha256, manifest.preBuildSourceFileCount);
```

---

## Security & Privacy Guarantees

1. **Zero Raw Code Serialization:** Only POSIX relative paths, SHA-256 digests, byte counts, language tags, and relative internal module edges are recorded. No source lines, AST identifier names, or string literals are ever emitted.
2. **Symlink Escape Prevention:** Uses `fs.lstatSync` on every entry and skips all symbolic links without traversing outside the repository root.
3. **Secret & Build Folder Exclusions:** Automatically skips `.env`, `.env.*`, `.npmrc`, `*.pem`, `*.key`, `*.pfx`, `*.p12`, `payment-config.json`, `*.sqlite*`, `*.db*`, `.git/`, `node_modules/`, `dist/`, `build/`, `out/`, `.output/`, `.plasmo/`, and `extension/`.
4. **Injection-Safe Composite Action:** All GitHub Action inputs are bound strictly via `env:` variables with zero inline shell interpolation.

---

## License

MIT © Tsuji Sound & Contributors
