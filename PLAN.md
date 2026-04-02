# Jobchain

Verifiable employment credentials. Built on [jobl](https://jobl.dev) for the resume format, adds cryptographic signatures and tooling for issuers, holders, and verifiers.

## Problem

The employment verification pipeline is broken:
- Resumes are self-authored PDFs with no proof
- ATSes OCR PDFs back to text, losing structure
- Background checks are slow, expensive, and binary (pass/fail)
- Previous VC attempts (Blockcerts, LinkedIn verified creds) died because they needed all three sides to adopt simultaneously

## Core Idea

Credentials are created at **onboarding**, not exit. They accumulate over the course of employment — title changes, team moves, project milestones — as signed amendments. By departure, the credential is already complete.

The "wallet" is just a **static site** (GitHub Pages, any hosting). A folder of signed JSON files. Trust comes from signatures, not hosting.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   ISSUERS                        │
│                                                  │
│  HR System ──→ Adapter ──→ Signed Credential     │
│  (BambooHR,    (plugin)    (W3C VC / JSON-LD)   │
│   Gusto, etc)                                    │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│                   HOLDER                         │
│                                                  │
│  Static site / git repo of signed credentials    │
│  + jobl file (self-authored resume)              │
│  jake.dev/credentials/                           │
│    ├── resume.jobl                               │
│    ├── discourse-2024-2026.vc.json               │
│    ├── github-contributions.vc.json              │
│    └── index.json (manifest)                     │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│                  VERIFIERS                       │
│                                                  │
│  ATS / Hiring manager / Anyone                   │
│  Fetches credentials, verifies signatures        │
│  Machine-readable, no PDF parsing                │
└─────────────────────────────────────────────────┘
```

## Components

### 1. Credential Format

W3C Verifiable Credentials (JSON-LD) wrapping jobl-structured data.

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "EmploymentCredential"],
  "issuer": "did:web:discourse.org",
  "issuanceDate": "2024-03-15",
  "credentialSubject": {
    "type": "EmploymentRecord",
    "title": "Infrastructure Engineer",
    "company": "Discourse",
    "start": "2024-03",
    "technologies": ["Ruby", "JavaScript"],
    "highlights": [...]
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:web:discourse.org#key-1",
    "proofValue": "..."
  }
}
```

### 2. CLI (`jobchain`)

Rust binary. Core commands:

```bash
# Issuer: initialize org keypair
jobchain init --org "Discourse" --domain discourse.org

# Issuer: create credential from template or interactively
jobchain issue --employee "Jake Goldsborough" \
  --title "Infrastructure Engineer" \
  --start 2024-03

# Issuer: amend existing credential (title change, etc.)
jobchain amend discourse-2024.vc.json \
  --title "Senior Infrastructure Engineer" \
  --effective 2025-06

# Holder: verify a credential
jobchain verify discourse-2024.vc.json

# Holder: build wallet (static site from credentials dir)
jobchain wallet build --dir ./credentials --out ./site

# Holder: import jobl resume into wallet
jobchain wallet add resume.jobl
```

### 3. Adapters

Plugins that hook into HR/dev tools and emit credentials on events. Start with one, expand later.

**Phase 1 — Manual / CLI-driven:**
- Issuer uses `jobchain issue` directly
- Good enough for dogfooding at Discourse

**Phase 2 — GitHub adapter:**
- Watches org membership + contribution events
- Issues attestations: "Jake contributed to discourse/discourse, 247 commits, 2024-2026"
- Lightweight — GitHub API, cron job or webhook

**Phase 3 — HR adapters:**
- BambooHR / Gusto / Rippling webhooks
- On hire: issue base credential
- On title change: amend credential
- On departure: finalize credential

**Future:**
- Jira / Linear — project participation
- Slack / Teams — team membership
- Learning platforms — certifications

### 4. Wallet (Static Site Generator)

Takes a directory of `.vc.json` files + optional `resume.jobl`, generates:
- `index.html` — human-readable credential list with verification status
- `index.json` — machine-readable manifest for ATS consumption
- Individual credential pages with verify button
- Deployable to GitHub Pages, Netlify, any static host

### 5. Verification Library

Rust crate (`jobchain-verify`) that can:
- Resolve issuer DIDs (`did:web:` to start — just a URL)
- Fetch public keys
- Verify Ed25519 signatures
- Check credential structure against jobl schema
- Embeddable in other tools / ATS integrations

## Identity / Key Management

Use `did:web` for issuer identity — simplest DID method, just a URL:
- `did:web:discourse.org` resolves to `https://discourse.org/.well-known/did.json`
- Company hosts their public key at that URL
- No blockchain required, DNS is the trust anchor
- Can migrate to other DID methods later if needed

Ed25519 for signatures — fast, small, well-supported.

## Implementation Phases

### Phase 1: Foundation (dogfood at Discourse)
- [ ] `jobchain init` — generate org keypair, output `did.json`
- [ ] `jobchain issue` — create signed credential from CLI input
- [ ] `jobchain verify` — verify a credential's signature
- [ ] Credential format spec (W3C VC subset)
- [ ] `did:web` resolver (fetch and parse `did.json`)
- [ ] Issue first real credential at Discourse

### Phase 2: Wallet
- [ ] `jobchain wallet build` — static site generator
- [ ] `index.json` manifest format
- [ ] GitHub Pages deployment example
- [ ] jobl integration (resume alongside credentials)

### Phase 3: Amendments & History
- [ ] `jobchain amend` — signed amendments to existing credentials
- [ ] Credential chain (base → amendments, all independently verifiable)
- [ ] Revocation support (issuer can revoke a credential)

### Phase 4: GitHub Adapter
- [ ] GitHub org membership watcher
- [ ] Contribution attestation generator
- [ ] Webhook or cron-based automation

### Phase 5: HR Adapters
- [ ] Adapter interface/trait definition
- [ ] BambooHR adapter (or whatever Discourse uses)
- [ ] Onboarding → credential creation flow

## Tech Stack

- **Language:** Rust (matches jobl, whoami-spec)
- **Signing:** Ed25519 (via `ed25519-dalek` or `ring`)
- **Serialization:** JSON-LD / serde_json
- **DID resolution:** HTTP client (`reqwest`)
- **Static site:** HTML templates (minimal, no framework)
- **jobl integration:** `jobl` crate as dependency

## Open Questions

- Should the wallet manifest follow a standard (e.g., DIF Credential Manifest)?
- How to handle credential portability if a company disappears (key gone, `did:web` unreachable)?
- Should holders be able to selectively disclose parts of a credential (zero-knowledge proofs)?
- How to incentivize the first wave of issuers beyond Discourse?

## Relationship to Other Projects

- **jobl** — resume format, self-authored structured data. Jobchain credentials *wrap* jobl-shaped data with signatures.
- **whoami-spec** — personal identity file. Complementary — whoami is narrative ("who I say I am"), jobchain is attestation ("what others confirm").
