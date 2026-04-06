# Jobchain

Verifiable employment credentials using W3C standards and Ed25519 signatures.

## What It Does

Jobchain lets employers issue cryptographically signed employment records. No blockchain, no platform, no PDF. Just public key cryptography and DNS.

Your employer signs a JSON document saying you worked there. Anyone can verify the signature by checking the public key hosted on the employer's domain.

## Quick Start

### Install

```bash
cargo install jobchain-cli
```

Or build from source:

```bash
git clone https://github.com/ducks/jobchain
cd jobchain
cargo build --release
```

### Usage

**1. Employer creates an identity**

```bash
$ jobchain init --org "Discourse" --domain discourse.org

Initialized jobchain identity for Discourse
  DID: did:web:discourse.org
  Next: host did.json at https://discourse.org/.well-known/did.json
```

This generates an Ed25519 keypair and a DID document. The public key lives at a well-known URL on the company's domain.

**2. Employer issues a credential**

```bash
$ echo '{"title":"Infrastructure Engineer","company":"Discourse","start":"2024-03"}' \
  | jobchain issue --domain discourse.org > jake-discourse.vc.json
```

That's a W3C Verifiable Credential. Structured JSON, signed with Ed25519. Hand the `.vc.json` file to the employee.

**3. Anyone verifies**

```bash
$ jobchain verify --input jake-discourse.vc.json

VALID -- credential signature verified
  Issuer:  did:web:discourse.org
  Subject: Infrastructure Engineer at Discourse
  Issued:  2026-04-02
```

The verify command fetches the public key from `discourse.org/.well-known/did.json` and checks the signature. No account needed. No API key. Just math.

## Key Features

- **W3C Verifiable Credentials** - Standard format, interoperable
- **Ed25519 signatures** - Fast, secure, widely supported
- **DID:web** - DNS is the trust anchor, no blockchain needed
- **Amendments** - Signed updates for promotions, role changes
- **Static wallet** - Host credentials as plain files on GitHub Pages, Netlify, etc.

## Commands

- `jobchain init` - Generate org identity and keypair
- `jobchain issue` - Sign employment credentials
- `jobchain verify` - Check credential signatures
- `jobchain amend` - Create signed amendments
- `jobchain wallet build` - Generate static HTML wallet

## Architecture

Jobchain is a Cargo workspace with three crates:

- **jobchain-core** - Credential types, Ed25519 signing, DID documents, amendment chains
- **jobchain-verify** - Signature verification (lightweight, future WASM target)
- **jobchain-cli** - The `jobchain` binary

131 tests. All passing.

## The Wallet

Your "wallet" is a folder of `.vc.json` files. Build a static site:

```bash
$ jobchain wallet build --dir ./credentials --out ./site
```

This generates HTML for humans and `index.json` for machines. Push to GitHub Pages and you're done.

## Why Not Blockchain

Blockchain solves one problem jobchain doesn't: persistence after the issuer disappears. If `discourse.org` goes dark, the public key is gone.

But blockchain adds massive complexity for that edge case. Consensus, gas fees, infrastructure. The social problem (getting employers to issue credentials) doesn't change regardless of storage.

DNS is the trust anchor. If persistence matters later, there are simpler solutions: key archival services, IPFS pinning, or embedding the public key in the credential itself.

## Amendments

Credentials aren't static. You get promoted. You change teams.

```bash
$ jobchain amend --credential jake-discourse.vc.json \
    --domain discourse.org \
    --patch '{"title":"Senior Infrastructure Engineer"}' \
    --effective-date 2025-06
```

Each amendment is independently verifiable. The chain forms a linked list: original credential, then amendments, each signed and hash-linked to its predecessor.

## What This Is Not

- **Not a platform** - No service to sign up for, no data to hand over
- **Not self-attested** - Only the employer's private key can produce a valid signature
- **Not a resume** - This is for employer-verified records. [JOBL](https://jobl.dev) handles self-authored resumes.

## Development

```bash
# Run tests
cargo test

# Run CLI locally
cargo run --bin jobchain -- --help

# Build release
cargo build --release
```

## Links

- [Documentation](https://ducks.github.io/jobchain/)
- [JOBL](https://jobl.dev) - Structured resume format
- [whoami-spec](https://github.com/ducks/whoami-spec) - Declarative identity

## License

MIT
