# AGENTS.md: SkillSeal handoff

## What this is and the claim

A Go CLI that pins an Agent Skills folder with SEP-2640-style `{path, digest, size}` entries and optional Ed25519 signatures. Claim: after `seal`, any silent edit to `SKILL.md` or a script, any undeclared file, any removed sealed file, or a flipped signature makes `verify` exit 1. Digests prove consistency with the seal, not trust in the content.

## Status

Real:
- Walks the skill tree, hashes raw bytes with SHA-256, writes `skill.seal.json`.
- Frontmatter gate: required `name` + `description`, directory name must match `name` (Agent Skills spec rules).
- Optional Ed25519 signature over a canonical inventory (sorted `path\0digest\0size\n`).
- Demo fixture is a valid Agent Skills layout (`SKILL.md`, `scripts/`, `references/`).
- `bash demo.sh` 9/9; `--break` (`--ignore-digest`) fails checks 3, 4, 5.

Stubbed / not built:
- No Sigstore / key directory / publisher registry.
- No marketplace install hook.
- No behavioural script scan (paths like `~/.aws` are out of scope).
- Frontmatter is a minimal parser, not `skills-ref`.

## Data shape

```
Seal {
  specVersion: "skillseal/0.1"
  name: string          # from SKILL.md frontmatter
  sealedAt: RFC3339
  files: [{path, digest: "sha256:<hex>", size}]
  publisher?: hex(ed25519 public key)
  signature?: hex(ed25519 sig over CanonicalBytes(files))
}
```

Aligned with MCP SEP-2640 resource integrity fields (`digest`, `size`), using relative paths instead of `skill://` URIs because the target is a filesystem folder.

## Repo map

- `main.go`: `seal`, `verify`, `show`, `keygen`. Exit 0 ok, 1 integrity failure, 2 bad input. `--ignore-digest` is the deliberate break switch.
- `seal.go`: walk, hash, compare, sign, frontmatter gate.
- `fixtures/invoice-reconcile/`: demo skill (Python check script is a labelled stub).
- `demo.sh`: the artifact. 9 checks plus `--break`.
- `seal_test.go`: round-trip, tamper, name/dir mismatch.

## Fresh clone: setup, run, verify

```
git clone https://github.com/ideator-labs/skillseal && cd skillseal
go test ./...
bash demo.sh                  # expect "RESULT: 9 passed, 0 failed", exit 0
bash demo.sh --break          # expect "RESULT: 6 passed, 3 failed", exit 1
```

Needs Go 1.22+ (tested with Go 1.27.3). No Docker, QEMU, network, or paid API.

## Design decisions

- Reuse SEP-2640's digest+size inventory rather than invent a new integrity model. Folder skills get the same consistency guarantee MCP-served skills already have.
- Sign the inventory, not each file. One signature covers add/remove/change.
- Exclude `skill.seal.json` from the walk so resealing is stable.
- `--ignore-digest` exists only so `demo.sh --break` proves the inventory check is load-bearing.

## Limits

- Consistency ≠ safety. Pair with content scanning for ToxicSkills-class findings.
- No publisher identity beyond a raw public key hex.
- Minimal frontmatter parser (name, description, dir match). Full `skills-ref` parity is a next step.
- Single-skill seal. No multi-skill lockfile for a repo's `.agents/skills` tree yet.

## Next steps (prioritized, each with done-when)

1. Multi-skill lockfile for a skills directory. Done when `seal-tree` writes one inventory covering every child skill and `verify-tree` fails on any child drift.
2. `skills-ref` parity for frontmatter. Done when a skill that fails `skills-ref validate` also fails `skillseal seal` for the same reason.
3. Sigstore keyless signing. Done when `seal --sigstore` produces a bundle a second machine verifies without a shared seed.
4. AAIF proposal draft. Done when a Sandbox proposal issue is opened against `aaif/project-proposals` linking this repo and the Security & Privacy draft's hash-pinning tier.
