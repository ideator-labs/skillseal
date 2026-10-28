# SkillSeal

Pin an [Agent Skills](https://agentskills.io/specification) folder with content digests, the same integrity shape [MCP SEP-2640](https://modelcontextprotocol.io/seps/2640-skills-extension) already requires for skills served over MCP.

Folder skills from GitHub or a marketplace sit outside that rule today. The Agent Skills format validates frontmatter naming through `skills-ref`, and defines no trust, signing, or install-time digest model ([Employed AI, Oct 25](https://employed-ai.com/articles/anthropic-agent-skills-agentic-ai-foundation-security-guidance-proposal/)). AAIF's Security & Privacy working group has a draft that proposes hash pinning; it is not adopted. Anthropic's Agent Skills donation to [AAIF](https://aaif.io/) on Oct 22 listed security guidance as a proposal, not a published document ([Anthropic](https://www.anthropic.com/news/donating-agent-skills-to-the-agentic-ai-foundation), [AAIF news](https://aaif.io/news/agentic-ai-foundation-announces-four-new-projects)).

SkillSeal writes `skill.seal.json` next to `SKILL.md`: every file gets `{path, digest, size}` with `sha256:<hex>`. `verify` fails on a silent edit, an undeclared file, a removed file, or a broken signature. Digests prove consistency with the seal, not that the content is safe (same claim as SEP-2640).

## Why this has a network effect

Each publisher that ships a seal gives every consumer a free CI check. Each agent or marketplace that refuses unsealed skills raises the cost of shipping unsigned folders. That is the flywheel AAIF's Security & Privacy draft sketches with an "organisational trust registry", applied to the open Agent Skills format.

## Quick start

```bash
go build -o skillseal .
./skillseal seal ./my-skill                 # write skill.seal.json
./skillseal seal ./my-skill --key <seed>    # also Ed25519-sign the inventory
./skillseal verify ./my-skill --require-signature
```

## Demo

```bash
bash demo.sh          # expect RESULT: 9 passed, 0 failed
bash demo.sh --break  # expect 3 failed (inventory check skipped)
```

Needs Go 1.22+. No network, Docker, QEMU, or paid API.

## AAIF path

- Companion to **Agent Skills** (Impact) and the MCP Skills extension (SEP-2640).
- Natural deliverable for the **Security & Privacy** working group (hash pinning is already in their draft).
- Propose via [aaif/project-proposals](https://github.com/aaif/project-proposals) as a Sandbox project, or as an Agent Skills SEP that adds `skill.seal.json` as an optional install artifact.

## Limits

- Digests are consistency, not safety. A sealed malicious skill still verifies.
- Ed25519 keys are raw seed hex for the POC; no key directory or Sigstore yet.
- Frontmatter checks cover name, description, and directory match only (not the full `skills-ref` surface).
- Does not scan script behaviour. Pair with a content scanner for that.

## License

Apache-2.0
