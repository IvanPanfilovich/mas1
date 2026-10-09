# Exact MAS1 v6.1 setup

The source prompt in `prompts/MAS1-v6.1-canonical.md` is byte-identical to the latest local canonical source found for this release. `profiles/codex-reference/` contains all twelve matching original Codex profiles. `VERSION.json` records their source hashes.

## Prerequisites and installation

Use a Codex runtime that supports standalone custom agents. Verify account access to every needed model and reasoning level; original profiles refer to GPT-5.6 Sol/Terra/Luna, GPT-6 Astra and GPT-5.3 Codex Spark. No package can grant that access. Do not silently substitute models for mandatory gates.

Copy needed reference profiles into your project's `.codex/agents/`, preserving their names and inspecting conflicts first. Add a project `AGENTS.md` instruction that resolves **MAS1 canonical v6.1** to the absolute path of `prompts/MAS1-v6.1-canonical.md` in your clone, reads it fully before use, and treats `<clone>/tools/analyze-mas1-ledgers.py` as the location of the original source-machine analyzer path. This is a path relocation only, not a workflow change. Keep this trigger distinct from **MAS1 portable**.

Open a fresh session and verify the actual profile/model/effort and permissions when dispatching; a file on disk does not prove runtime loading. Follow the canonical prework and execution rules. If a required route or independent context is missing, affected mutation/readiness remains blocked as specified by the source protocol.

## Ledgers and rollouts

Read section 8 of the canonical prompt and the schema before constructing an adopter ledger and marker. Use exactly one UUID/runtime-thread task directory; bind canonical paths and timestamps; record actual telemetry or explicit unknowns. Do not reuse synthetic fixture identities or source-machine cutovers as real adoption evidence.

The public package does not ship private source task witnesses, historical migration payloads or rollout master files. It cannot reproduce or certify the original deployment. Canonical analysis of a new rollout requires a new authorized frozen dispatch population and actual adoption/runtime evidence.

The public tools retain the single production validator and invalidated-cutover catalogue. Source-machine-specific historical migration support remains in the code for compatibility but is not a setup step for new users. Its private evidence is deliberately unavailable here.
