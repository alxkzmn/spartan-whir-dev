# spartan-p3 Workspace -- Agent Instructions

## Current Work: Solidity Verifier for Spartan-WHIR

The primary active task is building a Solidity (EVM) verifier for the Spartan-WHIR SNARK. The canonical root document is:

- **`./README.md`** -- this is the canonical, reviewed root document for the verifier work. If you need to make changes to the project plan, always write them to `./README.md` so it stays current.

Read the root README before starting any implementation work. It contains frozen ABI schemas, locked architectural decisions, stage sequencing, source-of-truth boundaries, and risk notes that have been reviewed across multiple rounds of expert review.

## Workspace Layout

This workspace contains several sibling projects. They serve different roles:

| Directory                | Role                                                                                                                                                                                                                         | Status              |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| `./spartan-whir/`        | Rust SNARK implementation (Spartan + WHIR PCS over KoalaBear). **Source of truth** for all verification logic.                                                                                                               | Active development  |
| `./whir-p3/`             | Rust WHIR library. PCS backend used by `spartan-whir`. Contains the WHIR verifier, sumcheck, Merkle multiproof, and config derivation logic.                                                                                 | Active dependency   |
| `./Plonky3/`             | Vendored Plonky3 library. Contains KoalaBear field definition and extension field arithmetic.                                                                                                                                | Vendored, read-only |
| `./spartan-whir-export/` | Rust crate for fixture export and Solidity code generation. Depends on `spartan-whir` + `alloy-sol-types`. Produces ABI-encoded test fixtures and template-specialized Solidity files.                                       | Active development  |
| `./sol-spartan-whir/`    | Foundry project for the Solidity verifier.                                                                                                                                                                                   | Active development  |
| `./sol-whir/`            | Legacy Solidity WHIR verifier over BN254. **Structural reference only** (project layout, gas harness, Merkle queue pattern, test patterns). Do NOT use as a logic source -- its WHIR state machine does not match `whir-p3`. | Reference only      |
| `./whir-old/`            | Legacy Rust WHIR implementation (BN254). **Workflow reference only** for fixture export pipeline structure. Not a schema or logic reference.                                                                                 | Reference only      |

## Key Technical Context

### What is Spartan-WHIR?

- **Spartan**: R1CS-based SNARK. Reduces constraint satisfaction to polynomial evaluation claims via two sumcheck protocols (outer cubic, inner quadratic).
- **WHIR**: Polynomial commitment scheme based on Reed-Solomon proximity testing. Uses iterative folding rounds with Merkle commitments, OOD sampling, STIR queries, and folding sumchecks.
- The full SNARK: Spartan reduces R1CS to a single polynomial opening claim, WHIR opens that claim.

### Field

- Base field: **KoalaBear** (p = 2^31 - 2^24 + 1, a 31-bit prime from Plonky3).
- Extension fields: degree-4 (quartic) or degree-8 (octic) binomial extensions, both using irreducible X^d - 3 (W = 3).
- The small field (31-bit) enables EVM gas savings: base-field products are 62 bits, so many can be accumulated in a `uint256` before modular reduction.

### Transcript / Fiat-Shamir

- `spartan-whir` defines its own Keccak challenger (`CanonicalSerializingChallenger32` in `canonical_challenger.rs`) that observes field elements in canonical form (`as_canonical_u32().to_le_bytes()`). It satisfies the same `FieldChallenger` trait that `whir-p3` requires, without modifying vendored Plonky3.
- Spartan domain separator: `keccak256(DomainSeparator::to_bytes())` produces a 32-byte hash that is observed into the challenger. The raw 76-byte preimage is NOT observed directly.
- WHIR domain separator: a `Vec<F>` pattern of field elements observed via `challenger.observe_slice(...)`.
- See `./sol-spartan-whir/AGENTS.md` for Solidity transcript-compatibility rules.

### Proof format

See `./sol-spartan-whir/AGENTS.md` for Solidity verifier proof-format paths, blob-layout rules, and EVM compatibility constraints.

## Rules for This Workspace

### What belongs in AGENTS.md

This file should contain **gotchas, non-obvious decisions, and tool/workflow instructions** — things that prevent the agent from repeating past mistakes or rediscovering working patterns. It should NOT contain:

- Measurements, gas numbers, test counts, or other facts about current state that change after every optimization or refactor. Use the root `README.md` for that, or provide commands to obtain them.
- Descriptions of what the code does (the code is the source of truth for that).

Exception: temporary tool issues that need workarounds. These should include instructions for how to detect when the issue is fixed, and a note to update this file when it is (e.g., "Foundry flamegraphs crash on deep call trees — if this stops happening, remove this caveat").

### Skills are the detailed workflow docs

Detailed workflow guides live under `./sol-spartan-whir/.agents/skills/*/SKILL.md`. See `./sol-spartan-whir/AGENTS.md` for the full list and for Solidity-specific optimization workflows.

Use `AGENTS.md` files for rules and non-obvious guidance. Use the skill files for step-by-step operational workflows.

### Use `####` headers in user-facing documents

Markdown files shared with humans (READMEs, design docs) should use 4th-level headers (`####`) to break up long `###` sections. This makes it possible to link someone directly to a specific subsection instead of saying "scroll down a bit." Do not avoid `####` out of style preference.

### Do not invent abbreviations or acronyms

Use existing names from the codebase. Do not coin new abbreviations for blob formats, verifier paths, or protocol variants. Invented acronyms are hard to search for, confuse readers, and never appear in the actual code.

### Write docs like a human maintainer, not an optimization log

When writing READMEs, design docs, or long-form explanations, prefer normal human labels and sentences over internal shorthand. If a phrase would sound strange when spoken aloud to another engineer, rewrite it.

Avoid labels like:

- "local-diff"
- "size-first"
- "follow-up pass"
- "wrapper reclaim"
- "production-path snapshot"
- "current best path"

Prefer plain language instead:

- "current state"
- "wrapper verifier"
- "native verifier"
- "bytecode reduction"
- "measured result"
- "recommended deployment target"

Technical precision still matters, but the default should be readable prose, not commit-log jargon.

### Dated "current state" sections must keep their dates in sync

If a section title or label says "current" and also includes a date, treat that date as part of the maintained content. When you update the contents of that section, update the date too. Do not leave a stale date attached to fresh numbers or conclusions.

### Solidity verifier rules live with the Solidity repo

Solidity-only rules now live in `./sol-spartan-whir/AGENTS.md`, including:

- fixture/exporter command conventions
- source-of-truth anchors for verifier logic and field arithmetic
- EVM compatibility rules
- Keccak Merkle prefix requirements
- extension-degree and folding-schedule constraints
- gas profiling, tx benchmarking, and `via_ir` workflows

## Solidity Verifier Workflows

For gas profiling, optimization workflows, validation gates, and `via_ir` interaction warnings, see `./sol-spartan-whir/AGENTS.md`.

Skill files for step-by-step operational workflows:

- `./sol-spartan-whir/.agents/skills/forge-flamegraph-profiling/SKILL.md`
- `./sol-spartan-whir/.agents/skills/tx-gas-benchmarking/SKILL.md`

## Implementation Stages (Summary)

See `./README.md` for full details.
