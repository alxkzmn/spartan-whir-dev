# spartan-p3 Workspace -- Agent Instructions

## Current Work: Solidity Verifier for Spartan-WHIR

The primary active task is building a Solidity (EVM) verifier for the Spartan-WHIR SNARK. The full implementation plan lives at:

- **`./solidity_verifier_plan.md`** -- this is the canonical, reviewed plan.

If you need to make changes to the plan, copy `./solidity_verifier_plan.md` into your own planning system first, then modify from there. Always write changes back to `./solidity_verifier_plan.md` so the workspace copy stays current.

Read the plan file before starting any implementation work. It contains frozen ABI schemas, locked architectural decisions, stage sequencing, source-of-truth boundaries, and risk notes that have been reviewed across multiple rounds of expert review.

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

- Uses Keccak-based challenger: `SerializingChallenger32<KoalaBear, HashChallenger<u8, Keccak256Hash, 32>>`.
- Spartan domain separator: `keccak256(DomainSeparator::to_bytes())` produces a 32-byte hash that is observed into the challenger. The raw 76-byte preimage is NOT observed directly.
- WHIR domain separator: a `Vec<F>` pattern of field elements observed via `challenger.observe_slice(...)`.
- Transcript byte-level compatibility between Rust and Solidity is the single highest correctness risk. If the Solidity challenger produces even one different byte during observe or sample operations, every subsequent challenge will diverge and the proof will be rejected.

### Proof format

- The Rust proof is encoded via `codec_v1.rs` as an `SPWB` binary blob.
- For the Solidity verifier, the first correctness path uses typed ABI encoding (`abi.encode`/`abi.decode`), not the binary blob.
- The binary blob wrapper is added later as a calldata optimization.

## Rules for This Workspace

### Verification-facing changes are protocol surface

Any change to transcript ordering, proof encoding, digest layout, Merkle hashing, or domain separator construction will break the Solidity verifier if not mirrored there. These are protocol-level changes. When making such a change, state explicitly which Solidity components are affected and what needs to be updated.

### Source-of-truth boundaries

- **Verification logic**: `./spartan-whir/src/protocol.rs`, `./spartan-whir/src/whir_pcs.rs`, `./whir-p3/src/whir/verifier/mod.rs`.
- **Field arithmetic**: `./Plonky3/koala-bear/src/koala_bear.rs`, `./Plonky3/field/src/extension/binomial_extension.rs`.
- **Hashing**: `./spartan-whir/src/hashers.rs`.
- **Merkle multiproof**: `./whir-p3/src/whir/merkle_multiproof.rs`.
- **Proof types**: `./whir-p3/src/whir/proof.rs`.
- **Config derivation**: `./whir-p3/src/whir/parameters.rs`.
- **Domain separator**: `./spartan-whir/src/domain_separator.rs`, `./whir-p3/src/fiat_shamir/domain_separator.rs`.
- **Structural patterns only**: `./sol-whir/` (Foundry layout, gas harness, Merkle queue structure).

### EVM verifier compatibility takes priority

The `spartan-whir` crate has its own `AGENTS.md` with detailed rules. The key constraint for this workspace: changes that make EVM verification harder, less efficient, or incompatible with the current plan should be rejected, even if they improve other aspects of the system (code cleanliness, Rust abstraction quality, prover performance, etc.).

### The `keccak_no_prefix` feature flag must stay disabled

The Solidity verifier assumes Keccak hashing with domain-separation prefix bytes (`0x00` for leaves, `0x01` for nodes). Enabling the `keccak_no_prefix` feature flag would remove these prefixes and silently break every Merkle verification in the Solidity verifier. Do not enable it.

### Extension degree: quartic first, octic required

The Solidity verifier architecture supports both extension degrees from the start. Quartic (degree 4) is implemented first because it has fewer coefficients and is easier to debug. Octic (degree 8) is needed for full algebraic security and must pass all tests before the Spartan verifier stage is considered complete. Both use the irreducible polynomial X^d - 3.

### Folding Schedule

`spartan-whir` currently hardcodes `FoldingFactor::Constant(...)` when building the WHIR config (see `whir_pcs.rs` line 311). The Solidity plan now targets a **schedule-generic verifier core** from the first implementation: the runtime-config verifier should consume the derived per-round schedule from exported config data instead of assuming a constant folding factor in code.

Changing Rust to `ConstantFromSecondRound` is a protocol-surface change: it changes the derived round schedule, WHIR Fiat-Shamir pattern, and fixed-config verifier constants. Do not change the folding-factor variant without following the schedule-tuning process in `./solidity_verifier_plan.md` and regenerating all affected fixtures/generated code.

## Implementation Stages (Summary)

See `./solidity_verifier_plan.md` for full details.
