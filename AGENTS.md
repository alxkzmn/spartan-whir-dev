# spartan-p3 Workspace -- Agent Instructions

## Current Work: Solidity Verifier for Spartan-WHIR

The primary active task is building a Solidity (EVM) verifier for the Spartan-WHIR SNARK. The canonical root document lives at:

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
- Transcript byte-level compatibility between Rust and Solidity is the single highest correctness risk. If the Solidity challenger produces even one different byte during observe or sample operations, every subsequent challenge will diverge and the proof will be rejected.

### Proof format

- The Rust proof is encoded via `codec_v1.rs` as the full Spartan binary blob format.
- The standalone-WHIR Solidity verifier has three paths:
  - **Native blob verifier** (`WhirBlobVerifierNative4`): production path. Reads the fixed-shape quartic blob directly from calldata.
  - **Typed ABI verifier** (`WhirVerifier4`): parity/test path. Uses `abi.encode`/`abi.decode` for debuggability.
  - **Blob decode-and-delegate wrapper** (`WhirBlobVerifier4`): decodes the blob into typed structs, then delegates to the typed verifier.
- The blob layout mixes encoding conventions on purpose (transcript-native LE for sections fed to the challenger, big-endian or packed for Merkle sections). Don't reorganize for consistency — the layout is optimized for gas. Any changes need benchmarking.
- Full-Spartan blob support (encoding the outer Spartan proof + WHIR together) is still later-stage work. The current blob is standalone-WHIR only.

## Rules for This Workspace

### What belongs in AGENTS.md

This file should contain **gotchas, non-obvious decisions, and tool/workflow instructions** — things that prevent the agent from repeating past mistakes or rediscovering working patterns. It should NOT contain:

- Measurements, gas numbers, test counts, or other facts about current state that change after every optimization or refactor. Use the root `README.md` for that, or provide commands to obtain them.
- Descriptions of what the code does (the code is the source of truth for that).

Exception: temporary tool issues that need workarounds. These should include instructions for how to detect when the issue is fixed, and a note to update this file when it is (e.g., "Foundry flamegraphs crash on deep call trees — if this stops happening, remove this caveat").

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

### Verification-facing changes are protocol surface

Any change to transcript ordering, proof encoding, digest layout, Merkle hashing, or domain separator construction will break the Solidity verifier if not mirrored there. These are protocol-level changes. When making such a change, state explicitly which Solidity components are affected and what needs to be updated.

### Dated "current state" sections must keep their dates in sync

If a section title or label says "current" and also includes a date, treat that date as part of the maintained content. When you update the contents of that section, update the date too. Do not leave a stale date attached to fresh numbers or conclusions.

### Exporter runs: always use release mode

The fixture exporter does real proving work and can be very slow in debug builds. When regenerating fixtures or generated Solidity from `spartan-whir-export`, always run the exporter in release mode:

- `cargo run --release -p spartan-whir-export --bin export-fixtures -- <output-dir>`

Do not use the debug `cargo run` path for normal fixture regeneration unless you are intentionally debugging the exporter itself.

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

Changing Rust to `ConstantFromSecondRound` is a protocol-surface change: it changes the derived round schedule, WHIR Fiat-Shamir pattern, and fixed-config verifier constants. Do not change the folding-factor variant without following the schedule-tuning process in `./README.md` and regenerating all affected fixtures/generated code.

## Gas Profiling with Forge Flamegraphs

### Overview

Foundry supports:

- `--flamegraph`: aggregated by function. This is usually the better first tool for optimization work because it answers "where does total gas go?"
- `--flamechart`: chronological / call-tree ordered. Use this after the hotspot is known and you need to understand call structure or sequencing.

Both generate SVGs in `./sol-spartan-whir/cache/`.

**Foundry flamegraph caveat:** `--flamegraph` and `--flamechart` can crash on tests with deep call trees (Foundry bug in trace decoding, not an OOM). If a test crashes, use a smaller/focused test. Prefer `--flamegraph` over `--flamechart` — it's more useful and more stable.

### Reading SVGs Programmatically

Flamegraph SVGs are XML text. Do NOT try `view_image` — it rejects SVGs. Instead parse with:

```bash
python3 -c "
import re
with open('cache/flamegraph_WhirGasProfileTest_testProfileStirBreakdown.svg') as f:
    content = f.read()
entries = re.findall(r'<title>([^<]+)\(([0-9,]+) gas, ([0-9.]+)%\)</title>', content)
parsed = [(name.strip(), int(gas.replace(',','')), float(pct)) for name, gas, pct in entries]
parsed.sort(key=lambda x: -x[1])
for name, gas, pct in parsed:
    print(f'{gas:>10,}  {pct:>5.1f}%  {name}')
"
```

This extracts every function with its cumulative gas and percentage, sorted by cost. Note that flamegraphs show the same function multiple times if it appears in different call stacks — aggregate manually if needed.

Foundry writes useful `<title>` tags into both flamegraphs and flamecharts. They include function name, cumulative gas, and percentage. This makes scripted extraction viable even when viewing the SVG manually is inconvenient.

### Profiling Infrastructure in `test/WhirGasProfile.t.sol`

The file contains two contracts:

- **`WhirProfileHarness`**: Deployed contract with `view` functions that replicate verifier logic with `gasleft()` instrumentation. Key functions:
  - `profileFullBreakdown()` — returns `FullBreakdown` struct with gas for each verifier phase (setup, sumchecks, STIR rounds, constraints, final check). This is the canonical top-level breakdown.
  - `profileStirBreakdowns()` — returns per-round `StirBreakdown` structs splitting STIR into: `sampleQueries`, `leafHashing`, `merkleReduction`, `pow`, `rowFolding`, `overhead`.
  - `profileStirMicro()` — micro-benchmarks for atomic operations (hashLeafBaseSlice, compressNode, KoalaBear.pow, sampleStirQueries). Uses 100-iteration loops for stable measurements.
  - Various `profileSynthetic*` functions for isolated constraint evaluation testing.

- **`WhirGasProfileTest`**: Test contract that calls harness functions and logs results. Key tests:
  - `testProfileFullBreakdown` — logs full verifier phase breakdown
  - `testProfileStirBreakdown` — logs per-round STIR internals
  - `testProfileStirMicro` — logs micro-benchmark results
  - `testGasWhirVerifyFixed` — canonical single-number gas measurement

### How to get gas numbers

- **Single canonical gas number**: `forge test --match-test testGasWhirVerifyFixed -vv`
- **Phase-level breakdown** (setup, sumchecks, STIR, constraints, final check): `forge test --match-test testProfileFullBreakdown -vv`
- **Per-round STIR internals** (sampleQueries, leafHashing, merkleReduction, pow, rowFolding): `forge test --match-test testProfileStirBreakdown -vv`
- **Micro-benchmarks** (hashLeafBaseSlice, compressNode, KoalaBear.pow, sampleStirQueries): `forge test --match-test testProfileStirMicro -vv`

Do not hardcode gas numbers in AGENTS.md — they go stale after every optimization. Always measure.

### Flamegraph vs `gasleft()` profiling

1. Run `gasleft()` tests first (`testProfile*`) to identify which phase to investigate.
2. Then flamegraph that phase to see function-level breakdown _within_ it. Flamegraphs are good for finding hidden overhead the profiling harness doesn't decompose.
3. Use `--flamechart` only when you already know the hotspot and need to understand call sequencing.

For cleaner flamegraphs, prefer synthetic or harness-level tests that isolate one verifier phase. Tests that call `_loadSuccessFixture()` include 5–25% harness noise.

### Optimization Validation Workflow

1. Run `forge test` — the full Solidity suite must pass
2. Run `forge test --match-test testGasWhirVerifyFixed -vv` — get the single canonical gas number
3. Run `forge test --match-test testProfileFullBreakdown -vv` — verify phase-level breakdown
4. Compare against previous numbers to confirm the delta matches expectations

### Warning: `via_ir` and Optimization Interactions

The Solidity compiler with `via_ir = true` (used in this project) is aggressive about inlining and eliminating dead code. Many "obvious" optimizations yield much less than estimated because the compiler was already doing something similar. Always benchmark before and after — never trust gas estimates alone. Previous examples of surprises:

- Low-level ext4 mul rewrite: expected -50k, actual **+208k** (compiler was already optimizing the high-level version better)
- Batch sumcheck validation: expected -5k, actual **+4.7k** (extra memory allocation outweighed saved checks)

**How to measure total tx gas** (run from `sol-spartan-whir/`):

```bash
# 1. Start anvil
anvil --silent          # mode=async

# 2. Run the benchmark script (native blob verifier)
forge script script/WhirBlobNativeTxBenchmark.s.sol \
  --rpc-url http://127.0.0.1:8545 --broadcast --slow \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# 3. Parse results
python3 parse_tx_gas.py direct

# 4. Kill anvil
pkill -f "anvil"
```

`parse_tx_gas.py` prints total tx gas, intrinsic, calldata gas (with byte counts), and execution remainder. Supports `direct` (EOA → verifier) and `wrapper` (EOA → wrapper → verifier) modes.

Other benchmark scripts: `WhirTxBenchmark.s.sol` (typed verifier), `MeasureTxGas.s.sol` (wrapper tx — needs `--tc MeasureTxGas`).

Key gotcha: **`--private-key` is required.** Without it, Foundry silently produces empty receipts.

## Implementation Stages (Summary)

See `./README.md` for full details.
