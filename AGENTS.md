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

## Gas Profiling with Forge Flamegraphs

### Overview

Foundry supports:

- `--flamegraph`: aggregated by function. This is usually the better first tool for optimization work because it answers "where does total gas go?"
- `--flamechart`: chronological / call-tree ordered. Use this after the hotspot is known and you need to understand call structure or sequencing.

Both generate SVGs in `./sol-spartan-whir/cache/`.

### Foundry Bug: Large Test Crash

In the current toolchain, both `--flamegraph` and `--flamechart` can crash with `capacity overflow` or `memory allocation of ... bytes failed` on deep verifier traces. The crash occurs _after_ the test passes, during trace decoding. This is a Foundry bug, not an OOM in verifier code.

This is **not** a simple gas threshold. It is shape-dependent:

- some `~1.5M` gas tests work (`testProfileStirBreakdown`)
- some `~0.75M` gas tests still crash (`testFlameRound0Stir`)
- the common factor is deep / complex decoded call trees, especially Merkle-heavy paths

**Tests that crash:**

- `testVerifyQuarticWhirSuccessFixture` (~1.9M gas)
- `testProfileFullBreakdown` (~1.9M gas)
- `testFlameRound0Stir`, `testFlameRound1Stir`, `testFlameFinalStir` (isolated STIR rounds with deep Merkle call trees)
- `testFlameConstraintEvaluation` (~1.9M gas)

**Tests that work:**

- `testProfileStirBreakdown` (~1.5M gas) -- combined STIR profile, the largest stable flamegraph/flamechart target so far
- `testFlameSyntheticEqConstraint` (~330k gas) -- eq constraint only
- `testFlameSyntheticSelectConstraint` (~251k gas) -- select constraint only

**Workaround:** Break profiling code into smaller focused tests. If a test crashes, it's too deep — split it or use a synthetic test with fewer queries/depth.

**Practical advice:** Prefer `--flamegraph` first. In practice it has been more useful and at least as stable as `--flamechart` on the current hotspot tests.

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

### Interpreting Results

**Key cost relationships (16-var, 2-round, foldingFactor=4 fixture):**

| Component           | Gas     | Notes                                                                                       |
| ------------------- | ------- | ------------------------------------------------------------------------------------------- |
| Total verify        | ~1,199k | `testGasWhirVerifyFixed`                                                                    |
| STIR (all 3 rounds) | ~575k   | 48% of total. Dominated by merkleReduction and rowFolding (both already assembly-optimized) |
| Constraint eval     | ~191k   | 16% of total. eq-poly and select-poly evaluation                                            |
| Sumchecks (all 4)   | ~112k   | 9% of total. ~27-31k per sumcheck round                                                     |
| Setup               | ~67k    | observePattern + parseCommitment                                                            |

**Per-query STIR costs:**

- Row folding: ~10.8-13.5k/query (fold schedule varies by round) — already assembly-optimized
- Merkle reduction: ~18.2-18.7k/query (depth×compressNode + index logic overhead) — already assembly-optimized
- Leaf hashing: 4.9k (base) or 7.2k (ext4) per query — already assembly-optimized

### Flamegraph vs `gasleft()` Profiling

- **`gasleft()` profiling** (the `testProfile*` tests): Precise per-phase gas. Best for tracking optimization progress and measuring specific changes. Run with `forge test --match-test <name> -vv`.
- **Flamegraph**: Shows function-level breakdown _within_ a phase. Best for finding unexpected costs (e.g., `_maskDigestTail` at 40k or `_clampEffectiveDigestBytes` at 17k — pure overhead discovered only via flamegraph). Use when you need to know _why_ a phase is expensive.
- **Flamechart**: Shows the chronological call tree. Use when the hotspot is already known and you want to understand sequencing or caller/callee nesting.

Always run `gasleft()` tests first to identify which phase to investigate, then flamegraph that phase (or the largest stable test covering it).

### Minimize Profiling Noise

Focused profiling targets are much better than full verifier traces.

- Tests that call `_loadSuccessFixture()` include harness noise in the graph. On some focused tests this is still 5%–25% of total gas.
- Prefer synthetic or harness-level tests that isolate one verifier phase.
- If a profiling target is still too noisy, create a dedicated test that preloads data in `setUp()` or hardcodes the minimal inputs needed for that phase.
- `testFlameSyntheticEqConstraint` and `testFlameSyntheticSelectConstraint` are currently the cleanest flamegraph targets for constraint work.
- `testProfileStirBreakdown` is currently the best stable target for STIR analysis when the isolated STIR flamegraphs crash.

### Optimization Validation Workflow

1. Run `forge test` — all 69 tests must pass
2. Run `forge test --match-test testGasWhirVerifyFixed -vv` — get the single canonical gas number
3. Run `forge test --match-test testProfileFullBreakdown -vv` — verify phase-level breakdown
4. Compare against previous numbers to confirm the delta matches expectations

### Warning: `via_ir` and Optimization Interactions

The Solidity compiler with `via_ir = true` (used in this project) is aggressive about inlining and eliminating dead code. Many "obvious" optimizations yield much less than estimated because the compiler was already doing something similar. Always benchmark before and after — never trust gas estimates alone. Previous examples of surprises:

- Low-level ext4 mul rewrite: expected -50k, actual **+208k** (compiler was already optimizing the high-level version better)
- Batch sumcheck validation: expected -5k, actual **+4.7k** (extra memory allocation outweighed saved checks)

### Cross-Verifier Gas Comparison (sol-spartan-whir vs sol-whir)

Both verifiers: 80-bit security, `foldingFactor = 4`, `numVariables = 16`.

| Metric               | sol-spartan-whir (WHIR-only) | sol-whir (BN254) |
| -------------------- | ---------------------------- | ---------------- |
| Execution gas        | 1,094,539                    | 677,011          |
| Total tx gas         | 1,367,920                    | 1,135,052        |
| Calldata + intrinsic | 273,381                      | 458,041          |

sol-spartan-whir has higher execution gas (~62%) but only ~21% higher total tx gas because smaller field elements yield less calldata.

**How to measure total tx gas:**

1. Deploy a wrapper contract that stores the `verify()` result in state (making it state-changing).
2. Run `forge script` against a local `anvil` instance with `--broadcast`.
3. Read `gasUsed` from `broadcast/<ScriptName>.s.sol/31337/run-latest.json`.

Scripts: `sol-spartan-whir/script/MeasureTxGas.s.sol`, `sol-whir/script/Verify.s.sol`.

## Implementation Stages (Summary)

See `./solidity_verifier_plan.md` for full details.
