#!/usr/bin/env python3
"""
WHIR parameter sweep for EVM verifier gas estimation.

Models the WHIR parameter derivation (CapacityBound soundness) and estimates
execution gas + calldata gas for various configurations including:
  - Constant(folding_factor) folding
  - ConstantFromSecondRound(first_ff, rest_ff) folding  [exploratory — not yet
    wired in spartan-whir, which hardcodes FoldingFactor::Constant(...)]
  - rs_domain_initial_reduction_factor
  - starting_log_inv_rate

Derived parameters mirror whir-p3/src/whir/parameters.rs and
whir-p3/src/parameters/errors.rs (CapacityBound branch). Includes:
  - Per-round pow_bits, folding_pow_bits, OOD samples
  - Starting folding PoW bits, commitment OOD samples
  - Final pow_bits, final folding PoW bits
  - Validity check: all derived PoW ≤ max_pow_bits (mirrors check_pow_bits())

Cost model calibrated against actual forge measurements (sol-spartan-whir, 13 April 2026):
  - Baseline: folding_factor=4, starting_log_inv_rate=6, rs_domain_initial_reduction_factor=1,
    max_pow_bits=30, num_vars=16 → 932,563 execution gas (measured)
  - Uses linearized Merkle auth paths (per-query sibling paths, inline assembly)
  - Schedule-dependent phases (setup, sumchecks, parse, observe, final ops) are modeled
    from the current `testProfileFullBreakdown` output, not collapsed into one constant

Known constraints:
  - KoalaBear ORDER = 2^31 - 2^24 + 1 → max_pow_bits = 30 (hard assert in challenger)
  - BabyBear ORDER = 2^31 - 2^27 + 1 → max_pow_bits = 30 (same)
  - Mersenne31: TWO_ADICITY = 1, not viable for WHIR (requires TwoAdicField)
  - KoalaBear TWO_ADICITY = 24, BabyBear TWO_ADICITY = 27
  - Constraint: log_folded_domain_size = (num_vars + lir - ff_0) <= TWO_ADICITY
  - rs_domain_initial_reduction_factor (v) must be <= ff_0
  - Rust-level schedule validity is not the same thing as current linearized-merkle Solidity
    compatibility. The script can rank broader schedules, but only the current
    selected schedule has been fully benchmarked end-to-end on the current
    linearized-merkle verifier path.

Usage:
  python3 whir_param_sweep.py
  python3 whir_param_sweep.py --num-vars 20
  python3 whir_param_sweep.py --max-starting-log-inv-rate 11
"""

import math
import argparse
from dataclasses import dataclass
from typing import List, Tuple

# === WHIR PARAMETER DERIVATION (CapacityBound soundness) ===

FIELD_SIZE_BITS = 124  # quartic extension of KoalaBear: 4 * 31 = 124
SECURITY_LEVEL = 80
MAX_POW_BITS = 30  # hard limit: (1 << bits) < F::ORDER_U32 for 31-bit primes
TWO_ADICITY = 24  # KoalaBear (BabyBear = 27, irrelevant for num_vars <= 16)
MAX_SEND = 6  # MAX_NUM_VARIABLES_TO_SEND_COEFFS
MAX_STARTING_LOG_INV_RATE = 11  # sweep cap


def eta_cb(log_inv_rate: int) -> float:
    """CapacityBound η = ρ/20 where ρ = 2^(-log_inv_rate)."""
    return 2 ** (-(log_inv_rate + math.log2(10) + 1))


def delta_cb(log_inv_rate: int) -> float:
    """CapacityBound δ = 1 - ρ - η."""
    rate = 2 ** (-log_inv_rate)
    return 1 - rate - eta_cb(log_inv_rate)


def list_size_bits_cb(log_degree: int, log_inv_rate: int) -> float:
    """List size bound in bits (CapacityBound)."""
    return (log_degree + log_inv_rate) - (-(log_inv_rate + math.log2(10) + 1))


def num_queries(protocol_security: float, log_inv_rate: int) -> int:
    """Number of STIR queries needed for given protocol security level."""
    d = delta_cb(log_inv_rate)
    log_1_minus_d = math.log2(1 - d)
    return math.ceil(-protocol_security / log_1_minus_d)


def query_error(log_inv_rate: int, nq: int) -> float:
    """Query soundness error in bits."""
    d = delta_cb(log_inv_rate)
    return -nq * math.log2(1 - d)


def ood_samples_fn(
    security_level: int, log_degree: int, log_inv_rate: int, field_bits: int
) -> int:
    """Number of OOD samples needed.
    Mirrors SecurityAssumption::determine_ood_samples (CapacityBound branch).
    Loop starts from 1, matching errors.rs line 173."""
    for s in range(1, 64):
        lsb = list_size_bits_cb(log_degree, log_inv_rate)
        error = 2 * lsb + log_degree * s
        ood_err = s * field_bits + 1 - error
        if ood_err >= security_level:
            return s
    raise ValueError("Could not find appropriate number of OOD samples")


def prox_gaps_error_cb(
    log_degree: int, log_inv_rate: int, field_bits: int, num_functions: int = 2
) -> float:
    """CapacityBound prox_gaps_error. Mirrors SecurityAssumption::prox_gaps_error."""
    assert num_functions >= 2
    log_eta = -(log_inv_rate + math.log2(10) + 1)
    error = (log_degree + 2 * log_inv_rate) - log_eta
    num_functions_1_log = math.log2(num_functions - 1)
    return field_bits - (error + num_functions_1_log)


def rbr_soundness_fold_sumcheck(
    field_bits: int, num_variables: int, log_inv_rate: int
) -> float:
    """Mirrors WhirConfig::rbr_soundness_fold_sumcheck (CapacityBound)."""
    list_size = list_size_bits_cb(num_variables, log_inv_rate)
    return field_bits - (list_size + 1)


def folding_pow_bits_fn(
    security_level: int, field_bits: int, num_variables: int, log_inv_rate: int
) -> float:
    """Mirrors WhirConfig::folding_pow_bits. Returns uncapped float."""
    pg = prox_gaps_error_cb(num_variables, log_inv_rate, field_bits, 2)
    sc = rbr_soundness_fold_sumcheck(field_bits, num_variables, log_inv_rate)
    error = min(pg, sc)
    return max(0.0, security_level - error)


def rbr_soundness_queries_combination(
    field_bits: int, num_variables: int, log_inv_rate: int, ood_samples: int, nq: int
) -> float:
    """Mirrors WhirConfig::rbr_soundness_queries_combination (CapacityBound)."""
    list_size = list_size_bits_cb(num_variables, log_inv_rate)
    log_combination = math.log2(ood_samples + nq)
    return field_bits - (log_combination + list_size + 1)


@dataclass
class RoundInfo:
    round_idx: object  # int or "final"
    num_variables: int  # num_variables at this round (after the fold that created it)
    folding_factor: int  # folding factor for this round's leaf/fold width
    log_inv_rate: int  # log_inv_rate at this round (before fold)
    num_queries: int
    pow_bits: int
    folding_pow_bits: int
    depth: int  # Merkle tree depth (log2 of number of leaves)
    is_base: bool  # True for round 0 (base-field leaves)
    next_lir: int = 0
    ood_samples: int = 0


@dataclass
class WhirConfig:
    n_rounds: int  # number of non-final STIR rounds
    final_sumcheck_rounds: int
    round_parameters: List[RoundInfo]
    total_queries: int
    num_vars: int  # initial number of variables (before any folding)
    ff_0: int  # first-round folding factor
    ff_rest: int  # subsequent rounds folding factor
    rs_domain_initial_reduction_factor: int
    commitment_ood_samples: int
    starting_folding_pow_bits: int
    final_folding_pow_bits: int
    valid: bool  # True if all derived PoW <= max_pow_bits
    invalid_reason: str = ""  # reason if invalid


def compute_number_of_rounds(num_vars: int, ff_0: int, ff_rest: int) -> Tuple[int, int]:
    """
    Mirrors FoldingFactor::compute_number_of_rounds from Rust.
    Returns (n_rounds, final_sumcheck_rounds).
    n_rounds does NOT include the final round.
    """
    if ff_0 == ff_rest:
        # Constant case
        if num_vars <= MAX_SEND:
            return (0, num_vars - ff_0)
        n_rounds = math.ceil((num_vars - MAX_SEND) / ff_0)
        fsr = num_vars - n_rounds * ff_0
        return (n_rounds - 1, fsr)
    else:
        # ConstantFromSecondRound case
        nv_after_first = num_vars - ff_0
        if nv_after_first < MAX_SEND:
            return (0, nv_after_first)
        n_rounds = math.ceil((nv_after_first - MAX_SEND) / ff_rest)
        fsr = nv_after_first - n_rounds * ff_rest
        return (n_rounds, fsr)


def derive_config(
    num_vars: int,
    ff_0: int,
    ff_rest: int,
    starting_lir: int,
    max_pow: int,
    rs_domain_initial_reduction_factor: int = 1,
) -> WhirConfig:
    """
    Derive full WHIR round schedule from parameters.

    Mirrors WhirConfig::new() from whir-p3/src/whir/parameters.rs.
    Derived PoW values are NOT clamped — they reflect what the protocol actually
    needs. The config is marked invalid (valid=False) if any derived PoW exceeds
    max_pow (mirrors check_pow_bits()).

    Args:
        num_vars: Number of variables in the committed polynomial
        ff_0: Folding factor for round 0
        ff_rest: Folding factor for subsequent rounds (same as ff_0 for Constant)
        starting_lir: Starting log inverse rate
        max_pow: Maximum PoW bits budget (used to compute protocol_security = sec - max_pow)
        rs_domain_initial_reduction_factor: rs_domain_initial_reduction_factor (must be <= ff_0, default 1)
    """
    if max_pow > MAX_POW_BITS:
        raise ValueError(
            f"max_pow ({max_pow}) exceeds field limit MAX_POW_BITS ({MAX_POW_BITS}). "
            f"Challenger will hard-assert: (1 << bits) < F::ORDER_U32"
        )
    assert (
        rs_domain_initial_reduction_factor <= ff_0
    ), f"rs_domain_initial_reduction_factor ({rs_domain_initial_reduction_factor}) must be <= ff_0 ({ff_0})"

    # Check TWO_ADICITY constraint
    log_folded = num_vars + starting_lir - ff_0
    assert (
        log_folded <= TWO_ADICITY
    ), f"log_folded_domain_size ({log_folded}) > TWO_ADICITY ({TWO_ADICITY})"

    n_rounds, final_sumcheck_rounds = compute_number_of_rounds(num_vars, ff_0, ff_rest)
    protocol_sec = SECURITY_LEVEL - max_pow

    # --- Commitment-level derivations (before any decrement) ---
    commitment_ood_samples = ood_samples_fn(
        SECURITY_LEVEL, num_vars, starting_lir, FIELD_SIZE_BITS
    )
    starting_folding_pow_bits = folding_pow_bits_fn(
        SECURITY_LEVEL, FIELD_SIZE_BITS, num_vars, starting_lir
    )

    rounds = []
    nv = num_vars
    lir = starting_lir
    log_domain = num_vars + starting_lir

    # Mirrors Rust: num_variables -= folding_factor.at_round(0) before the loop
    nv -= ff_0

    for i in range(n_rounds + 1):
        ff_this = ff_0 if i == 0 else ff_rest
        # Final round uses folding_factor.at_round(n_rounds):
        #   n_rounds==0 → at_round(0) → ff_0
        #   n_rounds>=1 → at_round(n_rounds) → ff_rest
        ff_final = ff_0 if n_rounds == 0 else ff_rest

        if i < n_rounds:
            # Non-final round
            v = rs_domain_initial_reduction_factor if i == 0 else 1
            next_lir = lir + (ff_this - v)

            nq = num_queries(protocol_sec, lir)
            ood_s = ood_samples_fn(SECURITY_LEVEL, nv, next_lir, FIELD_SIZE_BITS)

            # pow_bits (uncapped) — mirrors Rust
            qe = query_error(lir, nq)
            ce = rbr_soundness_queries_combination(
                FIELD_SIZE_BITS, nv, next_lir, ood_s, nq
            )
            pb = max(0.0, SECURITY_LEVEL - min(qe, ce))

            # folding_pow_bits (uncapped) — mirrors Rust
            fpow = folding_pow_bits_fn(SECURITY_LEVEL, FIELD_SIZE_BITS, nv, next_lir)

            tree_depth = log_domain - ff_this

            rounds.append(
                RoundInfo(
                    round_idx=i,
                    num_variables=nv,
                    folding_factor=ff_this,
                    log_inv_rate=lir,
                    num_queries=nq,
                    pow_bits=int(pb),
                    folding_pow_bits=int(fpow),
                    depth=tree_depth,
                    is_base=(i == 0),
                    next_lir=next_lir,
                    ood_samples=ood_s,
                )
            )

            nv -= (ff_final if (i + 1 == n_rounds) else ff_rest) if n_rounds > 0 else 0
            lir = next_lir
            log_domain -= v  # domain_size >>= v
        else:
            # Final round — ff from folding_factor.at_round(n_rounds)
            nq = num_queries(protocol_sec, lir)
            tree_depth = log_domain - ff_final

            # final_pow_bits (uncapped)
            final_qe = query_error(lir, nq)
            pb = max(0.0, SECURITY_LEVEL - final_qe)

            rounds.append(
                RoundInfo(
                    round_idx="final",
                    num_variables=nv,
                    folding_factor=ff_final,
                    log_inv_rate=lir,
                    num_queries=nq,
                    pow_bits=int(pb),
                    folding_pow_bits=0,
                    depth=tree_depth,
                    is_base=(i == 0),
                )
            )

    # final_folding_pow_bits: max(0, security_level - (field_size_bits - 1))
    final_folding_pow_bits = max(0.0, SECURITY_LEVEL - (FIELD_SIZE_BITS - 1))

    # --- Validity check (mirrors check_pow_bits()) ---
    all_pow_values = (
        [int(starting_folding_pow_bits), int(final_folding_pow_bits)]
        + [r.pow_bits for r in rounds]
        + [r.folding_pow_bits for r in rounds]
    )
    max_derived = max(all_pow_values)
    valid = max_derived <= max_pow
    invalid_reason = ""
    if not valid:
        invalid_reason = f"derived PoW {max_derived} > max_pow {max_pow}"

    return WhirConfig(
        n_rounds=n_rounds,
        final_sumcheck_rounds=final_sumcheck_rounds,
        round_parameters=rounds,
        total_queries=sum(r.num_queries for r in rounds),
        num_vars=num_vars,
        ff_0=ff_0,
        ff_rest=ff_rest,
        rs_domain_initial_reduction_factor=rs_domain_initial_reduction_factor,
        commitment_ood_samples=commitment_ood_samples,
        starting_folding_pow_bits=int(starting_folding_pow_bits),
        final_folding_pow_bits=int(final_folding_pow_bits),
        valid=valid,
        invalid_reason=invalid_reason,
    )


# === MERKLE LINEAR AUTH PATH MODEL ===
#
# The WHIR verifier uses independent per-query linear authentication paths
# (linearized April 2026, replacing the earlier frontier-based multiproof).
# Each query walks from leaf to root independently:
#   - compress calls per round = nq * depth  (each query hashes depth siblings)
#   - decommitments per round = nq * depth   (each query carries depth sibling hashes)
#
# The assembly _computeRootFromLeafHashes20 computes all queries in a single
# inline assembly block with amortized bookkeeping. The per-compress cost
# (MERKLE_PER_COMPRESS) includes inline keccak256, digest masking, and
# left/right child ordering.
#
# Verified against profiling: 76,215 / (9 * 18) = 470.5 gas/compress (Round 0),
# 48,312 / (6 * 17) = 473.6 (Round 1), 37,614 / (5 * 16) = 470.2 (Final).


def merkle_compress_calls(nq: int, depth: int) -> int:
    """Total keccak compress calls for linear auth paths (nq independent paths of length depth)."""
    return nq * depth


def merkle_decommitments(nq: int, depth: int) -> int:
    """Total decommitment count (sibling hashes) for linear auth paths."""
    return nq * depth


# === GAS COST MODEL (calibrated from actual forge measurements, 2026-04-13) ===
#
# Source measurements (folding_factor=4, 16 vars, 2 rounds + final, linear auth paths):
#   Merkle (linear auth paths, inline assembly _computeRootFromLeafHashes20):
#     Round 0 (depth=18, 9q): 76,215 gas, 162 compress calls → 470 gas/compress
#     Round 1 (depth=17, 6q): 48,312 gas, 102 compress calls → 474 gas/compress
#     Final  (depth=16, 5q): 37,614 gas,  80 compress calls → 470 gas/compress
#     → MERKLE_PER_COMPRESS = 471 gas per compress (average)
#   Leaf hash base (folding_factor=4): 20,591 / 9q = 2,288/q → ~143 gas per base value
#   Leaf hash ext4 (folding_factor=4): (21,938 + 18,299) / 11q = 3,658/q → ~229 gas per ext4 value
#   Row fold base (folding_factor=4): 64,602 / 9q = 7,178/q
#     -> 15 fold ops, 8 promote+fold = 306 gas, 7 ext4 fold = 675 gas
#   Row fold ext4 (folding_factor=4): (60,780 + 50,530) / 11q = 10,119/q → 675 gas per fold op
#   STIR evaluation-point exponentiation:
#     Round 0: 18,611 / (9q * 18 depth) ≈ 115 gas/depth-bit/query
#     Round 1: 11,939 / (6q * 17 depth) ≈ 117 gas/depth-bit/query
#     Final:    9,117 / (5q * 16 depth) ≈ 114 gas/depth-bit/query
#     → EVAL_POINT_POW_PER_DEPTH_BIT = 116
#   Sample: ~1,050/q, Overhead: ~742/q
#   ABI calldata: all values/OOD are uint256[] slots (32 bytes each).
#     Base uint256: 4 nonzero + 28 zero bytes → 176 gas.  Ext4 uint256: 16 nonzero + 16 zero → 320 gas.

# Calibrate Merkle per-compress cost from profiling data (linear auth paths):
#   Average across rounds: (470.5 + 473.6 + 470.2) / 3 ≈ 471 gas/compress
MERKLE_PER_COMPRESS = 471
SAMPLE_PER_QUERY = 1050
OVERHEAD_PER_QUERY = 742
LEAF_HASH_BASE_PER_VALUE = 143
LEAF_HASH_EXT4_PER_VALUE = 229
FOLD_EXT4_PER_OP = 675
FOLD_BASE_PROMOTE_PER_OP = 306
EVAL_POINT_POW_PER_DEPTH_BIT = 116
EVAL_POINT_POW_BASE = 0
# ABI calldata cost per uint256 slot (32 bytes):
# Base field (31-bit): 4 nonzero data bytes + 28 zero-padding = 4×16 + 28×4 = 176 gas
# Ext4 packed (4×31-bit in top 16 bytes): ~16 nonzero + 16 zero = 16×16 + 16×4 = 320 gas
BASE_VALUE_CD = 176  # per uint256 slot holding one base field element
EXT4_VALUE_CD = 320  # per uint256 slot holding one packed ext4 element
# Merkle decommitment: bytes32 = 32 bytes, ~20 nonzero digest + 12 zero padding
# 20×16 + 12×4 = 368 gas per node
DECOMMIT_CD = 368
CONSTRAINT_PER_VARIABLE = 9272  # eq-poly + select-poly + combine overhead

# === SCHEDULE-DEPENDENT PHASE COSTS ===
#
# Calibrated from the current `testProfileFullBreakdown` output on the
# linearized-merkle branch (16-var baseline, ff=4, lir=6).
#
# Phase breakdown (profiled, baseline):
#   setup                28,547
#   initial sumcheck     21,673
#   round0 parse         19,090
#   round0 sumcheck      22,102
#   round1 parse         14,576
#   round1 sumcheck      25,602
#   observe finalPoly    11,387
#   final select         0
#   final sumcheck       21,651
#   final value check    10,519
#
# We model those as:
#   - setup base
#   - parse(base + ood_samples * num_variables * OOD_PER_SAMPLE_PER_VAR)
#   - separate per-round costs for initial, regular, and final sumchecks
#   - dedicated folding-PoW cost inside round sumchecks
#   - final poly observation and final value check per coefficient
#
# The profiling harness still undercounts the full end-to-end typed verifier,
# so INTERPHASE_RESIDUAL remains a constant fitted to the current selected
# schedule after the dynamic buckets above are updated.

# Setup: domain separator observation + observePattern + initial scaffold work
SETUP_BASE = 4_943
# Parse commitment: _parseCommitment per invocation
PARSE_COMMITMENT_BASE = 5_548
OOD_PER_SAMPLE_PER_VAR = 564
# Sumcheck verification costs
INITIAL_SC_PER_ROUND = 5_418
ROUND_SC_PER_ROUND = 5_526
FINAL_SC_PER_ROUND = 5_413
FOLDING_POW_PER_BIT = 875
# Observe finalPoly: observePackedExt4Slice per coefficient
OBSERVE_EXT4_PER_COEFF = 712
# Final select: Horner evaluation of finalPoly at each final query point
FINAL_SELECT_PER_EVAL = 0
# Final value check: evaluate finalPoly at the final randomness point
FINAL_VALUE_PER_COEFF = 657
# Un-profiled inter-phase overhead (constant across configs)
INTERPHASE_RESIDUAL = 97_628


def leaf_hash_per_query(ff: int, is_base: bool) -> int:
    leaf_count = 2**ff
    rate = LEAF_HASH_BASE_PER_VALUE if is_base else LEAF_HASH_EXT4_PER_VALUE
    return int(rate * leaf_count)


def fold_per_query(ff: int, is_base: bool) -> int:
    n_folds = 2**ff - 1
    if is_base:
        base_layer = 2 ** (ff - 1)
        ext_folds = n_folds - base_layer
        return int(base_layer * FOLD_BASE_PROMOTE_PER_OP + ext_folds * FOLD_EXT4_PER_OP)
    else:
        return int(n_folds * FOLD_EXT4_PER_OP)


def evaluation_point_pow_gas(depth: int) -> int:
    if depth == 0:
        return 0
    return int(EVAL_POINT_POW_PER_DEPTH_BIT * depth + EVAL_POINT_POW_BASE)


def folding_pow_gas(pow_bits: int) -> int:
    if pow_bits == 0:
        return 0
    return int(FOLDING_POW_PER_BIT * pow_bits)


@dataclass
class GasBreakdown:
    stir: int = 0  # STIR operations: merkle, leaf, fold, sample, overhead, evaluation-point pow
    constraint: int = 0  # eq-poly + select-poly evaluation
    schedule: int = 0  # schedule-dependent: setup, sumchecks, parse, observe, final ops
    residual: int = 0  # un-profiled inter-phase overhead (constant)

    @property
    def total(self) -> int:
        return self.stir + self.constraint + self.schedule + self.residual


def estimate_execution_gas(cfg: WhirConfig) -> GasBreakdown:
    # --- STIR: per-round Merkle verify + leaf hash + row fold + query sampling ---
    # PoW for STIR challenges (pow_bits) stays here.
    # Folding PoW (folding_pow_bits) and OOD are now in the schedule bucket.
    stir = 0
    for r in cfg.round_parameters:
        nq = r.num_queries
        depth = r.depth
        merkle = merkle_compress_calls(nq, depth) * MERKLE_PER_COMPRESS
        leaf = leaf_hash_per_query(r.folding_factor, r.is_base) * nq
        fold = fold_per_query(r.folding_factor, r.is_base) * nq
        sample = SAMPLE_PER_QUERY * nq
        oh = OVERHEAD_PER_QUERY * nq
        eval_pow = nq * evaluation_point_pow_gas(depth)
        stir += merkle + leaf + fold + sample + oh + eval_pow

    # --- Constraint evaluation: eq-poly + select-poly ---
    constraint = 0
    for r in cfg.round_parameters:
        if isinstance(r.round_idx, int):
            constraint += r.num_variables * CONSTRAINT_PER_VARIABLE

    # --- Schedule-dependent phases ---
    sched = 0
    final_poly_length = 2**cfg.final_sumcheck_rounds
    final_nq = cfg.round_parameters[-1].num_queries

    # Setup: observePattern + domain separator + initial parse commitment
    sched += SETUP_BASE
    sched += (
        PARSE_COMMITMENT_BASE
        + cfg.commitment_ood_samples * cfg.num_vars * OOD_PER_SAMPLE_PER_VAR
    )

    # Initial sumcheck: ff_0 rounds + starting folding PoW
    sched += cfg.ff_0 * INITIAL_SC_PER_ROUND + folding_pow_gas(
        cfg.starting_folding_pow_bits
    )

    # Per non-final round: parse commitment + folding sumcheck
    for r in cfg.round_parameters:
        if isinstance(r.round_idx, int):
            # Parse: observe commitment digest + OOD sampling
            sched += (
                PARSE_COMMITMENT_BASE
                + r.ood_samples * r.num_variables * OOD_PER_SAMPLE_PER_VAR
            )
            # Folding sumcheck: ff_rest rounds + folding PoW
            sched += cfg.ff_rest * ROUND_SC_PER_ROUND + folding_pow_gas(
                r.folding_pow_bits
            )

    # Observe finalPoly
    sched += final_poly_length * OBSERVE_EXT4_PER_COEFF

    # Final select: Horner-evaluate finalPoly at each final query point
    sched += final_nq * final_poly_length * FINAL_SELECT_PER_EVAL

    # Final sumcheck: fsr rounds + final folding PoW
    sched += cfg.final_sumcheck_rounds * FINAL_SC_PER_ROUND + folding_pow_gas(
        cfg.final_folding_pow_bits
    )

    # Final value check: evaluate finalPoly at randomness point
    sched += final_poly_length * FINAL_VALUE_PER_COEFF

    return GasBreakdown(
        stir=stir, constraint=constraint, schedule=sched, residual=INTERPHASE_RESIDUAL
    )


def estimate_calldata_gas(cfg: WhirConfig) -> int:
    """Estimate calldata cost in gas (16 gas/nonzero byte, 4 gas/zero byte)."""
    leaf_cd = 0
    merkle_cd = 0
    for r in cfg.round_parameters:
        nq = r.num_queries
        depth = r.depth
        leaf_count = 2**r.folding_factor
        if r.is_base:
            leaf_cd += nq * leaf_count * BASE_VALUE_CD
        else:
            leaf_cd += nq * leaf_count * EXT4_VALUE_CD
        merkle_cd += merkle_decommitments(nq, depth) * DECOMMIT_CD

    # OOD answers in calldata: initial + per-round, each packed ext4 → uint256
    ood_cd = cfg.commitment_ood_samples * EXT4_VALUE_CD
    for r in cfg.round_parameters:
        if isinstance(r.round_idx, int):
            ood_cd += r.ood_samples * EXT4_VALUE_CD

    # --- Schedule-dependent proof components ---
    # Initial sumcheck: ff_0 rounds, each sends [c0, c2] (2 ext4) + powWitness (1 base)
    sc_cd = cfg.ff_0 * 2 * EXT4_VALUE_CD + cfg.ff_0 * BASE_VALUE_CD
    # Per non-final round: commitment (bytes32) + powWitness (base) + sumcheck
    # Sumcheck rounds = folding_factor.at_round(round+1), which is always ff_rest
    for r in cfg.round_parameters:
        if isinstance(r.round_idx, int):
            sc_cd += DECOMMIT_CD  # commitment bytes32
            sc_cd += BASE_VALUE_CD  # powWitness uint256
            sc_cd += cfg.ff_rest * 2 * EXT4_VALUE_CD  # sumcheck polynomialEvals
            sc_cd += cfg.ff_rest * BASE_VALUE_CD  # sumcheck powWitnesses
    # Final poly: 2^final_sumcheck_rounds ext4 coefficients
    sc_cd += (2**cfg.final_sumcheck_rounds) * EXT4_VALUE_CD
    # Final pow witness
    sc_cd += BASE_VALUE_CD
    # Final sumcheck (if final_sumcheck_rounds > 0): fsr rounds × (2 ext4 evals + 1 base pow)
    if cfg.final_sumcheck_rounds > 0:
        sc_cd += (
            cfg.final_sumcheck_rounds * 2 * EXT4_VALUE_CD
            + cfg.final_sumcheck_rounds * BASE_VALUE_CD
        )
    # Initial commitment (bytes32)
    sc_cd += DECOMMIT_CD

    # Fixed ABI overhead: array-length words, struct offsets, booleans,
    # function selector, base tx cost (21000). Empirically ~25,000 gas.
    fixed_cd = 25000

    return leaf_cd + merkle_cd + ood_cd + sc_cd + fixed_cd


def _short_name(name: str) -> str:
    """Shorten config name for table display."""
    s = name.replace("CURRENT ", "").replace("ConstantFromSecondRound", "CFSR")
    s = s.replace(",starting_log_inv_rate=", ", lir=")
    s = s.replace(",rs_domain_initial_reduction_factor=", ", rs_v=")
    return s + (" ◀ WhirVerifier4.sol" if name.startswith("CURRENT") else "")


_CFG_W = 44  # config name column width


def _table_header(ranked: bool = True) -> str:
    """Return markdown-style table header + separator."""
    if ranked:
        h = (
            f"| {'#':>3} | {'Config':<{_CFG_W}} "
            f"| {'Rnds':>4} | {'Queries':>7} "
            f"| {'Exec':>9} | {'Calldata':>8} "
            f"| {'Total':>10} | {'Δ Total':>9} |"
        )
        s = f"|{'-' * 5}|{'-' * (_CFG_W + 2)}|{'-' * 6}|{'-' * 9}|{'-' * 11}|{'-' * 10}|{'-' * 12}|{'-' * 11}|"
    else:
        h = (
            f"| {'Config':<{_CFG_W}} "
            f"| {'Rnds':>4} | {'Queries':>7} "
            f"| {'Exec':>9} | {'Calldata':>8} "
            f"| {'Total':>10} | {'Δ Total':>9} |"
        )
        s = f"|{'-' * (_CFG_W + 2)}|{'-' * 6}|{'-' * 9}|{'-' * 11}|{'-' * 10}|{'-' * 12}|{'-' * 11}|"
    return h + "\n" + s


def _table_row(r: "SweepResult", base_total: int, rank: int = None) -> str:
    """Format one markdown-style table row."""
    d_total = r.total - base_total
    n_rnds = r.cfg.n_rounds + 1
    sn = _short_name(r.name)
    if rank is not None:
        return (
            f"| {rank:>3} | {sn:<{_CFG_W}} "
            f"| {n_rnds:>4} | {r.cfg.total_queries:>7} "
            f"| {r.ex.total:>9,} | {r.cd:>8,} "
            f"| {r.total:>10,} | {d_total:>+9,} |"
        )
    return (
        f"| {sn:<{_CFG_W}} "
        f"| {n_rnds:>4} | {r.cfg.total_queries:>7} "
        f"| {r.ex.total:>9,} | {r.cd:>8,} "
        f"| {r.total:>10,} | {d_total:>+9,} |"
    )


def _table_ellipsis_row() -> str:
    return (
        f"| {'...':>3} | {'...':<{_CFG_W}} "
        f"| {'...':>4} | {'...':>7} "
        f"| {'...':>9} | {'...':>8} "
        f"| {'...':>10} | {'...':>9} |"
    )


def make_config_name(
    ff_0: int, ff_rest: int, lir: int, rs_v: int, is_current: bool = False
) -> str:
    """Build config name string from parameters."""
    if ff_0 == ff_rest:
        name = f"Constant({ff_0})"
    else:
        name = f"ConstantFromSecondRound({ff_0},{ff_rest})"
    name += f",starting_log_inv_rate={lir}"
    if rs_v != 1:
        name += f",rs_domain_initial_reduction_factor={rs_v}"
    if is_current:
        name = "CURRENT " + name
    return name


@dataclass
class SweepResult:
    name: str
    cfg: WhirConfig
    ex: GasBreakdown
    cd: int
    total: int
    group: str  # "Constant(4)", "Constant(5)", "ConstantFromSecondRound(...,4)", etc.


def max_starting_log_inv_rate(
    num_vars: int, ff_0: int, sweep_cap: int = MAX_STARTING_LOG_INV_RATE
) -> int:
    """Largest starting_log_inv_rate allowed by validity and the chosen sweep cap."""
    return min(sweep_cap, TWO_ADICITY - num_vars + ff_0)


def print_sweep(
    num_vars: int = 16,
    max_starting_log_inv_rate_cap: int = MAX_STARTING_LOG_INV_RATE,
):
    print(
        f"WHIR Parameter Sweep — {num_vars} variables, {SECURITY_LEVEL}-bit security, "
        f"quartic extension ({FIELD_SIZE_BITS}-bit)"
    )
    print(
        f"Max PoW: {MAX_POW_BITS} bits (31-bit prime field), "
        f"TWO_ADICITY: {TWO_ADICITY}"
    )
    print(
        "Note: rows below are Rust-valid schedule candidates. The current linearized-merkle "
        "Solidity verifier is only benchmarked end-to-end on the selected "
        "Constant(4), lir=6, rs_v=1 schedule."
    )

    # --- Sweep parameter ranges ---
    # Sweep the full validity space instead of a curated subset:
    #   - Constant(ff): ff in [1, num_vars]
    #   - ConstantFromSecondRound(ff_0, ff_rest): 1 <= ff_rest < ff_0 <= num_vars
    #   - starting_log_inv_rate in [1, min(cap, TWO_ADICITY - num_vars + ff_0)]
    #     (default cap = 11 for the current sweep)
    MAX_POW = MAX_POW_BITS

    # Current baseline
    CURRENT = (4, 4, 6, 1)  # (ff_0, ff_rest, lir, rs_v)

    base_cfg = derive_config(
        num_vars, *CURRENT[:3], MAX_POW, rs_domain_initial_reduction_factor=CURRENT[3]
    )
    base_exec = estimate_execution_gas(base_cfg)
    base_cd = estimate_calldata_gas(base_cfg)
    base_total = base_exec.total + base_cd

    results: List[SweepResult] = []

    def try_config(ff_0: int, ff_rest: int, lir: int, rs_v: int, group: str):
        try:
            cfg = derive_config(
                num_vars,
                ff_0,
                ff_rest,
                lir,
                MAX_POW,
                rs_domain_initial_reduction_factor=rs_v,
            )
        except (AssertionError, ValueError):
            return
        if not cfg.valid:
            return
        is_current = (ff_0, ff_rest, lir, rs_v) == CURRENT
        name = make_config_name(ff_0, ff_rest, lir, rs_v, is_current=is_current)
        ex = estimate_execution_gas(cfg)
        cd = estimate_calldata_gas(cfg)
        total = ex.total + cd
        results.append(
            SweepResult(name=name, cfg=cfg, ex=ex, cd=cd, total=total, group=group)
        )

    # 1. Constant(ff) — ff_0 == ff_rest
    for ff in range(1, num_vars + 1):
        group = f"Constant({ff})"
        max_lir = max_starting_log_inv_rate(num_vars, ff, max_starting_log_inv_rate_cap)
        if max_lir < 1:
            continue
        for lir in range(1, max_lir + 1):
            for rs_v in range(1, ff + 1):
                try_config(ff, ff, lir, rs_v, group)

    # 2. ConstantFromSecondRound(first_ff, rest_ff) — ff_0 > ff_rest
    for ff_rest in range(1, num_vars):
        for ff_0 in range(ff_rest + 1, num_vars + 1):
            group = f"ConstantFromSecondRound(*,{ff_rest})"
            max_lir = max_starting_log_inv_rate(
                num_vars, ff_0, max_starting_log_inv_rate_cap
            )
            if max_lir < 1:
                continue
            for lir in range(1, max_lir + 1):
                for rs_v in range(1, ff_0 + 1):
                    try_config(ff_0, ff_rest, lir, rs_v, group)

    # --- Print results grouped, sorted by total within each group ---
    seen_groups = []
    for r in results:
        if r.group not in seen_groups:
            seen_groups.append(r.group)

    for group in seen_groups:
        group_results = [r for r in results if r.group == group]
        group_results.sort(key=lambda r: r.total)

        is_exploratory = "ConstantFromSecondRound" in group
        label = f"[EXPLORATORY] {group}" if is_exploratory else group
        print(f"\n### {label} ({len(group_results)} configs)\n")
        print(_table_header(ranked=True))
        for i, r in enumerate(group_results, 1):
            print(_table_row(r, base_total, rank=i))

    # --- Top-N overall ---
    results.sort(key=lambda r: r.total)
    top_n = 10
    print(f"\n### TOP {top_n} OVERALL (out of {len(results)} valid)\n")
    print(_table_header(ranked=True))
    for i, r in enumerate(results[:top_n], 1):
        print(_table_row(r, base_total, rank=i))

    current_index = next(
        (i for i, r in enumerate(results, 1) if r.name.startswith("CURRENT ")), None
    )
    if current_index is not None and current_index > top_n:
        print(_table_ellipsis_row())
        print(_table_row(results[current_index - 1], base_total, rank=current_index))

    # Summary
    print(f"\n{'=' * 80}")
    print("NOTES:")
    print(f"{'=' * 80}")
    print(f"  • {len(results)} valid configs out of full sweep")
    print(
        f"  • PoW budget = {MAX_POW_BITS} bits (31-bit prime field hard limit in challenger)"
    )
    print(f"  • Configs with derived PoW > {MAX_POW_BITS} are excluded (invalid)")
    print(
        f"  • starting_log_inv_rate is capped at {max_starting_log_inv_rate_cap} for this sweep"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="WHIR parameter sweep for EVM verifier gas"
    )
    parser.add_argument(
        "--num-vars", type=int, default=16, help="Number of variables (default: 16)"
    )
    parser.add_argument(
        "--max-starting-log-inv-rate",
        type=int,
        default=MAX_STARTING_LOG_INV_RATE,
        help=(
            "Maximum starting_log_inv_rate to include in the sweep "
            f"(default: {MAX_STARTING_LOG_INV_RATE})"
        ),
    )
    args = parser.parse_args()
    print_sweep(args.num_vars, args.max_starting_log_inv_rate)
