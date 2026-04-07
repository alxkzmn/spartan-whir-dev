## Parameter Sweep

The script [`whir_param_sweep.py`](./whir_param_sweep.py) in the workspace root performs a full parametric sweep over WHIR protocol parameters and estimates EVM gas (execution + calldata) for each configuration.

### What it sweeps

| Parameter                            | Range                                                       | Description                                                                          |
| ------------------------------------ | ----------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `folding_factor`                     | 4–8                                                         | Reed-Solomon folding factor per round                                                |
| `starting_log_inv_rate`              | 4–12                                                        | Initial log inverse rate (controls tree depth vs. query count)                       |
| `rs_domain_initial_reduction_factor` | 1–`folding_factor`                                          | How much to slow round-0 rate growth (1 = default, `ff` = flat)                      |
| Folding schedule                     | `Constant(ff)` and `ConstantFromSecondRound(ff_0, ff_rest)` | Constant uses the same factor every round; CFSR uses a larger factor in round 0 only |

Invalid configs (derived PoW > 30 bits) are silently excluded.

### Usage

```sh
# Default: 16 variables
python3 whir_param_sweep.py

# Custom variable count
python3 whir_param_sweep.py --num-vars 20
```

### Output

1. **Grouped tables** — configs grouped by folding schedule type, sorted by total tx gas within each group.
2. **TOP 20 overall** — best 20 configs across all groups ranked by total tx gas.
3. **NOTES** — field constraints, PoW budget, and caveats about exploratory configs.

Each row shows:

| Column     | Meaning                                                                                                                          |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `#`        | Rank within group or overall                                                                                                     |
| `Config`   | Short config name (`lir` = starting_log_inv_rate, `rs_v` = rs_domain_initial_reduction_factor, `CFSR` = ConstantFromSecondRound) |
| `Rnds`     | Number of WHIR folding rounds                                                                                                    |
| `Queries`  | Total STIR queries (including final)                                                                                             |
| `Exec`     | Estimated execution gas                                                                                                          |
| `Calldata` | Estimated calldata gas                                                                                                           |
| `Total`    | `Exec + Calldata`                                                                                                                |
| `Δ Total`  | Delta vs. current baseline (`Constant(4), lir=6`), `◀` marks baseline                                                            |

### Caveats

- **Gas model is approximate**: calibrated against measured `forge test` execution gas (~5% error from constraint cost simplification).
- The script mirrors the derivation in `whir-p3/src/whir/parameters.rs` (CapacityBound branch), not a substitute for it.
