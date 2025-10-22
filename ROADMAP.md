# soliton.c Optimization Roadmap v0.4.1 → v0.4.4

**Philosophy**: Controlled experimental sequence with falsifiable hypotheses.
**Approach**: Measure → Verify → Optimize → Publish → Stabilize
**Target**: ≤0.40 cpb @ 64KB (match or beat OpenSSL's 0.35 cpb baseline)

---

## Current Status (v0.4.0)

**Performance**:
- **0.45 cpb @ 64KB** (VAES+VPCLMULQDQ fused kernels)
- OpenSSL 3.x: **0.35 cpb** (1.28× gap)
- Init: **4,964 cycles** (production-ready after 61.9× AES-NI optimization)

**Architecture**:
- Runtime dispatch (scalar / AES-NI+PCLMUL / VAES)
- Validated GHASH 8/16-lane kernels
- Reproducible EVP benchmarks + CSV results in repo
- 10,000/10,000 Gate C validation (100% OpenSSL match)

**Repository Status**:
- Canonical: Only working code + accurate docs
- Benchmarks and results checked in (`bench/`, `results/`)
- Clean, professional, production-ready

---

## Optimization Philosophy: Each Release = Controlled Experiment

Each point-release tests a **singular, falsifiable hypothesis** with measurable outcomes. This transforms optimization from feature bundling into rigorous performance engineering.

| Version | Singular Focus | Measurable Hypothesis | Target cpb |
|---------|----------------|----------------------|------------|
| **0.4.1a** | **Tooling Polish** | If measurement tooling is automated, variance will be <5% | - |
| **0.4.1** | **Measurement Integrity** | If we isolate steady-state and fix alignment, cpb will drop ≥5% | 0.43-0.44 |
| **0.4.2** | **Instruction Geometry** | If VAES and VPCLMULQDQ are perfectly overlapped, uops.port_1 ≈ uops.port_5 and cpb ≤ 0.42 | 0.41-0.42 |
| **0.4.3** | **Cache Choreography** | If L1 conflict misses <1% and prefetch cadence is correct, cpb ≤ 0.40 | 0.40 |
| **0.4.4** | **Throughput Synthesis** | If key/H caches and small-message reuse are added, median latency for 4KB ≤ 1.2× 64KB throughput | 0.38-0.40 |

---

## Gate System

### Correctness Gates (MUST stay green on every commit)

- **Gate P0** (Product Equivalence): 262/262 PASS
- **Gate A** (Commuting Diagram): 1,000/1,000 PASS
- **Gate B** (NIST 96-bit IV): 4/4 PASS
- **Gate C** (Cross-EVP Fuzz): 10,000/10,000 PASS

### NEW: Profiling Validation Gate (P-gate)

**Purpose**: Verify optimization actually improved microarchitecture

**Measurement**: Run `perf stat -d` on reference workload (64KB, 1:1 CT:AAD)

**Pass Criteria**:
- Port 1 & 5 utilization ≥ 75%
- Frontend stalls ≤ 5%
- L1 cache miss rate ≤ 1%

**If P-gate fails**: Optimization didn't actually overlap; **roll back**.

This keeps tuning empirical and prevents cargo-cult optimization.

### Benchmark Gate

**Pass Criteria**:
- **Median** cpb @ 64KB (1:1 mix) meets target band
- **σ** (standard deviation) < 5% of median
- **p95** latency documented in CSV
- CSV lands in `results/` with CPU/µcode/flags/perf-counters header

---

## v0.4.1a — Tooling Polish (Measurement Foundation)

**Subtitle**: *Measurement Integrity Foundation*

**Goal**: Freeze tooling before chasing cpb; eliminate statistical noise

**Hypothesis**: If measurement tooling is automated and standardized, variance will be consistently <5%

**Target**: No cpb target; pure infrastructure

### Work Items

1. **Minimal `bench.py` Parser**
   - Compute medians / confidence intervals from CSVs
   - Output statistical summary (median, σ, p95, p99)
   - Detect variance > 5% and warn

2. **Automated Perf Counter Capture**
   - Integrate `perf stat -x,` output into CSV
   - Capture: cycles, instructions, uops.port_1, uops.port_5, L1-misses
   - Merge into benchmark CSV with environment metadata

3. **Make Target: `make perf-snapshot`**
   - Bundle results + environment + perf counters
   - Generate timestamped directory: `results/snapshot_YYYYMMDD_HHMMSS/`
   - Include: CSV, perf stat output, cpuinfo, kernel version, git commit

4. **Reproducibility Script**
   - `tools/repro.sh` that runs full benchmark + validation
   - Checks CPU frequency governor (performance mode required)
   - Verifies turbo disabled, runs warmup, captures results

### Exit Criteria

- ✅ `bench.py` produces statistical summary from CSV
- ✅ `make perf-snapshot` generates complete measurement bundle
- ✅ Three consecutive runs show σ < 5% of median
- ✅ P-gate infrastructure integrated into benchmark
- ✅ Documentation updated with reproducibility checklist

### Files Created/Modified

- `tools/bench.py` - Statistical analysis tool
- `tools/repro.sh` - Full reproducibility script
- `Makefile` - Add `perf-snapshot` target
- `bench/evp_benchmark.c` - Integrate perf stat capture
- `RESULTS.md` - Add variance reporting format

---

## v0.4.1 — Measurement Integrity

**Subtitle**: *Measurement Hygiene*

**Goal**: Lock steady-state benchmark, remove measurement bias, fix alignment

**Hypothesis**: If we isolate steady-state and fix alignment, cpb will drop ≥5%

**Target**: **0.43–0.44 cpb** @ 64KB (median, σ < 5%)

### Work Items

1. **Bench Correctness**
   - Ensure EVP bench measures **stream time only** (separate init/setup vs update)
   - Init measured separately, excluded from cpb calculation
   - Document measurement methodology in CSV header

2. **Path Banners + Guards**
   - Always print which backend ran: `scalar / AES-NI / VAES fused / VAES 16-lane`
   - Prevent false greens from incorrect backend selection
   - Add backend detection verification at start of benchmark

3. **Alignment & Layout**
   - **64-byte align** GCM context structure
   - **64-byte align** `H^n` power table (256 bytes)
   - Verify no split-line loads in GHASH counter prep
   - Add alignment verification to test suite

### Exit Criteria

- ✅ **P-gate**: Port utilization ≥ 75%, frontend stalls ≤ 5%
- ✅ CSV shows stream-only **0.43–0.44 cpb** @ 64KB
- ✅ σ < 5% of median across 10 runs
- ✅ Backend identification in benchmark output
- ✅ Results + repro steps committed to `results/` and `RESULTS.md`

### Files Modified

- `bench/evp_benchmark.c` - Stream-only measurement, backend banner
- `core/common.h` - 64-byte aligned context and H-powers
- `test/check_alignment.c` - Alignment verification test
- `RESULTS.md` - v0.4.1 results with variance data

---

## v0.4.2 — Instruction Geometry

**Subtitle**: *Instruction Overlap*

**Goal**: Keep port 1/5 saturated, shorten critical path in 8-/16-lane kernels

**Hypothesis**: If VAES and VPCLMULQDQ are perfectly overlapped, uops.port_1 ≈ uops.port_5 and cpb ≤ 0.42

**Target**: **0.41–0.42 cpb** @ 64KB (median, σ < 5%)

### Work Items

1. **Reorder & Interleave**
   - Schedule CLMUL chains between VAES rounds to hide latency
   - Measure port balance: `perf stat -e uops_executed_port.port_1,uops_executed_port.port_5`
   - Target: port_1 and port_5 within 10% of each other
   - Ensure no inner-loop shuffles in GHASH (stay in kernel domain)

2. **Unroll Tuning by µarch**
   - Create dispatch table: lane-counts by CPU family
   - Example: 8-lane for Skylake, 16-lane for Rocket Lake/Raptor/Zen3
   - Add runtime detection in `core/dispatch.c`
   - Measure ILP (instructions per cycle) as sanity check

3. **One-Reduction-Per-Batch**
   - Verify reduction happens **once** per 8/16 products
   - Never mix reduced and unreduced in same XOR tree
   - Audit all GHASH kernels for consistency
   - Document reduction strategy in ARCHITECTURE.md

### Exit Criteria

- ✅ **P-gate**: uops.port_1 and uops.port_5 within 10% of each other
- ✅ **P-gate**: Frontend stalls ≤ 3%
- ✅ **0.41–0.42 cpb** @ 64KB (median, σ < 5%)
- ✅ Parity (±5%) with OpenSSL on CT-only workloads
- ✅ Consistent **+6–10%** on AAD-heavy/mixed workloads
- ✅ Update `RESULTS.md` with side-by-side comparison table

### Files Modified

- `core/gcm_fused_vaes_clmul.c` - Instruction reordering
- `core/gcm_fused16_vaes_clmul.c` - 16-lane overlap optimization
- `core/gcm_pipelined_vaes_clmul.c` - Pipeline scheduling
- `core/dispatch.c` - µarch-specific kernel selection
- `ARCHITECTURE.md` - Document reduction strategy
- `RESULTS.md` - Port balance data, performance comparison

---

## v0.4.3 — Cache Choreography

**Subtitle**: *Memory Subsystem*

**Goal**: Stabilize bandwidth and eliminate cache conflicts

**Hypothesis**: If L1 conflict misses <1% and prefetch cadence is correct, cpb ≤ 0.40

**Target**: **0.40 cpb** @ 64KB (median, σ < 5%)

### Work Items

1. **Prefetch Cadence**
   - Prefetch upcoming CT/AAD blocks **two cache lines ahead** in 16-lane kernel
   - Measure: `perf stat -e L1-dcache-load-misses,L1-dcache-prefetch-misses`
   - Target: L1 miss rate < 1%
   - Interleave loads/stores to minimize L1 set conflicts

2. **Cache-Conscious Layout**
   - Ensure H-powers table fits in single cache line set
   - Verify context structure doesn't straddle cache lines
   - Pad to avoid false sharing in future multi-threaded scenarios

3. **Empirical Tuning**
   - Test prefetch distances: 1, 2, 3 cache lines ahead
   - Measure bandwidth saturation vs prefetch aggressiveness
   - Document optimal prefetch strategy per µarch

### Exit Criteria

- ✅ **P-gate**: L1-dcache-load-misses < 1% of total loads
- ✅ **P-gate**: Memory bandwidth utilization ≥ 80% (measured via `perf mem`)
- ✅ **0.40 cpb** @ 64KB (median, σ < 5%)
- ✅ Noticeable gains at 4–16KB message sizes
- ✅ CSV shows improved AAD-only and 1:1 CT:AAD mixes

### Files Modified

- `core/gcm_fused16_vaes_clmul.c` - Prefetch instructions
- `core/gcm_pipelined16_vaes_clmul.c` - Load/store interleaving
- `core/common.h` - Cache-aligned padding
- `ARCHITECTURE.md` - Document cache strategy
- `RESULTS.md` - Multi-size performance table with L1 miss rates

---

## v0.4.4 — Throughput Synthesis

**Subtitle**: *Real-World Throughput*

**Goal**: Optimize for realistic workloads (small messages, context reuse)

**Hypothesis**: If key/H caches and small-message reuse are added, median latency for 4KB ≤ 1.2× 64KB throughput

**Target**: **0.38–0.40 cpb** @ 64KB, improved 4-16KB performance

### Work Items

1. **Context Reuse Pattern**
   - Document pattern for applications to reuse contexts across messages
   - Add "reset" API that preserves key/H-powers: `soliton_aesgcm_reset(ctx, new_iv)`
   - Amortizes init cost over multiple operations
   - Measure: 10× 4KB messages with reset vs fresh init

2. **Small Message Optimization**
   - Add fast path for messages < 1KB (avoid kernel overhead)
   - Use 4-block or single-block paths for tiny messages
   - Measure latency distribution (p50, p95, p99)

3. **Perf Stat Integration**
   - For 64KB 1:1 case, append full perf stat output to CSV:
     - `cycles, instructions, IPC`
     - `uops_executed.port_1, uops_executed.port_5`
     - `L1-dcache-load-misses, LLC-load-misses`
   - Validates instruction/memory balance

### Exit Criteria

- ✅ **P-gate**: All previous P-gate criteria still met
- ✅ **0.38–0.40 cpb** @ 64KB (median, σ < 5%)
- ✅ 4KB latency ≤ 1.2× 64KB cpb (amortized)
- ✅ Context reset API implemented and documented
- ✅ Perf stat data appended to CSV for transparency
- ✅ Results reproducible via one-command sequence in `README.md`

### Files Modified

- `include/soliton.h` - Add `soliton_aesgcm_reset()` API
- `core/dispatch.c` - Small message fast path
- `core/gcm_*.c` - Context reset implementation
- `bench/evp_benchmark.c` - Perf stat integration, multi-size sweep
- `ARCHITECTURE.md` - Document reset pattern and small-message strategy
- `README.md` - One-command reproducibility
- `RESULTS.md` - Complete empirical record with perf counters

---

## v0.4.5+ — Future Exploration (Out of Scope for 0.4.x)

**0.4.1–0.4.4** = **Deterministic mechanical tuning within invariant geometry**

**≥0.4.5** = **Extensions and exploration**

### Deferred to v0.4.5+

**AVX-512VL Path**:
- Target: ≤0.35 cpb (match/beat OpenSSL)
- 32-block batches with AVX-512
- Ice Lake+ only (no Skylake-X)
- Separate experimental branch

**ARM NEON/PMULL Optimization**:
- Current ARM implementation is basic
- Opportunity for NEON-specific scheduling
- Target: Competitive with Apple's crypto libs

**Auto-tuning System**:
- Runtime calibration of prefetch distance
- Kernel selection based on message size distribution
- Self-optimizing for workload characteristics

**Non-96-bit IV Support**:
- NIST J₀ computation for arbitrary IV lengths
- Currently only 96-bit IV validated
- Low priority (96-bit is NIST recommended)

---

## Success Metrics (Statistical Rigor)

### Performance Metrics

Each release reports:
- **Median** cpb (50th percentile)
- **σ** (standard deviation)
- **p95** latency (95th percentile)
- **p99** latency (99th percentile)

**Success Criteria**:
- Median ≤ target
- σ < 5% of median (repeatability)

### Profiling Metrics (P-gate)

Each release validates:
- Port utilization (P1, P5)
- Frontend/backend stalls
- L1/LLC cache miss rates
- IPC (instructions per cycle)

**Captured via**: `perf stat -d -x,` → merged into CSV

---

## Stability Soak (Pre-v0.5.0)

**After v0.4.4**, run week-long CI soak:

**Workload**:
- Random message sizes (64B–64KB)
- Cross-EVP fuzz with random keys/IVs
- Continuous correctness + performance monitoring

**Log**:
- Any mismatches → Gate C failure
- cpb drift > 10% → performance regression
- σ > 5% → measurement instability

**Quality Gate**: All soak metrics green → tag **v0.5.0** ("performance-complete")

---

## Microarchitectural Context

### Port Pressure (x86-64)

**VAES Instructions** (AESENC, AESENCLAST):
- Ports: P0, P1 (varies by µarch)
- Latency: 4 cycles (Skylake), 3 cycles (Ice Lake+)
- Throughput: 1/cycle (can dual-issue on some µarchs)

**VPCLMULQDQ Instructions**:
- Port: P5 (exclusive on most µarchs)
- Latency: 6 cycles (Skylake), 5 cycles (Ice Lake+)
- Throughput: 1/cycle

**Goal**: Balance VAES (P0/P1) and VPCLMULQDQ (P5) to saturate all ports

### Cache Hierarchy

**L1 Data Cache**:
- 32KB per core (typical)
- 64-byte line size
- 8-way set associative
- Latency: ~4 cycles

**L2 Cache**:
- 256KB–1MB per core
- Latency: ~12 cycles
- Critical: Keep H-powers hot (256 bytes)

**Prefetch Strategy**:
- 2 cache lines ahead (128 bytes)
- Avoid over-prefetching (pollutes cache)

---

## Measurement Environment

### Reference System

- **CPU**: Intel i9-11900F @ 2.5GHz (base, no turbo)
- **Microarchitecture**: Rocket Lake (Cypress Cove)
- **Features**: AVX2, VAES, VPCLMULQDQ, AES-NI
- **OS**: Linux (native or WSL2)
- **Compiler**: clang or gcc with `-O3 -march=native`

### Benchmark Protocol

**Setup**:
```bash
# Disable turbo boost
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# Set performance governor
sudo cpupower frequency-set -g performance

# Isolate CPU (optional, for precision)
# sudo cset shield -c 2 -k on
```

**Build**:
```bash
make clean && make libsoliton_core.a
cc -std=c17 -D_POSIX_C_SOURCE=199309L -O3 -march=native \
   -o bench/evp_benchmark bench/evp_benchmark.c -L. -lsoliton_core -lssl -lcrypto
```

**Run** (10 iterations for statistical confidence):
```bash
for i in {1..10}; do
    ./bench/evp_benchmark >> results/evp_benchmark_v041.csv
done
python tools/bench.py results/evp_benchmark_v041.csv
```

**Perf Profiling**:
```bash
perf stat -d -x, -o results/perf_v041.csv ./bench/evp_benchmark
```

---

## Reproducibility Checklist

### Before Benchmarking

- [ ] CPU governor set to `performance`
- [ ] Turbo boost disabled (or accounted for)
- [ ] No background processes (clean system)
- [ ] Consistent thermal conditions (cool down between runs)
- [ ] Git commit recorded in CSV header
- [ ] Kernel version, CPU model, compiler version logged

### During Benchmarking

- [ ] Warmup runs (100 iterations) before measurement
- [ ] Multiple runs (≥10) for statistical confidence
- [ ] Perf stat captured for each configuration
- [ ] Variance tracked (σ < 5% of median)

### After Benchmarking

- [ ] `make perf-snapshot` generates complete bundle
- [ ] CSV includes: median, σ, p95, p99, perf counters
- [ ] Results committed to `results/` with timestamp
- [ ] `RESULTS.md` updated with analysis
- [ ] P-gate criteria verified

---

## Outcome: Scientific Optimization Arc

Following this refined sequence, the **0.4.x branch becomes a clean empirical arc**:

> **Measure → Verify → Optimize → Publish → Stabilize**

Each release:
1. Tests a **singular hypothesis**
2. Passes **P-gate** (microarchitectural validation)
3. Produces **reproducible statistical evidence**
4. Documents **before/after with variance**

This makes soliton's optimization history as **legible and reproducible** as its correctness proofs.

**That's the hallmark of a mature systems project.**

---

## Performance Targets Summary

| Version | Subtitle | Target cpb @ 64KB | Key Hypothesis | Status |
|---------|----------|-------------------|----------------|--------|
| v0.4.0 | - | 0.45 | AES-NI key expansion | ✅ Shipped |
| v0.4.1a | Measurement Integrity Foundation | - | Tooling reduces variance | Planned |
| v0.4.1 | Measurement Hygiene | 0.43-0.44 | Alignment + isolation drops cpb ≥5% | Planned |
| v0.4.2 | Instruction Geometry | 0.41-0.42 | Port balance → cpb ≤ 0.42 | Planned |
| v0.4.3 | Cache Choreography | 0.40 | L1 misses <1% → cpb ≤ 0.40 | Planned |
| v0.4.4 | Throughput Synthesis | 0.38-0.40 | Context reuse + small-msg | Planned |

**OpenSSL baseline**: 0.35 cpb

---

**Document Version**: 2.0 (Refined)
**Author**: Airo Intelligence-Designer
**Date**: 2025-10-22
**Status**: Experimental roadmap with falsifiable hypotheses
