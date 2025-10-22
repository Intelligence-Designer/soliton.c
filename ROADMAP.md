# soliton.c Optimization Roadmap v0.4.1 → v0.4.4

**Philosophy**: Evidence-based, incremental optimization within existing architecture.
**Target**: ≤0.40 cpb @ 64KB (close or beat OpenSSL's 0.35 cpb baseline)

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

## Optimization Potential

### Realistic Targets (AVX2+VAES, single-thread, evidence-based)

**Short term** (configuration + scheduling):
→ **0.40–0.42 cpb** (≈10–12% gain)

**Medium term** (deeper overlap + cache/lanes):
→ **0.38–0.40 cpb** on Skylake/Raptor/Zen class

**Longer term** (AVX-512VL on Ice Lake+):
→ **≤0.35 cpb** (matches or beats OpenSSL)
*Keep this out of 0.4.x train; focus on AVX2 first*

**Headroom**: Pure microarchitecture — instruction scheduling, port pressure balance (VAES vs VPCLMULQDQ), interleave/unroll, prefetch & alignment. No algorithmic changes, no exotics.

---

## v0.4.1 — Bench Hygiene + Low-Risk Wins

**Goal**: Lock steady-state benchmark, remove measurement bias, harvest easy cpb

**Target**: **≤0.43–0.44 cpb** @ 64KB

### Work Items

1. **Bench Correctness**
   - Ensure EVP bench measures stream time only (separate init/setup vs update)
   - Already encouraged by results documentation
   - Expect visible drop when reporting stream-only cpb

2. **Path Banners + Guards**
   - Always print which backend ran: `scalar / AES-NI / VAES fused`
   - Prevent false greens from incorrect backend selection
   - Add to `bench/evp_benchmark.c`

3. **Alignment & Layout**
   - 64-byte align GCM context and `H^n` tables
   - Avoid split-line loads in GHASH and AES counter prep
   - Cheap, safe wins given documented memory layout
   - Modify `core/common.h` context structure

### Exit Criteria

- ✅ CSV shows stream-only **≤0.43–0.44 cpb** @ 64KB on reference box
- ✅ Results + repro steps committed to `results/` and `RESULTS.md`
- ✅ Backend identification in benchmark output

### Files Modified

- `bench/evp_benchmark.c` - Stream-only measurement, backend banner
- `core/common.h` - 64-byte aligned context
- `RESULTS.md` - Updated with v0.4.1 results

---

## v0.4.2 — VAES↔VPCLMULQDQ Overlap & Lane Scheduling

**Goal**: Keep port 1/5 saturated, shorten critical path in 8-/16-lane kernels

**Target**: **≤0.41–0.42 cpb** @ 64KB

### Work Items

1. **Reorder & Interleave**
   - Schedule CLMUL chains between VAES rounds to hide latency
   - Ensure no inner-loop shuffles in GHASH (stay in kernel domain)
   - Already doing this, but can optimize further
   - Focus on `core/gcm_fused_vaes_clmul.c` and `core/gcm_fused16_vaes_clmul.c`

2. **Unroll Tuning by µarch**
   - Create table of lane-counts and unroll by CPU
   - Example: 8-lane for Skylake, 16-lane for Raptor/Zen
   - Add runtime detection in `core/dispatch.c`

3. **One-Reduction-Per-Batch**
   - Verify reduction happens once per 8/16 products
   - Never mix reduced and unreduced in same XOR tree
   - Architecture doc already outlines batch math; keep canonical
   - Audit all GHASH kernels for consistency

### Exit Criteria

- ✅ **≤0.41–0.42 cpb** @ 64KB
- ✅ Parity (±5%) with OpenSSL on CT-only workloads
- ✅ Consistent **+6–10%** on AAD-heavy/mixed workloads
- ✅ Update `RESULTS.md` with side-by-side comparison table

### Files Modified

- `core/gcm_fused_vaes_clmul.c` - Instruction reordering
- `core/gcm_fused16_vaes_clmul.c` - 16-lane optimization
- `core/gcm_pipelined_vaes_clmul.c` - Pipeline scheduling
- `core/dispatch.c` - µarch-specific kernel selection
- `RESULTS.md` - Performance comparison tables

---

## v0.4.3 — Prefetch & Context Reuse (Real-World Throughput)

**Goal**: Stabilize bandwidth and small/medium message performance

**Target**: **≤0.40 cpb** @ 64KB

### Work Items

1. **Prefetch Cadence**
   - Prefetch upcoming CT/AAD blocks two cache lines ahead in 16-lane kernel
   - Interleave loads/stores to minimize L1 set conflicts
   - Architecture sketch lists kernel variants; apply measured prefetch
   - Careful tuning required (too aggressive = slowdown)

2. **Provider-Layer Context Cache**
   - Reuse expanded keys and `H^n` across messages in same session
   - OpenSSL does this; repo philosophy supports pragmatic performance
   - Requires provider integration (currently not built)
   - Alternative: Document pattern for applications to reuse contexts

### Exit Criteria

- ✅ **≤0.40 cpb** @ 64KB
- ✅ Noticeable gains at 4–16KB message sizes
- ✅ CSV shows improved AAD-only and 1:1 CT:AAD mixes
- ✅ Context reuse pattern documented (or provider implementation)

### Files Modified

- `core/gcm_fused16_vaes_clmul.c` - Prefetch instructions
- `core/gcm_pipelined16_vaes_clmul.c` - Load/store interleaving
- Provider layer (if integrated) or documentation
- `RESULTS.md` - Multi-size performance table

---

## v0.4.4 — Final Polish & Publication

**Goal**: Lock reproducibility and ship the performance paper trail

**Target**: **0.38–0.40 cpb** @ 64KB

### Work Items

1. **Perf Stat Append**
   - For 64KB 1:1 case, record:
     - `cycles, instructions`
     - `uops_executed.port_1, uops_executed.port_5`
     - `cache-misses`
   - Append to CSV to document overlap health
   - Validates VAES/VPCLMULQDQ port balance

2. **Architecture & Results Docs**
   - Finalize `ARCHITECTURE.md` with actual design
   - Keep `RESULTS.md` strictly empirical (before/after tables, environment headers)
   - Already started; ensure completeness

3. **Canonical Repo Discipline**
   - Keep **only** working code, accurate docs, and benchmark CSVs
   - This is the explicit contract
   - No aspirational features, no dead code

### Exit Criteria

- ✅ **0.38–0.40 cpb** @ 64KB achieved on reference box
- ✅ Results reproducible via one command sequence in `README.md`
- ✅ Perf stat data appended to CSV for transparency
- ✅ Documentation complete and accurate

### Files Modified

- `bench/evp_benchmark.c` - Perf stat integration
- `ARCHITECTURE.md` - Final completeness review
- `RESULTS.md` - Complete empirical record
- `README.md` - One-command reproducibility

---

## Why This Will Work

### Architecture is Ready

Current design has **all** the right levers:
- ✅ Dispatch system (runtime backend selection)
- ✅ Fused kernels (8-block, 16-block variants)
- ✅ Batch GHASH (multi-block accumulation)
- ✅ Verified domain discipline (spec ↔ internal transforms)

We're not inventing new machinery — just **turning the knobs the architecture already exposes**.

### Repository Philosophy Alignment

Publish **only what exists and is reproducible**:
- Each 0.4.x release comes with CSVs + steps
- No promises, only measurements
- Clean, canonical code and documentation

---

## Crisp Acceptance Gates Per Release

### Correctness Gates (P0/A/B/C)
**MUST stay green on every commit**

- Gate P0 (Product Equivalence): 262/262 PASS
- Gate A (Commuting Diagram): 1000/1000 PASS
- Gate B (NIST 96-bit IV): 4/4 PASS
- Gate C (Cross-EVP Fuzz): 10,000/10,000 PASS

### Benchmark Gate
**Median cpb @ 64KB (1:1 mix) meets target band for that version**

- CSV lands in `results/` with CPU/µcode/flags header
- Results section in `RESULTS.md` updated
- Reproducible via `README.md` instructions

---

## Microarchitectural Considerations

### Port Pressure (x86-64)

**VAES Instructions** (AESENC, AESENCLAST):
- Ports: P0, P1 (varies by µarch)
- Latency: 4 cycles (Skylake), 3 cycles (Ice Lake+)
- Throughput: 1/cycle (can dual-issue on some µarchs)

**VPCLMULQDQ Instructions**:
- Port: P5 (exclusive on most µarchs)
- Latency: 6 cycles (Skylake), 5 cycles (Ice Lake+)
- Throughput: 1/cycle

**Goal**: Balance VAES (P0/P1) and VPCLMULQDQ (P5) to avoid bottlenecks

### Cache Optimization

**L1 Cache**:
- 32KB per core (typical)
- 64-byte line size
- 8-way set associative
- **Prefetch 2 lines ahead to hide latency**

**L2 Cache**:
- 256KB–1MB per core
- Critical for H-power table (256 bytes, keep hot)

---

## Performance Targets Summary

| Version | Target cpb @ 64KB | Key Optimization | Status |
|---------|-------------------|------------------|--------|
| v0.4.0 | 0.45 | AES-NI key expansion | ✅ Shipped |
| v0.4.1 | 0.43–0.44 | Bench hygiene + alignment | Planned |
| v0.4.2 | 0.41–0.42 | VAES/CLMUL overlap | Planned |
| v0.4.3 | 0.40 | Prefetch + context reuse | Planned |
| v0.4.4 | 0.38–0.40 | Polish + publication | Planned |

**OpenSSL baseline**: 0.35 cpb

---

## Beyond 0.4.x (Future Work, Out of Scope for Now)

### AVX-512 Path (v0.5.0+)
- Target: **≤0.35 cpb** (match/beat OpenSSL)
- 32-block batches with AVX-512
- Ice Lake+ only (no Skylake-X)
- Separate track after AVX2 path is mature

### ARM NEON Optimization
- Current ARM implementation is basic
- Opportunity for NEON-specific scheduling
- Target: Competitive with Apple's crypto libs

### Non-96-bit IV Support
- NIST J₀ computation for arbitrary IV lengths
- Currently only 96-bit IV validated
- Low priority (96-bit is standard)

---

## Measurement Environment

**Reference System**:
- CPU: Intel i9-11900F @ 2.5GHz (base, no turbo)
- Microarchitecture: Rocket Lake (Cypress Cove)
- Features: AVX2, VAES, VPCLMULQDQ, AES-NI
- OS: Linux (native or WSL2)
- Compiler: clang or gcc with `-O3 -march=native`

**Benchmark Command**:
```bash
make clean && make libsoliton_core.a
cc -std=c17 -D_POSIX_C_SOURCE=199309L -O3 -march=native \
   -o bench/evp_benchmark bench/evp_benchmark.c -L. -lsoliton_core -lssl -lcrypto
./bench/evp_benchmark > results/evp_benchmark_v041.csv
```

**Perf Profiling** (v0.4.4):
```bash
perf stat -d ./bench/evp_benchmark 2>&1 | tee results/perf_stat_v044.txt
```

---

## Conclusion

**Bottom Line**: With disciplined scheduling, small structural tweaks, and hard measurement, **0.38–0.40 cpb** on AVX2+VAES is within reach in the 0.4.x line.

This puts soliton.c at — or just ahead of — OpenSSL for mixed workloads, while staying **brutally reproducible** and true to the **canonical repository standard**.

---

**Document Version**: 1.0
**Author**: Airo Intelligence-Designer
**Date**: 2025-10-22
**Status**: Roadmap for v0.4.1 → v0.4.4
