# soliton.c Tools (v0.4.1a)

Measurement and reproducibility tools for performance analysis.

---

## bench.py - Statistical Analysis

**Purpose**: Compute statistical metrics from benchmark CSV results.

**Usage**:
```bash
python tools/bench.py results/benchmark.csv
python tools/bench.py results/benchmark.csv --format csv
```

**Metrics Computed**:
- **Median**: 50th percentile (target metric)
- **σ** (stdev): Standard deviation (repeatability)
- **%CV**: Coefficient of variation (σ/median × 100)
- **p95/p99**: 95th/99th percentile latency

**Success Criteria**:
- Exit code 0: %CV < 5% (reproducible)
- Exit code 1: %CV ≥ 5% (high variance, investigate)

**Output Formats**:
- `table` (default): Human-readable analysis
- `csv`: Machine-readable summary for further processing

**Example**:
```bash
$ python tools/bench.py results/snapshot_20251022_143000/benchmark.csv

================================================================================
Benchmark Statistical Analysis
================================================================================

Metadata:
  Timestamp: 20251022_143000
  Git Commit: 62f0350abcd...
  Iterations: 10

Size       Metric   Median       σ            %CV      p95          p99          Status
--------------------------------------------------------------------------------
64         cpb      0.4520       0.0187       4.13     0.4680       0.4720       ✓ OK
256        cpb      0.4502       0.0156       3.46     0.4630       0.4650       ✓ OK
1024       cpb      0.4495       0.0168       3.74     0.4640       0.4670       ✓ OK

Overall Status: PASS ✓ (variance < 5%)
Max %CV: 4.13% (threshold: <5%)
================================================================================
```

---

## repro.sh - Reproducible Benchmark Runner

**Purpose**: Automate reproducible performance measurements with full environment capture.

**Usage**:
```bash
./tools/repro.sh [iterations]
```

**Default**: 10 iterations (adjust for desired confidence level)

**What it does**:
1. **System checks**: CPU governor, turbo boost, system load
2. **Build**: Clean build with consistent flags
3. **Warmup**: 100 iterations to stabilize cache/branch predictor
4. **Measurement**: N iterations with cycle-accurate timing
5. **Perf capture**: `perf stat -d` if available
6. **Analysis**: Statistical validation with bench.py
7. **Bundle**: Complete snapshot in `results/snapshot_YYYYMMDD_HHMMSS/`

**Output Files**:
- `benchmark.csv` - Measurement data
- `environment.txt` - System configuration (CPU, kernel, compiler, git commit)
- `analysis.txt` - Statistical analysis results
- `perf_stat.txt` - Perf counters (if available)

**Example**:
```bash
$ ./tools/repro.sh 10

==========================================
soliton.c Reproducible Benchmark
==========================================

Timestamp: 20251022_143000
Iterations: 10

Checking system configuration...

CPU Governor: performance
[✓] CPU governor is 'performance'
[✓] Turbo boost is DISABLED (good for reproducibility)
System load: 0.15

Capturing environment metadata...
[✓] Environment metadata saved to results/snapshot_20251022_143000/environment.txt

Building soliton.c...
[✓] Built libsoliton_core.a
[✓] Built bench/evp_benchmark

Running warmup (100 iterations)...
[✓] Warmup complete

Running measurement (10 iterations)...
  Iteration 1/10... done
  Iteration 2/10... done
  ...
[✓] Measurement complete
[✓] Results saved to results/snapshot_20251022_143000/benchmark.csv

Capturing perf stat...
[✓] Perf stat saved to results/snapshot_20251022_143000/perf_stat.txt

Analyzing results...
[✓] Statistical analysis passed (σ < 5%)

==========================================
Benchmark Complete
==========================================

Results directory: results/snapshot_20251022_143000

Status: PASS ✓ (variance < 5%)

To reproduce these results:
  ./tools/repro.sh 10
==========================================
```

---

## Makefile Target: perf-snapshot

**Purpose**: Convenient shorthand for running reproducible benchmarks.

**Usage**:
```bash
make perf-snapshot
```

**Equivalent to**:
```bash
make libsoliton_core.a
./tools/repro.sh 10
```

---

## Best Practices

### For Reproducible Measurements

1. **Disable CPU Turbo Boost**:
   ```bash
   echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
   ```

2. **Set Performance Governor**:
   ```bash
   sudo cpupower frequency-set -g performance
   ```

3. **Minimize Background Activity**:
   - Close unnecessary applications
   - Disable background services during benchmarking
   - Check system load: `uptime`

4. **Thermal Stability**:
   - Allow system to cool between runs
   - Monitor CPU temperature
   - Consistent ambient temperature

5. **Multiple Runs**:
   - Run ≥10 iterations for statistical confidence
   - Verify %CV < 5% before accepting results

### For Performance Analysis

1. **Use bench.py** to validate reproducibility
2. **Check perf counters** for microarchitectural insights
3. **Document environment** (git commit, CPU, compiler)
4. **Commit results** to `results/` with timestamps

---

## Integration with Roadmap

**v0.4.1a** (Tooling Polish):
- ✅ `bench.py` for statistical analysis
- ✅ `repro.sh` for reproducible benchmarking
- ✅ `make perf-snapshot` for convenience

**v0.4.1** (Measurement Hygiene):
- Will use these tools to validate alignment optimizations
- Target: σ < 5% across all message sizes

**v0.4.2+** (Instruction Geometry, Cache Choreography):
- Perf stat integration for port utilization analysis
- L1/LLC cache miss rate tracking

---

## Troubleshooting

### High Variance (%CV ≥ 5%)

**Symptoms**:
```
Status: WARN ⚠ (high variance or analysis unavailable)
```

**Causes**:
- CPU turbo boost enabled
- CPU governor not set to 'performance'
- Background processes consuming CPU
- Thermal throttling
- Insufficient warmup

**Solutions**:
1. Follow "Best Practices" above
2. Increase warmup iterations in repro.sh
3. Run on dedicated/isolated system
4. Check CPU temperature/cooling

### Perf Stat Not Available

**Symptoms**:
```
[⚠] perf not available (skipping perf stat)
```

**Causes**:
- WSL2 environment (perf requires native Linux)
- Missing linux-tools package
- Insufficient permissions

**Solutions**:
- Run on native Linux for full perf support
- Install: `sudo apt install linux-tools-generic`
- Use sudo: `sudo ./tools/repro.sh 10` (not recommended)

---

## Version History

**v0.4.1a** (2025-10-22):
- Initial tooling release
- bench.py: Statistical analysis
- repro.sh: Reproducible benchmarking
- Makefile integration

---

**Philosophy**: Measure → Verify → Optimize → Publish → Stabilize

**Canonical Repository**: https://github.com/Intelligence-Designer/soliton.c
