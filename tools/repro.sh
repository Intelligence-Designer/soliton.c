#!/bin/bash
#
# repro.sh - Reproducible benchmark script for soliton.c
#
# This script ensures reproducible performance measurements by:
# - Checking system configuration (CPU governor, turbo, etc.)
# - Building with consistent flags
# - Running controlled warmup and measurement
# - Capturing environment metadata
# - Analyzing results statistically
#
# Usage:
#   ./tools/repro.sh [iterations]
#
# Example:
#   ./tools/repro.sh 10    # Run 10 iterations for statistical confidence
#

set -e

# Configuration
ITERATIONS=${1:-10}
WARMUP_ITERATIONS=100
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="results/snapshot_${TIMESTAMP}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "soliton.c Reproducible Benchmark"
echo "=========================================="
echo ""
echo "Timestamp: ${TIMESTAMP}"
echo "Iterations: ${ITERATIONS}"
echo ""

# Function: Print status messages
status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Create results directory
mkdir -p "${RESULTS_DIR}"
status "Created results directory: ${RESULTS_DIR}"

# ================================================
# System Configuration Checks
# ================================================

echo ""
echo "Checking system configuration..."
echo ""

# Check CPU governor
check_governor() {
    if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
        GOVERNOR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
        echo "CPU Governor: ${GOVERNOR}"

        if [ "${GOVERNOR}" != "performance" ]; then
            warning "CPU governor is NOT set to 'performance'"
            warning "For best reproducibility, set:"
            warning "  sudo cpupower frequency-set -g performance"
            echo ""
            read -p "Continue anyway? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        else
            status "CPU governor is 'performance'"
        fi
    else
        warning "Cannot check CPU governor (WSL2 or no cpufreq)"
    fi
}

# Check turbo boost
check_turbo() {
    if [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
        TURBO=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)
        if [ "${TURBO}" == "1" ]; then
            status "Turbo boost is DISABLED (good for reproducibility)"
        else
            warning "Turbo boost is ENABLED"
            warning "For best reproducibility, disable:"
            warning "  echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo"
        fi
    else
        warning "Cannot check turbo boost status"
    fi
}

# Check background processes
check_load() {
    LOAD=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    echo "System load: ${LOAD}"

    # Simple heuristic: load > 1.0 might indicate background activity
    if (( $(echo "${LOAD} > 1.0" | bc -l) )); then
        warning "System load is high (${LOAD})"
        warning "Background processes may affect benchmark results"
    fi
}

check_governor
check_turbo
check_load

# ================================================
# Capture Environment Metadata
# ================================================

echo ""
echo "Capturing environment metadata..."
echo ""

capture_metadata() {
    local meta_file="${RESULTS_DIR}/environment.txt"

    {
        echo "# soliton.c Benchmark Environment"
        echo "# Generated: ${TIMESTAMP}"
        echo ""
        echo "## Git"
        echo "Commit: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
        echo "Branch: $(git branch --show-current 2>/dev/null || echo 'unknown')"
        echo "Dirty: $(git diff --quiet && echo 'no' || echo 'yes')"
        echo ""
        echo "## System"
        echo "Kernel: $(uname -r)"
        echo "OS: $(uname -o)"
        echo "Architecture: $(uname -m)"
        echo ""
        echo "## CPU"
        if [ -f /proc/cpuinfo ]; then
            grep "model name" /proc/cpuinfo | head -1 | sed 's/model name.*: /CPU: /'
            grep "cpu MHz" /proc/cpuinfo | head -1 | sed 's/cpu MHz.*: /Frequency: /' | awk '{print $1 " " $2 " MHz"}'
            grep "flags" /proc/cpuinfo | head -1 | grep -o "vaes\|vpclmulqdq\|aes\|pclmul" | sort -u | tr '\n' ' ' | sed 's/^/CPU Flags: /'
            echo ""
        fi
        echo ""
        echo "## Compiler"
        ${CC:-cc} --version | head -1 || echo "unknown"
        echo "CFLAGS: -std=c17 -O3 -march=native"
        echo ""
        echo "## Configuration"
        if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
            echo "CPU Governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
        fi
        if [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
            TURBO=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)
            echo "Turbo Disabled: $([ "${TURBO}" == "1" ] && echo 'yes' || echo 'no')"
        fi
        echo ""
    } > "${meta_file}"

    status "Environment metadata saved to ${meta_file}"
}

capture_metadata

# ================================================
# Build
# ================================================

echo ""
echo "Building soliton.c..."
echo ""

make clean >/dev/null 2>&1 || true
if make libsoliton_core.a >/dev/null 2>&1; then
    status "Built libsoliton_core.a"
else
    error "Failed to build libsoliton_core.a"
    exit 1
fi

# Build benchmark
CC=${CC:-cc}
BENCH_SRC="bench/evp_benchmark.c"
BENCH_BIN="bench/evp_benchmark"

if [ ! -f "${BENCH_SRC}" ]; then
    error "Benchmark source not found: ${BENCH_SRC}"
    exit 1
fi

${CC} -std=c17 -D_POSIX_C_SOURCE=199309L -O3 -march=native \
    -o "${BENCH_BIN}" "${BENCH_SRC}" -L. -lsoliton_core -lssl -lcrypto >/dev/null 2>&1

if [ -f "${BENCH_BIN}" ]; then
    status "Built ${BENCH_BIN}"
else
    error "Failed to build ${BENCH_BIN}"
    exit 1
fi

# ================================================
# Warmup
# ================================================

echo ""
echo "Running warmup (${WARMUP_ITERATIONS} iterations)..."
echo ""

for i in $(seq 1 ${WARMUP_ITERATIONS}); do
    "${BENCH_BIN}" >/dev/null 2>&1 || true
done

status "Warmup complete"

# ================================================
# Measurement
# ================================================

echo ""
echo "Running measurement (${ITERATIONS} iterations)..."
echo ""

CSV_FILE="${RESULTS_DIR}/benchmark.csv"

# Add CSV header with metadata
{
    echo "# soliton.c Benchmark Results"
    echo "# Timestamp: ${TIMESTAMP}"
    echo "# Git Commit: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
    echo "# Iterations: ${ITERATIONS}"
    echo "# Warmup: ${WARMUP_ITERATIONS}"
    echo "#"
    echo "# Format: size,cycles,cpb"
} > "${CSV_FILE}"

for i in $(seq 1 ${ITERATIONS}); do
    echo -n "  Iteration $i/${ITERATIONS}... "
    "${BENCH_BIN}" >> "${CSV_FILE}" 2>&1
    echo "done"
done

status "Measurement complete"
status "Results saved to ${CSV_FILE}"

# ================================================
# Perf Stat (if available)
# ================================================

echo ""
echo "Capturing perf stat..."
echo ""

PERF_FILE="${RESULTS_DIR}/perf_stat.txt"

if command -v perf >/dev/null 2>&1; then
    perf stat -d "${BENCH_BIN}" > /dev/null 2> "${PERF_FILE}" || true
    if [ -f "${PERF_FILE}" ] && [ -s "${PERF_FILE}" ]; then
        status "Perf stat saved to ${PERF_FILE}"
    else
        warning "Perf stat capture failed (may need sudo or Linux native)"
    fi
else
    warning "perf not available (skipping perf stat)"
fi

# ================================================
# Statistical Analysis
# ================================================

echo ""
echo "Analyzing results..."
echo ""

if [ -f "tools/bench.py" ]; then
    if python3 tools/bench.py "${CSV_FILE}" > "${RESULTS_DIR}/analysis.txt"; then
        cat "${RESULTS_DIR}/analysis.txt"
        status "Statistical analysis passed (σ < 5%)"
        ANALYSIS_OK=1
    else
        cat "${RESULTS_DIR}/analysis.txt"
        warning "Statistical analysis failed (σ ≥ 5%)"
        ANALYSIS_OK=0
    fi
else
    warning "tools/bench.py not found (skipping analysis)"
    ANALYSIS_OK=0
fi

# ================================================
# Summary
# ================================================

echo ""
echo "=========================================="
echo "Benchmark Complete"
echo "=========================================="
echo ""
echo "Results directory: ${RESULTS_DIR}"
echo ""
echo "Files generated:"
echo "  - benchmark.csv        Measurement data"
echo "  - environment.txt      System configuration"
echo "  - analysis.txt         Statistical analysis"
if [ -f "${PERF_FILE}" ]; then
    echo "  - perf_stat.txt        Perf counters"
fi
echo ""

if [ "${ANALYSIS_OK}" == "1" ]; then
    echo -e "${GREEN}Status: PASS ✓${NC} (variance < 5%)"
    echo ""
    echo "Results are reproducible and ready for documentation."
else
    echo -e "${YELLOW}Status: WARN ⚠${NC} (high variance or analysis unavailable)"
    echo ""
    echo "Consider:"
    echo "  - Disabling CPU turbo boost"
    echo "  - Setting CPU governor to 'performance'"
    echo "  - Eliminating background processes"
    echo "  - Allowing system to cool"
fi

echo ""
echo "To reproduce these results:"
echo "  ./tools/repro.sh ${ITERATIONS}"
echo ""
echo "=========================================="
