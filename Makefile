# soliton.c Makefile
# Freestanding C17 cryptographic engine

# Compiler selection
CC ?= clang
AR = ar

# Base flags
CSTD = -std=c17
FREESTANDING = -ffreestanding -fno-builtin -fstrict-aliasing
OPT = -O3 -fomit-frame-pointer
WARNINGS = -Wall -Wextra -Wpedantic -Werror
INCLUDES = -I./include -I./core

# Core flags (freestanding, with -fPIC for shared library compatibility)
CORE_FLAGS = $(CSTD) $(FREESTANDING) $(OPT) $(WARNINGS) $(INCLUDES) -fPIC

# Hosted flags (for CLI/provider)
HOSTED_FLAGS = $(CSTD) $(OPT) $(WARNINGS) $(INCLUDES)

# Backend-specific flags
VAES_FLAGS = -mvaes -mvpclmulqdq -mavx2 -maes -mpclmul -mssse3
AVX512_FLAGS = -mavx512f -mavx512vl
AVX2_FLAGS = -mavx2
NEON_FLAGS = -march=armv8-a+crypto

# Object files
CORE_SCALAR_OBJS = \
	core/aes_scalar.o \
	core/gcm_scalar.o \
	core/chacha_scalar.o \
	core/poly1305_scalar.o \
	core/dispatch.o \
	core/diagnostics.o

SCHED_OBJS = \
	sched/lanes.o \
	sched/persist.o \
	sched/superlane.o \
	sched/autotune.o \
	sched/plan.o \
	sched/plan_log.o

# Detect architecture
ARCH := $(shell uname -m)

# Vector backends (conditionally compiled based on CPU features)
VECTOR_OBJS =

# X86-64 vector backends
ifeq ($(ARCH),x86_64)
    # Check for AVX2 support
    AVX2_SUPPORTED := $(shell echo | $(CC) -mavx2 -dM -E - 2>/dev/null | grep -q __AVX2__ && echo yes)
    ifeq ($(AVX2_SUPPORTED),yes)
        VECTOR_OBJS += core/chacha_avx2.o
    endif

    # Check for AES-NI support (for fast single-block encryption + key expansion)
    AESNI_SUPPORTED := $(shell echo | $(CC) -maes -dM -E - 2>/dev/null | grep -q __AES__ && echo yes)
    ifeq ($(AESNI_SUPPORTED),yes)
        VECTOR_OBJS += core/aes_aesni.o core/aes256_key_expand_aesni.o
    endif

    # Check for VAES support (requires both VAES and AES-NI)
    VAES_SUPPORTED := $(shell echo | $(CC) -mvaes -maes -dM -E - 2>/dev/null | grep -q __VAES__ && echo yes)
    ifeq ($(VAES_SUPPORTED),yes)
        VECTOR_OBJS += core/aes_vaes.o
    endif

    # Check for PCLMUL support
    PCLMUL_SUPPORTED := $(shell echo | $(CC) -mpclmul -dM -E - 2>/dev/null | grep -q __PCLMUL__ && echo yes)
    ifeq ($(PCLMUL_SUPPORTED),yes)
        VECTOR_OBJS += core/ghash_clmul.o
    endif

    # Check for VAES+PCLMUL (enables fused GCM kernel + pipelined kernels + depth-16 kernels)
    VAES_PCLMUL_SUPPORTED := $(shell echo | $(CC) -mvaes -mvpclmulqdq -maes -mpclmul -dM -E - 2>/dev/null | grep -q __VAES__ && echo yes)
    ifeq ($(VAES_PCLMUL_SUPPORTED),yes)
        VECTOR_OBJS += core/gcm_fused_vaes_clmul.o core/gcm_pipelined_vaes_clmul.o core/gcm_fused16_vaes_clmul.o core/gcm_pipelined16_vaes_clmul.o
    endif
endif

ALL_CORE_OBJS = $(CORE_SCALAR_OBJS) $(VECTOR_OBJS) $(SCHED_OBJS)

# Targets
.PHONY: all clean test bench diag bench-artifacts

all: libsoliton_core.a soliton

libsoliton_core.a: $(ALL_CORE_OBJS)
	$(AR) rcs $@ $^
	@echo "Built static library: $@"

# Scalar backends (freestanding)
core/aes_scalar.o: core/aes_scalar.c
	$(CC) $(CORE_FLAGS) -c -o $@ $<

core/gcm_scalar.o: core/gcm_scalar.c
	$(CC) $(CORE_FLAGS) -c -o $@ $<

core/chacha_scalar.o: core/chacha_scalar.c
	$(CC) $(CORE_FLAGS) -c -o $@ $<

core/poly1305_scalar.o: core/poly1305_scalar.c
	$(CC) $(CORE_FLAGS) -c -o $@ $<

core/dispatch.o: core/dispatch.c
ifeq ($(ARCH),x86_64)
	$(CC) $(CORE_FLAGS) -mavx2 -mvaes -mpclmul -c -o $@ $<
else ifeq ($(ARCH),aarch64)
	$(CC) $(CORE_FLAGS) -march=armv8-a+crypto -c -o $@ $<
else
	$(CC) $(CORE_FLAGS) -c -o $@ $<
endif

core/diagnostics.o: core/diagnostics.c
	$(CC) $(CORE_FLAGS) -c -o $@ $<

# Vector backends - X86-64
core/chacha_avx2.o: core/chacha_avx2.c
	$(CC) $(CORE_FLAGS) $(AVX2_FLAGS) -c -o $@ $<

core/aes_aesni.o: core/aes_aesni.c
	$(CC) $(CORE_FLAGS) -maes -c -o $@ $<

core/aes256_key_expand_aesni.o: core/aes256_key_expand_aesni.c
	$(CC) $(CORE_FLAGS) -maes -c -o $@ $<

core/aes_vaes.o: core/aes_vaes.c
	$(CC) $(CORE_FLAGS) $(VAES_FLAGS) -c -o $@ $<

core/ghash_clmul.o: core/ghash_clmul.c
	$(CC) $(CORE_FLAGS) -mpclmul -maes -mssse3 -c -o $@ $<

core/gcm_fused_vaes_clmul.o: core/gcm_fused_vaes_clmul.c
	$(CC) $(CORE_FLAGS) $(VAES_FLAGS) -c -o $@ $<

core/gcm_pipelined_vaes_clmul.o: core/gcm_pipelined_vaes_clmul.c
	$(CC) $(CORE_FLAGS) $(VAES_FLAGS) -c -o $@ $<

core/gcm_fused16_vaes_clmul.o: core/gcm_fused16_vaes_clmul.c
	$(CC) $(CORE_FLAGS) $(VAES_FLAGS) -c -o $@ $<

core/gcm_pipelined16_vaes_clmul.o: core/gcm_pipelined16_vaes_clmul.c
	$(CC) $(CORE_FLAGS) $(VAES_FLAGS) -c -o $@ $<

# Vector backends - ARM
ifeq ($(ARCH),aarch64)
    # Check for NEON support (standard on ARMv8)
    VECTOR_OBJS += core/chacha_neon.o

    # Check for crypto extensions
    CRYPTO_SUPPORTED := $(shell echo | $(CC) -march=armv8-a+crypto -dM -E - 2>/dev/null | grep -q __ARM_FEATURE_CRYPTO && echo yes)
    ifeq ($(CRYPTO_SUPPORTED),yes)
        VECTOR_OBJS += core/aes_neon.o core/ghash_pmull.o
    endif
endif

# ARM NEON backends
core/aes_neon.o: core/aes_neon.c
	$(CC) $(CORE_FLAGS) -march=armv8-a+crypto -c -o $@ $<

core/ghash_pmull.o: core/ghash_pmull.c
	$(CC) $(CORE_FLAGS) -march=armv8-a+crypto -c -o $@ $<

core/chacha_neon.o: core/chacha_neon.c
	$(CC) $(CORE_FLAGS) -march=armv8-a -c -o $@ $<

# Scheduler objects
sched/%.o: sched/%.c
	$(CC) $(CORE_FLAGS) -c -o $@ $<

# CLI tool (hosted)
cli/soliton.o: cli/soliton.c
	$(CC) $(HOSTED_FLAGS) -c -o $@ $<

soliton: cli/soliton.o libsoliton_core.a
	$(CC) $(HOSTED_FLAGS) -o $@ $^
	@echo "Built CLI tool: $@"

# OpenSSL providers
provider: solitonprov.so glidepathprov.so

# Legacy provider (basic EVP wrapper)
solitonprov.so: provider/soliton_provider.o libsoliton_core.a
	$(CC) -shared -fPIC -o $@ $< -L. -lsoliton_core -lcrypto
	@echo "Built OpenSSL 3.x provider: $@"

provider/soliton_provider.o: provider/soliton_provider.c
	$(CC) $(HOSTED_FLAGS) -fPIC -c -o $@ $<

# Glidepath Provider (v1.8.1 - Compatibility Mode)
glidepathprov.so: provider/glidepath_provider.o libsoliton_core.a
	$(CC) -shared -fPIC -o $@ $< -L. -lsoliton_core -lcrypto
	@echo "Built Glidepath Provider (v1.8.1): $@"

provider/glidepath_provider.o: provider/glidepath_provider.c
	$(CC) $(HOSTED_FLAGS) -fPIC -c -o $@ $<

# Testing
test: libsoliton_core.a test/test_suite
	./test/test_suite
	@echo "Test suite completed"

test/test_suite: test/test_suite.c libsoliton_core.a
	$(CC) $(HOSTED_FLAGS) -o $@ $< -L. -lsoliton_core

# Gate P0: Product Equivalence Test (256-bit CLMUL product verification)
test/test_mul_product: test/test_mul_product.c
	$(CC) -O2 -mpclmul -mssse3 -msse4.1 -o $@ $<
	@echo "Built Gate P0 test: $@"

# Gate A: Commuting Diagram Test (GHASH correctness proof)
test/test_commute: test/test_commute.c libsoliton_core.a
	$(CC) -O2 -mpclmul -mssse3 -I./include -I./core -o $@ $< -L. -lsoliton_core
	@echo "Built Gate A test: $@"

test/test_ghash_edges: test/test_ghash_edges.c libsoliton_core.a
	$(CC) -O2 -mpclmul -mssse3 -I./include -I./core -o $@ $< -L. -lsoliton_core
	@echo "Built Gate A edge test: $@"

# Gate B: NIST SP 800-38D Test Vectors
test/test_gcm_nist: test/test_gcm_nist.c libsoliton_core.a
	$(CC) $(HOSTED_FLAGS) -o $@ $< -L. -lsoliton_core
	@echo "Built Gate B test: $@"

# Gate C: Cross-EVP Fuzzing vs OpenSSL
test/test_gcm_cross_evp: test/test_gcm_cross_evp.c libsoliton_core.a
	$(CC) $(HOSTED_FLAGS) -o $@ $< -L. -lsoliton_core -lcrypto
	@echo "Built Gate C test: $@"

# Run all gates (proof obligations)
test-gates: test/test_mul_product test/test_commute test/test_ghash_edges test/test_gcm_nist test/test_gcm_cross_evp
	@echo "=========================================="
	@echo "  Running Gate P0 (Product Equivalence)"
	@echo "=========================================="
	./test/test_mul_product
	@echo ""
	@echo "=========================================="
	@echo "  Running Gate A (Commuting Diagram)"
	@echo "=========================================="
	./test/test_commute
	@echo ""
	@echo "=========================================="
	@echo "  Running Gate A (Edge Cases)"
	@echo "=========================================="
	./test/test_ghash_edges
	@echo ""
	@echo "=========================================="
	@echo "  Running Gate B (NIST Vectors)"
	@echo "=========================================="
	./test/test_gcm_nist
	@echo ""
	@echo "=========================================="
	@echo "  Gate Test Summary"
	@echo "=========================================="

# Benchmarking
bench: tools/benchmark
	./tools/benchmark
	@echo "Benchmark completed"

tools/benchmark: tools/benchmark.c libsoliton_core.a
	$(CC) $(HOSTED_FLAGS) -o $@ $< -L. -lsoliton_core

# Diagnostic build (with -DSOLITON_DIAGNOSTICS)
DIAG_FLAGS = -DSOLITON_DIAGNOSTICS
DIAG_OBJS = $(ALL_CORE_OBJS:.o=.diag.o)

diag: tools/bench_with_diagnostics
	@echo "Running diagnostics..."
	./tools/bench_with_diagnostics

# Diagnostic object files
%.diag.o: %.c
	$(CC) $(CORE_FLAGS) $(DIAG_FLAGS) -c -o $@ $<

core/dispatch.diag.o: core/dispatch.c
ifeq ($(ARCH),x86_64)
	$(CC) $(CORE_FLAGS) $(DIAG_FLAGS) -mavx2 -mvaes -mpclmul -c -o $@ $<
else ifeq ($(ARCH),aarch64)
	$(CC) $(CORE_FLAGS) $(DIAG_FLAGS) -march=armv8-a+crypto -c -o $@ $<
else
	$(CC) $(CORE_FLAGS) $(DIAG_FLAGS) -c -o $@ $<
endif

core/aes_vaes.diag.o: core/aes_vaes.c
	$(CC) $(CORE_FLAGS) $(DIAG_FLAGS) $(VAES_FLAGS) -c -o $@ $<

core/ghash_clmul.diag.o: core/ghash_clmul.c
	$(CC) $(CORE_FLAGS) $(DIAG_FLAGS) -mpclmul -mssse3 -c -o $@ $<

core/gcm_fused_vaes_clmul.diag.o: core/gcm_fused_vaes_clmul.c
	$(CC) $(CORE_FLAGS) $(DIAG_FLAGS) $(VAES_FLAGS) -c -o $@ $<

core/chacha_avx2.diag.o: core/chacha_avx2.c
	$(CC) $(CORE_FLAGS) $(DIAG_FLAGS) $(AVX2_FLAGS) -c -o $@ $<

libsoliton_diag.a: $(DIAG_OBJS)
	$(AR) rcs $@ $^
	@echo "Built diagnostic library: $@"

provider/soliton_provider.diag.o: provider/soliton_provider.c
	$(CC) $(HOSTED_FLAGS) $(DIAG_FLAGS) -fPIC -c -o $@ $<

solitonprov_diag.so: provider/soliton_provider.diag.o libsoliton_diag.a
	$(CC) -shared -fPIC -o $@ $< -L. -lsoliton_diag -lcrypto
	@echo "Built diagnostic provider: $@"

tools/bench_with_diagnostics: tools/bench_with_diagnostics.c libsoliton_diag.a
	$(CC) $(HOSTED_FLAGS) $(DIAG_FLAGS) -o $@ $< -L. -lsoliton_diag

# Reproducible benchmark harness with artifacts
.PHONY: bench-artifacts
bench-artifacts: tools/bench_depth16 tools/benchmark libsoliton_core.a
	@echo "=== Running Reproducible Benchmark Harness ==="
	@echo ""
	@echo "This will run benchmarks and capture full artifacts for reproducibility."
	@echo "Artifacts will be saved to artifacts/ directory."
	@echo ""
	@mkdir -p artifacts
	@echo "1. Running native depth-16 benchmark..."
	@./scripts/capture_artifacts.sh artifacts/native_depth16 ./tools/bench_depth16
	@echo ""
	@echo "2. Running native AES-GCM benchmark (various sizes)..."
	@./scripts/capture_artifacts.sh artifacts/native_aesgcm ./tools/benchmark
	@echo ""
	@echo "=== Benchmark Artifacts Complete ==="
	@echo "Results saved to artifacts/ directory"
	@echo ""
	@echo "Summary:"
	@grep -h "Throughput" artifacts/*/benchmark_output.txt || true

# Clean
clean:
	rm -f core/*.o core/*.diag.o sched/*.o sched/*.diag.o provider/*.o provider/*.diag.o cli/*.o test/*.o tools/*.o
	rm -f libsoliton_core.a libsoliton_diag.a solitonprov.so glidepathprov.so solitonprov_diag.so soliton
	rm -f test/test_aes_gcm test/test_chacha_poly test/test_ct test/test_suite
	rm -f tools/benchmark tools/bench_with_diagnostics tools/bench_gcm_native tools/bench_ghash8
	@echo "Cleaned build artifacts"

# Installation
PREFIX ?= /usr/local
install: libsoliton_core.a soliton
	install -D -m 644 libsoliton_core.a $(PREFIX)/lib/libsoliton_core.a
	install -D -m 644 include/soliton.h $(PREFIX)/include/soliton.h
	install -D -m 755 soliton $(PREFIX)/bin/soliton
	@echo "Installed to $(PREFIX)"

.PHONY: help
help:
	@echo "soliton.c build targets:"
	@echo "  all       - Build library, CLI, and provider (if OpenSSL available)"
	@echo "  clean     - Remove build artifacts"
	@echo "  test      - Run test suite"
	@echo "  bench     - Run benchmarks"
	@echo "  install   - Install library, headers, and tools"
	@echo ""
	@echo "Compiler: CC=$(CC)"
	@echo "Architecture: $(ARCH)"