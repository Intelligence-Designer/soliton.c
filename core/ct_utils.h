/*
 * ct_utils.h - Constant-time utilities for soliton.c
 * All operations here must be constant-time with respect to secret data
 */

#ifndef SOLITON_CT_UTILS_H
#define SOLITON_CT_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"

/* Constant-time byte selection: return a if c=1, b if c=0 */
static SOLITON_INLINE uint8_t ct_select_u8(uint8_t a, uint8_t b, int c) {
    uint8_t mask = (uint8_t)(-c);
    return (a & mask) | (b & ~mask);
}

/* Constant-time word selection */
static SOLITON_INLINE uint32_t ct_select_u32(uint32_t a, uint32_t b, int c) {
    uint32_t mask = (uint32_t)(-c);
    return (a & mask) | (b & ~mask);
}

static SOLITON_INLINE uint64_t ct_select_u64(uint64_t a, uint64_t b, int c) {
    uint64_t mask = (uint64_t)(-c);
    return (a & mask) | (b & ~mask);
}

/* Constant-time equality check: return 1 if equal, 0 otherwise */
static SOLITON_INLINE int ct_eq_u8(uint8_t a, uint8_t b) {
    uint32_t x = a ^ b;
    x = (uint32_t)(-x) | x;
    return 1 & ((x - 1) >> 31);
}

static SOLITON_INLINE int ct_eq_u32(uint32_t a, uint32_t b) {
    uint32_t x = a ^ b;
    x = (uint32_t)(-x) | x;
    return 1 & ((x - 1) >> 31);
}

/* Constant-time less-than: return 1 if a < b, 0 otherwise */
static SOLITON_INLINE int ct_lt_u32(uint32_t a, uint32_t b) {
    uint32_t x = a ^ ((a ^ b) | ((a - b) ^ b));
    return (x >> 31) & 1;
}

/* Constant-time greater-or-equal: return 1 if a >= b, 0 otherwise */
static SOLITON_INLINE int ct_ge_u32(uint32_t a, uint32_t b) {
    return 1 ^ ct_lt_u32(a, b);
}

/* Constant-time is-zero check */
static SOLITON_INLINE int ct_is_zero_u8(uint8_t x) {
    return ct_eq_u8(x, 0);
}

static SOLITON_INLINE int ct_is_zero_u32(uint32_t x) {
    return ct_eq_u32(x, 0);
}

/* Constant-time mask generation: return all 1s if c=1, all 0s if c=0 */
static SOLITON_INLINE uint32_t ct_mask_u32(int c) {
    return (uint32_t)(-c);
}

static SOLITON_INLINE uint64_t ct_mask_u64(int c) {
    return (uint64_t)(-c);
}

/* Constant-time memory operations */

/* Copy n bytes from src to dst if condition is true */
static SOLITON_INLINE void ct_cmov(void* dst, const void* src, size_t n, int condition) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;

    for (size_t i = 0; i < n; i++) {
        d[i] = ct_select_u8(s[i], d[i], condition);
    }
    SOLITON_BARRIER();
}

/* XOR n bytes from src into dst if condition is true */
static SOLITON_INLINE void ct_cond_xor(void* dst, const void* src, size_t n, int condition) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    uint8_t mask = (uint8_t)(-condition);

    for (size_t i = 0; i < n; i++) {
        d[i] ^= s[i] & mask;
    }
    SOLITON_BARRIER();
}

/* Swap two memory regions if condition is true */
static SOLITON_INLINE void ct_cswap(void* a, void* b, size_t n, int condition) {
    uint8_t* pa = (uint8_t*)a;
    uint8_t* pb = (uint8_t*)b;
    uint8_t mask = (uint8_t)(-condition);

    for (size_t i = 0; i < n; i++) {
        uint8_t tmp = mask & (pa[i] ^ pb[i]);
        pa[i] ^= tmp;
        pb[i] ^= tmp;
    }
    SOLITON_BARRIER();
}

/* Constant-time memory comparison: return 0 if equal, non-zero otherwise */
static SOLITON_INLINE int ct_memcmp(const void* a, const void* b, size_t n) {
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    uint8_t diff = 0;

    for (size_t i = 0; i < n; i++) {
        diff |= pa[i] ^ pb[i];
    }
    SOLITON_BARRIER();

    return diff;
}

/* Check if all bytes are zero */
static SOLITON_INLINE int ct_is_zero_mem(const void* p, size_t n) {
    const uint8_t* pp = (const uint8_t*)p;
    uint8_t acc = 0;

    for (size_t i = 0; i < n; i++) {
        acc |= pp[i];
    }
    SOLITON_BARRIER();

    return ct_is_zero_u8(acc);
}

/* Masked operations for tail handling */

/* Create a byte mask: 0xFF if index < len, 0x00 otherwise */
static SOLITON_INLINE uint8_t ct_index_mask(size_t index, size_t len) {
    return (uint8_t)(-(index < len));
}

/* Masked byte load: return data[index] if index < len, else 0 */
static SOLITON_INLINE uint8_t ct_masked_load(const uint8_t* data, size_t index, size_t len) {
    uint8_t mask = ct_index_mask(index, len);
    uint8_t value = (index < len) ? data[index] : 0;
    return value & mask;
}

/* Masked byte store: store value to data[index] if index < len */
static SOLITON_INLINE void ct_masked_store(uint8_t* data, size_t index, uint8_t value, size_t len) {
    uint8_t mask = ct_index_mask(index, len);
    if (index < len) {
        data[index] = (data[index] & ~mask) | (value & mask);
    }
}

/* GF(2^128) operations for GHASH */

/* Reverse bits in a byte */
static SOLITON_INLINE uint8_t ct_reverse_bits(uint8_t b) {
    b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4);
    b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2);
    b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1);
    return b;
}

/* Reverse byte order and bits for GHASH */
static SOLITON_INLINE void ct_reverse_bytes_bits(uint8_t* dst, const uint8_t* src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = ct_reverse_bits(src[n - 1 - i]);
    }
}

/* Increment counter in big-endian format */
static SOLITON_INLINE void ct_inc_be32(uint8_t ctr[4]) {
    uint32_t val = soliton_be32(ctr);
    val++;
    soliton_put_be32(ctr, val);
}

/* Add to counter with wrap-around */
static SOLITON_INLINE uint32_t ct_add_ctr(uint32_t ctr, uint32_t inc) {
    return ctr + inc;
}

/* Timing measurement helpers (for CT verification only) */
#ifdef SOLITON_CT_VERIFY

/* Get CPU timestamp counter */
static SOLITON_INLINE uint64_t ct_rdtsc(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t val;
    __asm__ volatile ("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#else
    return 0;
#endif
}

/* Memory and instruction fence */
static SOLITON_INLINE void ct_fence(void) {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile ("mfence; lfence" ::: "memory");
#elif defined(__aarch64__)
    __asm__ volatile ("dsb sy; isb" ::: "memory");
#else
    SOLITON_BARRIER();
#endif
}

#endif /* SOLITON_CT_VERIFY */

#endif /* SOLITON_CT_UTILS_H */