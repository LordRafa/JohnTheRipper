/*-
 * Copyright 2009 Colin Percival
 * Copyright 2012,2013 Alexander Peslyak
 * Copyright 2013 Rafael Waldo Delgado Doblas
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system and modified by Alexander Peslyak for Jonh the Ripper.
 * 
 * Rafael Waldo Delgado Doblas modified this file to merge the sse and non-sse
 * versions of scrypt in the same source code.
 * 
 */
#include "scrypt_platform.h"

#include <sys/types.h>
#include <sys/mman.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../arch.h"
#include "sha256.h"
#include "sysendian.h"

#include "crypto_scrypt.h"


#if !(defined(MMX_COEF) && MMX_COEF == 4)
//--------Non-SSE CPUs Code--------

static void
blkcpy(void * dest, void * src, size_t len)
{
   size_t * D = dest;
   size_t * S = src;
   size_t L = len / sizeof(size_t);
   size_t i;

   for (i = 0; i < L; i++)
      D[i] = S[i];
}

static void
blkxor(void * dest, void * src, size_t len)
{
   size_t * D = dest;
   size_t * S = src;
   size_t L = len / sizeof(size_t);
   size_t i;

   for (i = 0; i < L; i++)
      D[i] ^= S[i];
}

/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
static void
salsa20_8(uint32_t B[16])
{
   uint32_t x[16];
   size_t i;

   blkcpy(x, B, 64);
   for (i = 0; i < 8; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
      /* Operate on columns. */
      x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
      x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);

      x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
      x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);

      x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
      x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);

      x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
      x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);

      /* Operate on rows. */
      x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
      x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);

      x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
      x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);

      x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
      x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);

      x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
      x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
#undef R
   }
   for (i = 0; i < 16; i++)
      B[i] += x[i];
}

/**
 * blockmix_salsa8(Bin, Bout, X, r):
 * Compute Bout = BlockMix_{salsa20/8, r}(Bin).  The input Bin must be 128r
 * bytes in length; the output Bout must also be the same size.  The
 * temporary space X must be 64 bytes.
 */
static void
blockmix_salsa8(uint32_t * Bin, uint32_t * Bout, uint32_t * X, size_t r)
{
   size_t i;

   /* 1: X <-- B_{2r - 1} */
   blkcpy(X, &Bin[(2 * r - 1) * 16], 64);

   /* 2: for i = 0 to 2r - 1 do */
   for (i = 0; i < 2 * r; i += 2) {
      /* 3: X <-- H(X \xor B_i) */
      blkxor(X, &Bin[i * 16], 64);
      salsa20_8(X);

      /* 4: Y_i <-- X */
      /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
      blkcpy(&Bout[i * 8], X, 64);

      /* 3: X <-- H(X \xor B_i) */
      blkxor(X, &Bin[i * 16 + 16], 64);
      salsa20_8(X);

      /* 4: Y_i <-- X */
      /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
      blkcpy(&Bout[i * 8 + r * 16], X, 64);
   }
}

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static uint64_t
integerify(void * B, size_t r)
{
   uint32_t * X = (void *)((uintptr_t)(B) + (2 * r - 1) * 64);

   return (((uint64_t)(X[1]) << 32) + X[0]);
}

/**
 * smix(B, r, N, defeat_tmto, V, XY):
 * Compute B = SMix_r(B, N).  The input B must be 128r bytes in length;
 * the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r + 64 bytes in length.  The value N must be a
 * power of 2 greater than 1.  The arrays B, V, and XY must be aligned to a
 * multiple of 64 bytes.
 */
static void
smix(uint8_t * B, size_t r, uint64_t N, int defeat_tmto,
    uint32_t * V, uint32_t * XY)
{
   uint32_t * X = XY;
   uint32_t * Y = &XY[32 * r];
   uint32_t * Z = &XY[64 * r];
   uint64_t i;
   uint64_t j;
   size_t k;

   /* 1: X <-- B */
   for (k = 0; k < 32 * r; k++)
      X[k] = le32dec(&B[4 * k]);

   /* 2: for i = 0 to N - 1 do */
   for (i = 0; i < N; i += 2) {
      /* 3: V_i <-- X */
      blkcpy(&V[i * (32 * r)], X, 128 * r);

      /* 4: X <-- H(X) */
      blockmix_salsa8(X, Y, Z, r);

      /* 3: V_i <-- X */
      blkcpy(&V[(i + 1) * (32 * r)], Y, 128 * r);

      /* 4: X <-- H(X) */
      blockmix_salsa8(Y, X, Z, r);
   }

   /* 6: for i = 0 to N - 1 do */
   for (i = 0; i < N; i += 2) {
      /* 7: j <-- Integerify(X) mod N */
      j = integerify(X, r) & (N - 1);

      /* 8: X <-- H(X \xor V_j) */
      blkxor(X, &V[j * (32 * r)], 128 * r);
      if (defeat_tmto)
         blkcpy(&V[j * (32 * r)], X, 128 * r);
      blockmix_salsa8(X, Y, Z, r);

      /* 7: j <-- Integerify(X) mod N */
      j = integerify(Y, r) & (N - 1);

      /* 8: X <-- H(X \xor V_j) */
      blkxor(Y, &V[j * (32 * r)], 128 * r);
      if (defeat_tmto)
         blkcpy(&V[j * (32 * r)], Y, 128 * r);
      blockmix_salsa8(Y, X, Z, r);
   }

   /* 10: B' <-- X */
   for (k = 0; k < 32 * r; k++)
      le32enc(&B[4 * k], X[k]);
}


#else
//----------SSE CPUs Code----------

#include <emmintrin.h>
#ifdef __XOP__
#include <x86intrin.h>
#endif

#ifdef __XOP__
#define ARX(out, in1, in2, s) \
	out = _mm_xor_si128(out, _mm_roti_epi32(_mm_add_epi32(in1, in2), s));
#else
#define ARX(out, in1, in2, s) \
	{ \
		__m128i T = _mm_add_epi32(in1, in2); \
		out = _mm_xor_si128(out, _mm_slli_epi32(T, s)); \
		out = _mm_xor_si128(out, _mm_srli_epi32(T, 32-s)); \
	}
#endif

#define SALSA20_2ROUNDS \
	/* Operate on "columns". */ \
	ARX(X1, X0, X3, 7) \
	ARX(X2, X1, X0, 9) \
	ARX(X3, X2, X1, 13) \
	ARX(X0, X3, X2, 18) \
\
	/* Rearrange data. */ \
	X1 = _mm_shuffle_epi32(X1, 0x93); \
	X2 = _mm_shuffle_epi32(X2, 0x4E); \
	X3 = _mm_shuffle_epi32(X3, 0x39); \
\
	/* Operate on "rows". */ \
	ARX(X3, X0, X1, 7) \
	ARX(X2, X3, X0, 9) \
	ARX(X1, X2, X3, 13) \
	ARX(X0, X1, X2, 18) \
\
	/* Rearrange data. */ \
	X1 = _mm_shuffle_epi32(X1, 0x39); \
	X2 = _mm_shuffle_epi32(X2, 0x4E); \
	X3 = _mm_shuffle_epi32(X3, 0x93);

/**
 * Apply the salsa20/8 core to the block provided in (X0 ... X3) ^ (Z0 ... Z3).
 */
#define SALSA20_8_XOR_ANY(maybe_decl, Z0, Z1, Z2, Z3, out) \
	{ \
		maybe_decl Y0 = X0 = _mm_xor_si128(X0, Z0); \
		maybe_decl Y1 = X1 = _mm_xor_si128(X1, Z1); \
		maybe_decl Y2 = X2 = _mm_xor_si128(X2, Z2); \
		maybe_decl Y3 = X3 = _mm_xor_si128(X3, Z3); \
		SALSA20_2ROUNDS \
		SALSA20_2ROUNDS \
		SALSA20_2ROUNDS \
		SALSA20_2ROUNDS \
		(out)[0] = X0 = _mm_add_epi32(X0, Y0); \
		(out)[1] = X1 = _mm_add_epi32(X1, Y1); \
		(out)[2] = X2 = _mm_add_epi32(X2, Y2); \
		(out)[3] = X3 = _mm_add_epi32(X3, Y3); \
	}

#define SALSA20_8_XOR_MEM(in, out) \
	SALSA20_8_XOR_ANY(__m128i, (in)[0], (in)[1], (in)[2], (in)[3], out)

#define SALSA20_8_XOR_REG(out) \
	SALSA20_8_XOR_ANY(/* empty */, Y0, Y1, Y2, Y3, out)

/**
 * blockmix_salsa8(Bin, Bout, r):
 * Compute Bout = BlockMix_{salsa20/8, r}(Bin).  The input Bin must be 128r
 * bytes in length; the output Bout must also be the same size.
 */
static inline void
blockmix_salsa8(__m128i * Bin, __m128i * Bout, size_t r)
{
	__m128i X0, X1, X2, X3;
	size_t i;

	/* 1: X <-- B_{2r - 1} */
	X0 = Bin[8 * r - 4];
	X1 = Bin[8 * r - 3];
	X2 = Bin[8 * r - 2];
	X3 = Bin[8 * r - 1];

	/* 3: X <-- H(X \xor B_i) */
	/* 4: Y_i <-- X */
	/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
	SALSA20_8_XOR_MEM(Bin, Bout)

	/* 2: for i = 0 to 2r - 1 do */
	r--;
	for (i = 0; i < r;) {
		/* 3: X <-- H(X \xor B_i) */
		/* 4: Y_i <-- X */
		/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
		SALSA20_8_XOR_MEM(&Bin[i * 8 + 4], &Bout[(r + i) * 4 + 4])

		i++;

		/* 3: X <-- H(X \xor B_i) */
		/* 4: Y_i <-- X */
		/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
		SALSA20_8_XOR_MEM(&Bin[i * 8], &Bout[i * 4])
	}

	/* 3: X <-- H(X \xor B_i) */
	/* 4: Y_i <-- X */
	/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
	SALSA20_8_XOR_MEM(&Bin[i * 8 + 4], &Bout[(r + i) * 4 + 4])
}

#define XOR4(in) \
	X0 = _mm_xor_si128(X0, (in)[0]); \
	X1 = _mm_xor_si128(X1, (in)[1]); \
	X2 = _mm_xor_si128(X2, (in)[2]); \
	X3 = _mm_xor_si128(X3, (in)[3]);

#define XOR4_2(in1, in2) \
	X0 = _mm_xor_si128((in1)[0], (in2)[0]); \
	X1 = _mm_xor_si128((in1)[1], (in2)[1]); \
	X2 = _mm_xor_si128((in1)[2], (in2)[2]); \
	X3 = _mm_xor_si128((in1)[3], (in2)[3]);

static inline uint32_t
blockmix_salsa8_xor(__m128i * Bin1, __m128i * Bin2, __m128i * Bout, size_t r)
{
	__m128i X0, X1, X2, X3;
	size_t i;

	/* 1: X <-- B_{2r - 1} */
	XOR4_2(&Bin1[8 * r - 4], &Bin2[8 * r - 4])

	/* 3: X <-- H(X \xor B_i) */
	/* 4: Y_i <-- X */
	/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
	XOR4(Bin1)
	SALSA20_8_XOR_MEM(Bin2, Bout)

	/* 2: for i = 0 to 2r - 1 do */
	r--;
	for (i = 0; i < r;) {
		/* 3: X <-- H(X \xor B_i) */
		/* 4: Y_i <-- X */
		/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
		XOR4(&Bin1[i * 8 + 4])
		SALSA20_8_XOR_MEM(&Bin2[i * 8 + 4], &Bout[(r + i) * 4 + 4])

		i++;

		/* 3: X <-- H(X \xor B_i) */
		/* 4: Y_i <-- X */
		/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
		XOR4(&Bin1[i * 8])
		SALSA20_8_XOR_MEM(&Bin2[i * 8], &Bout[i * 4])
	}

	/* 3: X <-- H(X \xor B_i) */
	/* 4: Y_i <-- X */
	/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
	XOR4(&Bin1[i * 8 + 4])
	SALSA20_8_XOR_MEM(&Bin2[i * 8 + 4], &Bout[(r + i) * 4 + 4])

	return _mm_cvtsi128_si32(X0);
}

#undef XOR4
#define XOR4(in, out) \
	(out)[0] = Y0 = _mm_xor_si128((in)[0], (out)[0]); \
	(out)[1] = Y1 = _mm_xor_si128((in)[1], (out)[1]); \
	(out)[2] = Y2 = _mm_xor_si128((in)[2], (out)[2]); \
	(out)[3] = Y3 = _mm_xor_si128((in)[3], (out)[3]);

static inline uint32_t
blockmix_salsa8_xor_save(__m128i * Bin1, __m128i * Bin2, __m128i * Bout,
    size_t r)
{
	__m128i X0, X1, X2, X3, Y0, Y1, Y2, Y3;
	size_t i;

	/* 1: X <-- B_{2r - 1} */
	XOR4_2(&Bin1[8 * r - 4], &Bin2[8 * r - 4])

	/* 3: X <-- H(X \xor B_i) */
	/* 4: Y_i <-- X */
	/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
	XOR4(Bin1, Bin2)
	SALSA20_8_XOR_REG(Bout)

	/* 2: for i = 0 to 2r - 1 do */
	r--;
	for (i = 0; i < r;) {
		/* 3: X <-- H(X \xor B_i) */
		/* 4: Y_i <-- X */
		/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
		XOR4(&Bin1[i * 8 + 4], &Bin2[i * 8 + 4])
		SALSA20_8_XOR_REG(&Bout[(r + i) * 4 + 4])

		i++;

		/* 3: X <-- H(X \xor B_i) */
		/* 4: Y_i <-- X */
		/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
		XOR4(&Bin1[i * 8], &Bin2[i * 8])
		SALSA20_8_XOR_REG(&Bout[i * 4])
	}

	/* 3: X <-- H(X \xor B_i) */
	/* 4: Y_i <-- X */
	/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
	XOR4(&Bin1[i * 8 + 4], &Bin2[i * 8 + 4])
	SALSA20_8_XOR_REG(&Bout[(r + i) * 4 + 4])

	return _mm_cvtsi128_si32(X0);
}

#undef ARX
#undef SALSA20_2ROUNDS
#undef SALSA20_8_XOR_ANY
#undef SALSA20_8_XOR_MEM
#undef SALSA20_8_XOR_REG
#undef XOR4
#undef XOR4_2

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static inline uint32_t
integerify(void * B, size_t r)
{
	return *(uint32_t *)((uintptr_t)(B) + (2 * r - 1) * 64);
}

/**
 * smix(B, r, N, defeat_tmto, V, XY):
 * Compute B = SMix_r(B, N).  The input B must be 128r bytes in length;
 * the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r + 64 bytes in length.  The value N must be a
 * power of 2 greater than 1.  The arrays B, V, and XY must be aligned to a
 * multiple of 64 bytes.
 */
static void
smix(uint8_t * B, size_t r, uint32_t N, int defeat_tmto, void * V, void * XY)
{
	size_t s = 128 * r;
	__m128i * X = V, * Y;
	uint32_t * X32 = V;
	uint32_t i, j;
	size_t k;

	/* 1: X <-- B */
	/* 3: V_i <-- X */
	for (k = 0; k < 2 * r; k++) {
		for (i = 0; i < 16; i++) {
			X32[k * 16 + i] =
			    le32dec(&B[(k * 16 + (i * 5 % 16)) * 4]);
		}
	}

	/* 2: for i = 0 to N - 1 do */
	for (i = 1; i < N - 1; i += 2) {
		/* 4: X <-- H(X) */
		/* 3: V_i <-- X */
		Y = (void *)((uintptr_t)(V) + i * s);
		blockmix_salsa8(X, Y, r);

		/* 4: X <-- H(X) */
		/* 3: V_i <-- X */
		X = (void *)((uintptr_t)(V) + (i + 1) * s);
		blockmix_salsa8(Y, X, r);
	}

	/* 4: X <-- H(X) */
	/* 3: V_i <-- X */
	Y = (void *)((uintptr_t)(V) + i * s);
	blockmix_salsa8(X, Y, r);

	/* 4: X <-- H(X) */
	/* 3: V_i <-- X */
	X = XY;
	blockmix_salsa8(Y, X, r);

	X32 = XY;
	Y = (void *)((uintptr_t)(XY) + s);

	/* 7: j <-- Integerify(X) mod N */
	j = integerify(X, r) & (N - 1);

	if (defeat_tmto) {
		/* 6: for i = 0 to N - 1 do */
		for (i = 0; i < N; i += 2) {
			__m128i * V_j = (void *)((uintptr_t)(V) + j * s);

			/* 8: X <-- H(X \xor V_j) */
			/* 7: j <-- Integerify(X) mod N */
			j = blockmix_salsa8_xor_save(X, V_j, Y, r) & (N - 1);
			V_j = (void *)((uintptr_t)(V) + j * s);

			/* 8: X <-- H(X \xor V_j) */
			/* 7: j <-- Integerify(X) mod N */
			j = blockmix_salsa8_xor_save(Y, V_j, X, r) & (N - 1);
		}
	} else {
		/* 6: for i = 0 to N - 1 do */
		for (i = 0; i < N; i += 2) {
			__m128i * V_j = (void *)((uintptr_t)(V) + j * s);

			/* 8: X <-- H(X \xor V_j) */
			/* 7: j <-- Integerify(X) mod N */
			j = blockmix_salsa8_xor(X, V_j, Y, r) & (N - 1);
			V_j = (void *)((uintptr_t)(V) + j * s);

			/* 8: X <-- H(X \xor V_j) */
			/* 7: j <-- Integerify(X) mod N */
			j = blockmix_salsa8_xor(Y, V_j, X, r) & (N - 1);
		}
	}

	/* 10: B' <-- X */
	for (k = 0; k < 2 * r; k++) {
		for (i = 0; i < 16; i++) {
			le32enc(&B[(k * 16 + (i * 5 % 16)) * 4],
			    X32[k * 16 + i]);
		}
	}
}


#endif
//----------Common Code-----------

static void * alloc_aligned(void ** base, size_t size)
{
	void * ptr;
#ifdef MAP_ANON
	if ((ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
#ifdef MAP_NOCORE
	    MAP_ANON | MAP_PRIVATE | MAP_NOCORE,
#else
	    MAP_ANON | MAP_PRIVATE,
#endif
	    -1, 0)) == MAP_FAILED)
		ptr = NULL;
	*base = ptr;
#elif defined(HAVE_POSIX_MEMALIGN)
	if ((errno = posix_memalign(&ptr, 64, size)) != 0)
		ptr = NULL;
	*base = ptr;
#else
	if (size + 63 < size) {
		errno = ENOMEM;
		return NULL;
	}
	if ((*base = malloc(size + 63)) == NULL)
		return NULL;
	ptr = (uint32_t *)(((uintptr_t)(*base) + 63) & ~ (uintptr_t)(63));
#endif
	return ptr;
}

static int free_aligned(void * base, size_t size)
{
#ifdef MAP_ANON
	if (base)
		return munmap(base, size);
#else
	free(base);
#endif
	return 0;
}

int escrypt_init(escrypt_ctx_t * ctx,
    uint64_t rom_N, uint32_t rom_r,
    const uint8_t * param, size_t paramlen)
{
/* The ROM stuff is not implemented yet */
	ctx->ram_base = ctx->ram_aligned = NULL;
	ctx->ram_size = 0;
	return 0;
}

int escrypt_free(escrypt_ctx_t * ctx)
{
	if (free_aligned(ctx->ram_base, ctx->ram_size))
		return -1;
	ctx->ram_base = ctx->ram_aligned = NULL;
	ctx->ram_size = 0;
	return 0;
}

/**
 * escrypt_kdf(ctx, passwd, passwdlen, salt, saltlen, N, r, p, defeat_tmto,
 *     buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2 greater than 1.
 *
 * Return 0 on success; or -1 on error.
 */
int
escrypt_kdf(escrypt_ctx_t * ctx,
    const uint8_t * passwd, size_t passwdlen,
    const uint8_t * salt, size_t saltlen, uint64_t N, uint32_t r, uint32_t p,
    int defeat_tmto, uint8_t * buf, size_t buflen)
{
	size_t B_size, V_size, XY_size, need;
	uint8_t * B;
	uint32_t * V, * XY;
	uint32_t i;

	/* Sanity-check parameters. */
#if SIZE_MAX > UINT32_MAX
	if (buflen > (((uint64_t)(1) << 32) - 1) * 32) {
		errno = EFBIG;
		goto err0;
	}
#endif
	if ((uint64_t)(r) * (uint64_t)(p) >= (1 << 30)) {
		errno = EFBIG;
		goto err0;
	}
	if (N > UINT32_MAX) {
		errno = EFBIG;
		goto err0;
	}
	if (((N & (N - 1)) != 0) || (N == 0)) {
		errno = EINVAL;
		goto err0;
	}
	if ((r > SIZE_MAX / 128 / p) ||
#if SIZE_MAX / 256 <= UINT32_MAX
	    (r > SIZE_MAX / 256) ||
#endif
	    (N > SIZE_MAX / 128 / r)) {
		errno = ENOMEM;
		goto err0;
	}

	/* Allocate memory. */
	B_size = (size_t)128 * r * p;
	V_size = (size_t)128 * r * N;
	need = B_size + V_size;
	if (need < V_size) {
		errno = ENOMEM;
		goto err0;
	}
	XY_size = (size_t)256 * r;
	need += XY_size;
	if (need < XY_size) {
		errno = ENOMEM;
		goto err0;
	}
	if (ctx->ram_size < need) {
		if (free_aligned(ctx->ram_base, ctx->ram_size))
			goto err0;
		ctx->ram_size = 0;
		ctx->ram_aligned = alloc_aligned(&ctx->ram_base, need);
		if (!ctx->ram_aligned)
			goto err0;
		ctx->ram_size = need;
	}
	B = (uint8_t *)ctx->ram_aligned;
	V = (uint32_t *)((uint8_t *)B + B_size);
	XY = (uint32_t *)((uint8_t *)V + V_size);

	/* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
	PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, 1, B, B_size);

	/* 2: for i = 0 to p - 1 do */
	for (i = 0; i < p; i++) {
		/* 3: B_i <-- MF(B_i, N) */
		smix(&B[(size_t)128 * i * r], r, N, defeat_tmto, V, XY);
	}

	/* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
	PBKDF2_SHA256(passwd, passwdlen, B, B_size, 1, buf, buflen);

	/* Success! */
	return (0);

err0:
	/* Failure! */
	return (-1);
}
