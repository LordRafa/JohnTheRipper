/*
 * Generic scrypt support, based on Alexander Peslyak escrypt library.
 *
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Lord Rafa.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>
#include <string.h>
#include "escrypt/crypto_scrypt.h"

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "loader.h"

#define FORMAT_LABEL			"lordrafa-scrypt"
#define FORMAT_NAME			"generic scrypt"
#define ALGORITHM_NAME			"scrypt/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		72

#define BINARY_SIZE			128
#define BINARY_ALIGN			1
#define SALT_SIZE			BINARY_SIZE
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		96
#define MAX_KEYS_PER_CRYPT		96

static struct fmt_tests tests[] = {
	{"$7$C6..../....WZaPV7LSUEKMo34.$e/BXPpxvzq.sRDab3rZ4QTPa2b.RtAJpcg.wJsRPgm0", "Hello"},
   {"$7$C6..../....WZaPV7LSUEKMo34.$NxdWOR.uGgR63TiwfW9kIXS7sAUYADXNR5Ke5QN3Fv7", "World"},
	{NULL}
};

static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1];
static char saved_salt[SALT_SIZE];
static char crypt_out[MAX_KEYS_PER_CRYPT][BINARY_SIZE];

static int valid(char *ciphertext, struct fmt_main *self)
{
	int length, count_base64, id, pw_length;
	char pw[PLAINTEXT_LENGTH + 1], *new_ciphertext;
/* We assume that these are zero-initialized */
	static char sup_length[BINARY_SIZE], sup_id[0x80];

	length = count_base64 = 0;
	while (ciphertext[length]) {
		if (atoi64[ARCH_INDEX(ciphertext[length])] != 0x7F &&
		    (ciphertext[0] == '_' || length >= 2))
			count_base64++;
		length++;
	}

	if (length != 74)
		return 0;

	id = 0;
   if (ciphertext[0] == '$' || ciphertext[1] == '7')
      id = 7;

/* Previously detected as supported */
	if (sup_length[length] > 0 && sup_id[id] > 0)
		return 1;

/* Previously detected as unsupported */
	if (sup_length[length] < 0 && sup_id[id] < 0)
		return 0;

	pw_length = ((length - 2) / 11) << 3;
	if (pw_length >= sizeof(pw))
		pw_length = sizeof(pw) - 1;
	memcpy(pw, ciphertext, pw_length); /* reuse the string, why not? */
	pw[pw_length] = 0;
   
   new_ciphertext = escrypt(pw, ciphertext);
   
	if (new_ciphertext && strlen(new_ciphertext) == length &&
	    !strncmp(new_ciphertext, ciphertext, 31)) {
		sup_length[length] = 1;
		sup_id[id] = 1;
		return 1;
	}

	if (!sup_length[length])
		sup_length[length] = -1;
	if (!sup_id[id])
		sup_id[id] = -1;
	return 0;
}

static void *binary(char *ciphertext)
{
	static char out[BINARY_SIZE];
	strncpy(out, ciphertext, sizeof(out)); /* NUL padding is required */
	return out;
}

static void *salt(char *ciphertext)
{
	static char out[SALT_SIZE];

	/* NUL padding is required */
	memset(out, 0, sizeof(out));
	memcpy(out, ciphertext, 30);

	return out;
}

#define H(s, i) \
	((int)(unsigned char)(atoi64[ARCH_INDEX((s)[(i)])] ^ (s)[(i) - 1]))

#define H0(s) \
	int i = strlen(s) - 2; \
	return i > 0 ? H((s), i) & 0xF : 0
#define H1(s) \
	int i = strlen(s) - 2; \
	return i > 2 ? (H((s), i) ^ (H((s), i - 2) << 4)) & 0xFF : 0
#define H2(s) \
	int i = strlen(s) - 2; \
	return i > 2 ? (H((s), i) ^ (H((s), i - 2) << 6)) & 0xFFF : 0
#define H3(s) \
	int i = strlen(s) - 2; \
	return i > 4 ? (H((s), i) ^ (H((s), i - 2) << 5) ^ \
	    (H((s), i - 4) << 10)) & 0xFFFF : 0
#define H4(s) \
	int i = strlen(s) - 2; \
	return i > 6 ? (H((s), i) ^ (H((s), i - 2) << 5) ^ \
	    (H((s), i - 4) << 10) ^ (H((s), i - 6) << 15)) & 0xFFFFF : 0

static int binary_hash_0(void *binary)
{
	H0((char *)binary);
}

static int binary_hash_1(void *binary)
{
	H1((char *)binary);
}

static int binary_hash_2(void *binary)
{
	H2((char *)binary);
}

static int binary_hash_3(void *binary)
{
	H3((char *)binary);
}

static int binary_hash_4(void *binary)
{
	H4((char *)binary);
}

static int get_hash_0(int index)
{
	H0(crypt_out[index]);
}

static int get_hash_1(int index)
{
	H1(crypt_out[index]);
}

static int get_hash_2(int index)
{
	H2(crypt_out[index]);
}

static int get_hash_3(int index)
{
	H3(crypt_out[index]);
}

static int get_hash_4(int index)
{
	H4(crypt_out[index]);
}

static int salt_hash(void *salt)
{
	int i, h;

	i = strlen((char *)salt) - 1;
	if (i > 1) i--;

	h = (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i])];
	h ^= ((unsigned char *)salt)[i - 1];
	h <<= 6;
	h ^= (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i - 1])];
	h ^= ((unsigned char *)salt)[i];

	return h & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
	strcpy(saved_salt, salt);
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
   static int warned = 0;
   int count = *pcount;
   int index;

   for (index = 0; index < count; index++) {
      char *hash = escrypt(saved_key[index], saved_salt);
      if (!hash) {
         if (!warned) {
            fprintf(stderr,                    
                    "Warning: crypt() returned NULL\n");
            warned = 1;
         }
         hash = "";
      }
      strnzcpy(crypt_out[index], hash, BINARY_SIZE);
   }

   return count;
}


static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!strcmp((char *)binary, crypt_out[index]))
			return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !strcmp((char *)binary, crypt_out[index]);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_scrypt_lordrafa = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		fmt_default_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			NULL,
			NULL
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			NULL,
			NULL
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
