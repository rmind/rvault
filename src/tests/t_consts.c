/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include "rvault.h"
#include "storage.h"
#include "crypto.h"
#include "sys.h"
#include "mock.h"
#include "utils.h"

#define	TEST_KEY \
    "0705b45c2be368b6aadf21656a89dad8fed6172170b7e78f638a650dab05d7ea"

#define	TEST_AKEY \
    "9e31efad8c27303105669c4c21351558742c564c07d23702c45ca68bfc3ac43b"

#define	TEST_IV_96	"508c39cf1b4a706a219ab837"
#define	TEST_IV_128	"508c39cf1b4a706a219ab837981ba4b0"

static const struct test_case {
	crypto_cipher_t	cipher;
	const char *	iv;
	const char *	exp_hmac;
	const char *	exp_aetag;
	const char *	expecting;
} test_cases[] = {
#if !defined(USE_AE_CIPHERS_ONLY)
	{
		.cipher = AES_256_CBC,
		.iv = TEST_IV_128,
		.exp_aetag =
		    "f4 42 5c c9 fb 5e 35 27 30 ba 26 2e 9f 8b a8 29"
		    "70 09 99 9c 56 17 93 67 e0 0c f1 8a bf 14 0b 15",
		.expecting =
		    "ee c1 39 07 55 68 49 1e e8 ef 71 d4 ac bd bf 43"
		    "63 b1 16 66 a8 c6 6e c8 a1 50 18 66 ff e8 87 e5"
		    "10 f5 4b 3c 6e c2 3e 1a 09 e3 d7 e7 53 f9 b1 61",
	},
#endif
	{
		.cipher = AES_256_GCM,
		.iv = TEST_IV_96,
		.exp_aetag =
		    "a2 e5 6b 59 17 51 38 a3 b3 70 49 d7 b3 62 a1 3e",
		.expecting =
		    "3e 79 81 60 b5 33 23 fc 0b 10 cd fc 0c c8 41 cb"
		    "67 fd d7 35 a6 e8 5b 56 c4 53 ca 35 54 92 43 2a"
		    "d0 b3 95 56 54 c2 97 ba 51 80 fc e7",
	},
	{
		.cipher = CHACHA20_POLY1305,
		.iv = TEST_IV_96,
		.exp_aetag =
		    "3d 9f a9 a9 76 86 01 25 8d 00 c8 b7 a3 02 74 59",
		.expecting =
		    "cc e3 8e bf 97 6e c2 c0 69 33 db 5c f3 b2 2b 23"
		    "e8 9d 25 5c 8f b5 24 00 45 98 6c de d0 6d 3a c5"
		    "6c e0 94 33 40 74 b7 72 cf 0c 71 f3",
	}
};

static const uint8_t kdf_expected_val[] = {
	0x3c, 0xde, 0x91, 0x65, 0xb0, 0x5b, 0x53, 0xbe,
	0x45, 0x9d, 0x55, 0xcf, 0x5e, 0x69, 0x61, 0xed
};

static const uint8_t hmac_expected_val[] = {
	0x4d, 0x03, 0xf0, 0x02, 0x3f, 0xfb, 0x43, 0x0e,
	0xb8, 0x2f, 0xe6, 0x4a, 0x60, 0x0b, 0x36, 0x0c,
	0xc8, 0xbd, 0xeb, 0xf6, 0x0e, 0x71, 0x1f, 0x11,
	0x8b, 0xd2, 0xfa, 0x9f, 0x4f, 0xb7, 0xe4, 0x6d
};

///////////////////////////////////////////////////////////////////////////////

static void
test_kdf(void)
{
	uint8_t buf[sizeof(kdf_expected_val)];
	int ret;

	ret = kdf_passphrase_genkey(TEST_TEXT, NULL, 0, buf, sizeof(buf));
	assert(ret == 0);
	assert(memcmp(buf, kdf_expected_val, sizeof(buf)) == 0);
}

static crypto_t *
test_get_crypto(crypto_cipher_t c, crypto_hmac_t hmac_id)
{
	crypto_t *crypto;
	size_t keylen, akeylen;
	void *key, *akey;
	int ret;

	crypto = crypto_create(c, hmac_id);
	assert(crypto != NULL);

	key = hex_readmem_arbitrary(TEST_KEY, strlen(TEST_KEY), &keylen);
	ret = crypto_set_key(crypto, key, keylen);
	assert(ret == 0);
	free(key);

	akey = hex_readmem_arbitrary(TEST_AKEY, strlen(TEST_AKEY), &akeylen);
	ret = crypto_set_authkey(crypto, akey, akeylen);
	assert(ret == 0);
	free(akey);

	return crypto;
}

static void
test_hmac(void)
{
	uint8_t hmac[HMAC_MAX_BUFLEN];
	crypto_t *crypto;
	ssize_t nbytes;

	crypto = test_get_crypto(CRYPTO_CIPHER_PRIMARY, CRYPTO_HMAC_PRIMARY);
	assert(crypto != NULL);

	nbytes = crypto_hmac(crypto, TEST_TEXT, TEST_TEXT_LEN, hmac);
	assert(crypto_hmac_len(CRYPTO_HMAC_PRIMARY) == nbytes);
	assert((ssize_t)sizeof(hmac_expected_val) == nbytes);
	assert(memcmp(hmac, hmac_expected_val, nbytes) == 0);

	crypto_destroy(crypto);
}

static void
test_crypto(const struct test_case *t)
{
	uint8_t buf[TEST_TEXT_LEN * 2];
	size_t ivlen, taglen, explen;
	void *iv, *exp_aetag, *exp_data;
	ssize_t nbytes, ret;
	const void *aetag;
	crypto_t *crypto;

	crypto = test_get_crypto(t->cipher, CRYPTO_HMAC_PRIMARY);
	assert(crypto != NULL);

	iv = hex_readmem_arbitrary(t->iv, strlen(t->iv), &ivlen);
	ret = crypto_set_iv(crypto, iv, ivlen);
	assert(ret == 0);
	free(iv);

	ret = crypto_set_aad(crypto, TEST_AAD, strlen(TEST_AAD));
	assert(ret == 0);

	nbytes = crypto_encrypt(crypto, TEST_TEXT, TEST_TEXT_LEN,
	    buf, crypto_get_buflen(crypto, TEST_TEXT_LEN));
	assert(nbytes > 0);

	exp_data = hex_readmem_arbitrary(t->expecting,
	    strlen(t->expecting), &explen);
	assert(exp_data && (size_t)nbytes == explen);
	assert(memcmp(exp_data, buf, explen) == 0);
	free(exp_data);

	exp_aetag = hex_readmem_arbitrary(t->exp_aetag,
	    strlen(t->exp_aetag), &taglen);
	aetag = crypto_get_aetag(crypto, &taglen);
	assert(memcmp(exp_aetag, aetag, taglen) == 0);
	free(exp_aetag);

	crypto_destroy(crypto);
}

int
main(void)
{
	test_kdf();
	test_hmac();

	for (unsigned i = 0; i < __arraycount(test_cases); i++) {
		const struct test_case *t = &test_cases[i];
		test_crypto(t);
	}

	puts("ok");
	return 0;
}
