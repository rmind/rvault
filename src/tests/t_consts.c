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

/*
 * AES 256 + CBC mode: IV is 16 bytes; key is 32 bytes.
 * Chacha20: IV is 16 bytes (96 bit nonce + 32 bit counter); key is 32 bytes.
 *
 * cipher="-aes-256-cbc "
 * cipher="-chacha20"
 *
 * printf "the quick brown fox jumped over the lazy dog" | \
 *   openssl enc $cipher \
 *   -iv 508c39cf1b4a706a219ab837981ba4b0 \
 *   -K 0705b45c2be368b6aadf21656a89dad8fed6172170b7e78f638a650dab05d7ea | \
 *   od -t x1
 */

#define	TEST_KEY \
    "0705b45c2be368b6aadf21656a89dad8fed6172170b7e78f638a650dab05d7ea"

#define	TEST_AKEY \
    "9e31efad8c27303105669c4c21351558742c564c07d23702c45ca68bfc3ac43b"

#define	TEST_IV_96	"508c39cf1b4a706a219ab837"
#define	TEST_IV_128	"508c39cf1b4a706a219ab837981ba4b0"

static const struct test_case {
	crypto_cipher_t	cipher;
	const char *	iv;
	const char *	aetag;
	const char *	aad;
	const char *	expecting;
} test_cases[] = {
	{
		.cipher = AES_256_CBC,
		.iv = TEST_IV_128,
		.expecting =
		    "ee c1 39 07 55 68 49 1e e8 ef 71 d4 ac bd bf 43"
		    "63 b1 16 66 a8 c6 6e c8 a1 50 18 66 ff e8 87 e5"
		    "10 f5 4b 3c 6e c2 3e 1a 09 e3 d7 e7 53 f9 b1 61",
	},
	{
		.cipher = AES_256_GCM,
		.iv = TEST_IV_96,
		.aetag = "5e 5c fd 54 fb 13 c2 66 6b f0 23 57 d6 d7 5f c2",
		.expecting =
		    "3e 79 81 60 b5 33 23 fc 0b 10 cd fc 0c c8 41 cb"
		    "67 fd d7 35 a6 e8 5b 56 c4 53 ca 35 54 92 43 2a"
		    "d0 b3 95 56 54 c2 97 ba 51 80 fc e7",
	},
	{
		.cipher = CHACHA20,
		.iv = TEST_IV_128,
		.expecting =
		    "6e 3b 10 b5 3f 40 58 cb 5e db 8e bc d2 fe 4b cc"
		    "dc 0a 64 e5 b5 4a 10 50 cc fd b0 da 9c 5a bc 60"
		    "75 b8 a8 aa a0 40 ea 6a c9 ec fd bf",
	},
	{
		.cipher = CHACHA20_POLY1305,
		.iv = TEST_IV_96,
		.aetag = "73 eb e8 c8 13 24 ff 28 f8 b4 05 3a 03 15 81 ed",
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

static void
test_crypto(crypto_cipher_t c, const char *iv_str, const char *tag_str,
    const char *aad_str, const char *exp_str)
{
	uint8_t buf[TEST_TEXT_LEN * 2];
	size_t ivlen, keylen, akeylen, tmplen, explen;
	void *key, *akey, *iv, *tmpbuf, *exp_data;
	ssize_t nbytes, ret;
	crypto_t *cf;

	cf = crypto_create(c, CRYPTO_HMAC_PRIMARY);
	assert(cf != NULL);

	iv = hex_readmem_arbitrary(iv_str, strlen(iv_str), &ivlen);
	ret = crypto_set_iv(cf, iv, ivlen);
	assert(ret == 0);
	free(iv);

	key = hex_readmem_arbitrary(TEST_KEY, strlen(TEST_KEY), &keylen);
	ret = crypto_set_key(cf, key, keylen);
	assert(ret == 0);
	free(key);

	akey = hex_readmem_arbitrary(TEST_AKEY, strlen(TEST_AKEY), &akeylen);
	ret = crypto_set_authkey(cf, akey, akeylen);
	assert(ret == 0);
	free(akey);

	if (tag_str) {
		tmpbuf = hex_readmem_arbitrary(tag_str, strlen(tag_str), &tmplen);
		ret = crypto_set_aetag(cf, tmpbuf, tmplen);
		assert(ret == 0);
		free(tmpbuf);
	}

	if (aad_str) {
		tmpbuf = hex_readmem_arbitrary(aad_str, strlen(aad_str), &tmplen);
		ret = crypto_set_aad(cf, tmpbuf, tmplen);
		assert(ret == 0);
		free(tmpbuf);
	}

	nbytes = crypto_encrypt(cf, TEST_TEXT, TEST_TEXT_LEN,
	    buf, crypto_get_buflen(cf, TEST_TEXT_LEN));
	assert(nbytes > 0);

	exp_data = hex_readmem_arbitrary(exp_str, strlen(exp_str), &explen);
	assert(exp_data && (size_t)nbytes == explen);
	assert(memcmp(exp_data, buf, explen) == 0);
	free(exp_data);

	crypto_destroy(cf);
}

int
main(void)
{
	test_kdf();

	for (unsigned i = 0; i < __arraycount(test_cases); i++) {
		const struct test_case *t = &test_cases[i];
		test_crypto(t->cipher, t->iv, t->aetag, t->aad, t->expecting);
	}

	puts("ok");
	return 0;
}
