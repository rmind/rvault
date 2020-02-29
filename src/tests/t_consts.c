/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
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

static const char *test_iv =
    "508c39cf1b4a706a219ab837981ba4b0";

static const char *test_key =
    "0705b45c2be368b6aadf21656a89dad8fed6172170b7e78f638a650dab05d7ea";

static const char *aes_expected_val =
    "ee c1 39 07 55 68 49 1e e8 ef 71 d4 ac bd bf 43"
    "63 b1 16 66 a8 c6 6e c8 a1 50 18 66 ff e8 87 e5"
    "10 f5 4b 3c 6e c2 3e 1a 09 e3 d7 e7 53 f9 b1 61";

static const char *chacha20_expected_val =
    "6e 3b 10 b5 3f 40 58 cb 5e db 8e bc d2 fe 4b cc"
    "dc 0a 64 e5 b5 4a 10 50 cc fd b0 da 9c 5a bc 60"
    "75 b8 a8 aa a0 40 ea 6a c9 ec fd bf";

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
test_crypto(crypto_cipher_t c, const char *iv_str, const char *key_str,
    const char *exp_str)
{
	uint8_t buf[TEST_TEXT_LEN * 2];
	size_t ivlen, keylen, explen;
	void *key, *iv, *exp_data;
	ssize_t nbytes, ret;
	crypto_t *cf;

	cf = crypto_create(c);
	assert(cf != NULL);

	iv = hex_readmem_arbitrary(iv_str, strlen(iv_str), &ivlen);
	ret = crypto_set_iv(cf, iv, ivlen);
	assert(ret == 0);
	free(iv);

	key = hex_readmem_arbitrary(key_str, strlen(key_str), &keylen);
	ret = crypto_set_key(cf, key, keylen);
	assert(ret == 0);
	free(key);

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
	test_crypto(AES_256_CBC, test_iv, test_key, aes_expected_val);
	test_crypto(CHACHA20, test_iv, test_key, chacha20_expected_val);
	puts("ok");
	return 0;
}
