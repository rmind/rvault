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
#include <assert.h>

#include "rvault.h"
#include "crypto.h"
#include "utils.h"
#include "mock.h"

static void
test_encdec(crypto_cipher_t c, const void *data, const size_t datalen,
    const char *passphrase, const bool should_use_ae)
{
	char *iv, *dec_buf, *enc_buf;
	size_t len, buflen, aetaglen;
	ssize_t ret, nbytes;
	const void *aetag;
	crypto_t *cf;

	/*
	 * Setup the crypto object.
	 */
	cf = crypto_create(c);
	assert(cf != NULL);

	iv = crypto_gen_iv(cf, &len);
	assert(iv != NULL);
	crypto_set_iv(cf, iv, len);
	free(iv);

	ret = crypto_set_passphrasekey(cf, passphrase, NULL, 0);
	assert(ret == 0);

	/*
	 * Get a buffer and encrypt.
	 */
	buflen = crypto_get_buflen(cf, datalen);
	enc_buf = malloc(buflen);
	assert(enc_buf != NULL);
	nbytes = crypto_encrypt(cf, data, datalen, enc_buf, buflen);
	assert(nbytes > 0);

	if (crypto_using_ae(cf)) {
		assert(should_use_ae);
		aetag = crypto_get_tag(cf, &aetaglen);
		assert(aetag != NULL);
	} else {
		assert(!should_use_ae);
		aetag = NULL;
	}

	if (aetag) {
		ret = crypto_set_tag(cf, aetag, aetaglen);
		assert(ret == 0);
	}

	/*
	 * Get another buffer and decrypt.
	 */
	dec_buf = calloc(1, buflen);
	assert(dec_buf != NULL);
	ret = crypto_decrypt(cf, enc_buf, nbytes, dec_buf, buflen);
	assert(ret > 0);
	free(enc_buf);

	/*
	 * Compare the original data with the output buffer.
	 */
	assert((size_t)ret == datalen);
	assert(memcmp(dec_buf, data, datalen) == 0);
	free(dec_buf);

	crypto_destroy(cf);
}

static void
test_sizes(const unsigned *sizes, size_t count, unsigned multi)
{
	for (unsigned i = 0; i < count; i++) {
		const size_t len = (size_t)sizes[i] * multi;
		unsigned char *buf = malloc(len);

		assert(buf != NULL);
		crypto_getrandbytes(buf, len);

		test_encdec(AES_256_CBC, buf, len, TEST_TEXT, false);
		test_encdec(CHACHA20, buf, len, TEST_TEXT, false);

		test_encdec(AES_256_GCM, buf, len, TEST_TEXT, true);
		test_encdec(CHACHA20_POLY1305, buf, len, TEST_TEXT, true);

		free(buf);
	}
}

static void
test_size_profiles(void)
{
	const unsigned small_sizes[] = { 1, 13, 16, 17, 31, 32, 33, 128, 1024 };
	const unsigned large_sizes[] = { 1, 16, 128, 1024 };

	test_sizes(small_sizes, __arraycount(small_sizes), 1); // bytes
	test_sizes(large_sizes, __arraycount(large_sizes), 1024 * 1024); // MB
}

int
main(void)
{
	static const uint8_t zeros[15] = {0};

	/* 15 bytes of zeros. */
	test_encdec(AES_256_CBC, zeros, sizeof(zeros), "meow", false);
	test_encdec(AES_256_GCM, zeros, sizeof(zeros), "meow", true);

	/*
	 * Basic cipher tests.
	 */
	test_encdec(AES_256_CBC, TEST_TEXT, TEST_TEXT_LEN, "meow", false);
	test_encdec(CHACHA20, TEST_TEXT, TEST_TEXT_LEN, "meow", false);

	test_encdec(AES_256_GCM, TEST_TEXT, TEST_TEXT_LEN, "meow", true);
	test_encdec(CHACHA20_POLY1305, TEST_TEXT, TEST_TEXT_LEN, "meow", true);

	/* Large dataset: from bytes to megabytes and a gigabyte. */
	test_size_profiles();

	puts("ok");
	return 0;
}
