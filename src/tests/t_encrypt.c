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
#include <assert.h>

#include "rvault.h"
#include "crypto.h"
#include "utils.h"
#include "mock.h"

static crypto_t *
get_crypto(crypto_cipher_t c, void **iv, size_t *ivlen, const char *passphrase)
{
	crypto_t *crypto;
	ssize_t ret;

	crypto = crypto_create(c, CRYPTO_HMAC_PRIMARY);
	assert(crypto != NULL);

	if (*iv == NULL) {
		*iv = crypto_gen_iv(crypto, ivlen);
		assert(*iv != NULL);
	}

	ret = crypto_set_iv(crypto, *iv, *ivlen);
	assert(ret == 0);

	ret = crypto_set_passphrasekey(crypto, passphrase, NULL, 0);
	assert(ret == 0);

	return crypto;
}

static void
test_encdec(crypto_cipher_t c, const void *data, const size_t datalen,
    const char *passphrase)
{
	crypto_t *c_enc, *c_dec;
	char *dec_buf, *enc_buf;
	size_t ivlen, buflen, aetaglen;
	unsigned char *ae_tag;
	const void *tmpbuf;
	ssize_t ret, nbytes;
	void *iv = NULL;
	char aad = '$';

	/*
	 * Create a crypto object, get a buffer and encrypt.
	 */
	c_enc = get_crypto(c, &iv, &ivlen, passphrase);
	ret = crypto_set_aad(c_enc, &aad, sizeof(aad));
	assert(ret == 0);

	buflen = crypto_get_buflen(c_enc, datalen);
	enc_buf = malloc(buflen);
	assert(enc_buf != NULL);

	nbytes = crypto_encrypt(c_enc, data, datalen, enc_buf, buflen);
	assert(nbytes > 0);

	/*
	 * Obtain the AE tag and destroy the crypto object.
	 */
	tmpbuf = crypto_get_aetag(c_enc, &aetaglen);
	ae_tag = malloc(aetaglen);
	assert(ae_tag != NULL);
	memcpy(ae_tag, tmpbuf, aetaglen);
	crypto_destroy(c_enc);

	/*
	 * Create another crypto object; we want separate crypto objects
	 * for encryption/decryption to rule out any state re-use bugs.
	 *
	 * Also, get another buffer.  Attempt to decrypt with invalid
	 * AAD and AE tag.  Both attempts must fail.
	 */
	c_dec = get_crypto(c, &iv, &ivlen, passphrase);
	dec_buf = calloc(1, buflen);
	assert(dec_buf != NULL);

	ret = crypto_set_aad(c_dec, &aad, sizeof(aad));
	assert(ret == 0);

	ae_tag[0]++; // "corrupt" AE tag
	ret = crypto_set_aetag(c_dec, ae_tag, aetaglen);
	assert(ret == 0);

	ret = crypto_decrypt(c_dec, enc_buf, nbytes, dec_buf, buflen);
	assert(ret == -1);

	ae_tag[0]--; // restore the AE tag
	ret = crypto_set_aetag(c_dec, ae_tag, aetaglen);
	assert(ret == 0);

	aad++; // "corrupt" the AAD
	ret = crypto_set_aad(c_dec, &aad, sizeof(aad));
	assert(ret == 0);

	ret = crypto_decrypt(c_dec, enc_buf, nbytes, dec_buf, buflen);
	assert(ret == -1);

	aad--; // restore the AAD
	ret = crypto_set_aad(c_dec, &aad, sizeof(aad));
	assert(ret == 0);

	/*
	 * Decrypt and compare the original data with the output buffer.
	 */
	ret = crypto_decrypt(c_dec, enc_buf, nbytes, dec_buf, buflen);
	assert(ret > 0);

	assert((size_t)ret == datalen);
	assert(memcmp(dec_buf, data, datalen) == 0);

	/* Destroy and release everything. */
	crypto_destroy(c_dec);
	free(enc_buf);
	free(dec_buf);
	free(ae_tag);
	free(iv);
}

static void
test_sizes(const size_t *sizes, size_t count, unsigned multi)
{
	for (unsigned i = 0; i < count; i++) {
		const size_t len = sizes[i] * multi;
		unsigned char *buf = malloc(len);

		assert(buf != NULL);
		crypto_getrandbytes(buf, len);

		/* Non-AE cipher with HMAC-based AE. */
		test_encdec(AES_256_CBC, buf, len, TEST_TEXT);
		test_encdec(CHACHA20, buf, len, TEST_TEXT);

		/* AE cipher (no HMAC-based AE, naturally). */
		test_encdec(AES_256_GCM, buf, len, TEST_TEXT);
		test_encdec(CHACHA20_POLY1305, buf, len, TEST_TEXT);

		free(buf);
	}
}

int
main(void)
{
	const size_t small[] = { 1, 13, 16, 17, 31, 32, 33, 128, 1024 };
	const size_t large[] = { 1, 16, 128, 1024 };

	/*
	 * Large dataset: from bytes to megabytes and a gigabyte.
	 */
	test_sizes(small, __arraycount(small), 1); // bytes
	test_sizes(large, __arraycount(large), 1024 * 1024); // MB

	puts("ok");
	return 0;
}
