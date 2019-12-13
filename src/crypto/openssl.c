/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * OpenSSL wrapper for the symmetric ciphers and HMAC.
 *
 * Some notes:
 *
 * - OpenSSL uses PKCS#5 for AES in CBC.
 *
 * - Plain SHA-3 has HMAC properties, but OpenSSL also provides the
 *   primitive via its HMAC API.
 */

#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#define	__CRYPTO_PRIVATE
#include "crypto.h"
#include "utils.h"

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#error "OpenSSL version 1.1.0 or newer required"
#endif

static const EVP_CIPHER *
get_openssl_cipher(crypto_cipher_t c)
{
	const EVP_CIPHER *cipher;

	switch (c) {
	case AES_256_CBC:
		cipher = EVP_aes_256_cbc();
		break;
	case AES_256_GCM:
		cipher = EVP_aes_256_gcm();
		break;
	case CHACHA20:
		cipher = EVP_chacha20();
		break;
	case CHACHA20_POLY1305:
		cipher = EVP_chacha20_poly1305();
		break;
	default:
		return NULL;
	}
	return cipher;
}

static int
openssl_crypto_create(crypto_t *crypto)
{
	const EVP_CIPHER *cipher;

	if ((cipher = get_openssl_cipher(crypto->cipher)) == NULL) {
		return -1;
	}
	crypto->ctx = (void *)(uintptr_t)cipher;
	crypto->klen = EVP_CIPHER_key_length(cipher);
	crypto->ilen = EVP_CIPHER_iv_length(cipher);
	crypto->blen = EVP_CIPHER_block_size(cipher);
	return 0;
}

/*
 * openssl_crypto_encrypt: see crypto_encrypt() for description.
 */
static ssize_t
openssl_crypto_encrypt(const crypto_t *crypto,
    const void *inbuf, size_t inlen, void *outbuf, size_t outlen)
{
	const EVP_CIPHER *cipher = crypto->ctx;
	EVP_CIPHER_CTX *ctx;
	unsigned char *bufp;
	ssize_t nbytes = -1;
	int len;

	if (crypto->cipher == AES_256_GCM ||
	    crypto->cipher == CHACHA20_POLY1305) {
		errno = ENOTSUP; // TODO
		return -1;
	}

	/* Note: OpenSSL APIs take signed int. */
	if (inlen > INT_MAX || roundup(inlen, crypto->blen) > outlen) {
		return -1;
	}
	if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
		return -1;
	}
	if (EVP_EncryptInit_ex(ctx, cipher, NULL, crypto->key, crypto->iv) != 1) {
		nbytes = -1;
		goto err;
	}
	bufp = outbuf;
	nbytes = 0;

	if (EVP_EncryptUpdate(ctx, bufp, &len, inbuf, inlen) != 1) {
		nbytes = -1;
		goto err;
	}
	nbytes += len;

	if (EVP_EncryptFinal_ex(ctx, bufp + nbytes, &len) != 1) {
		nbytes = -1;
		goto err;
	}
	nbytes += len;
err:
	EVP_CIPHER_CTX_free(ctx);
	return nbytes;
}

/*
 * openssl_crypto_decrypt: see crypto_decrypt() description.
 */
static ssize_t
openssl_crypto_decrypt(const crypto_t *crypto,
    const void *inbuf, size_t inlen, void *outbuf, size_t outlen)
{
	const EVP_CIPHER *cipher = crypto->ctx;
	EVP_CIPHER_CTX *ctx;
	unsigned char *bufp;
	ssize_t nbytes = -1;
	int len;

	if (crypto->cipher == AES_256_GCM ||
	    crypto->cipher == CHACHA20_POLY1305) {
		errno = ENOTSUP; // TODO
		return -1;
	}

	/* Note: OpenSSL APIs take signed int. */
	if (inlen > INT_MAX || roundup(inlen, crypto->blen) > outlen) {
		return -1;
	}
	if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
		return -1;
	}
	if (EVP_DecryptInit_ex(ctx, cipher, NULL, crypto->key, crypto->iv) != 1) {
		goto err;
	}
	bufp = outbuf;
	nbytes = 0;

	if (EVP_DecryptUpdate(ctx, bufp, &len, inbuf, inlen) != 1) {
		nbytes = -1;
		goto err;
	}
	nbytes += len;

	if (EVP_DecryptFinal_ex(ctx, bufp + nbytes, &len) != 1) {
		nbytes = -1;
		goto err;
	}
	nbytes += len;
err:
	EVP_CIPHER_CTX_free(ctx);
	return nbytes;
}

/*
 * hmac_sha3_256: should be a plain SHA-3 256-bit hash.
 */
ssize_t
hmac_sha3_256(const void *key, size_t klen, const void *data, size_t dlen,
    unsigned char buf[static HMAC_SHA3_256_BUFLEN])
{
	const EVP_MD *h = EVP_sha3_256();
	unsigned nbytes;
	HMAC_CTX *ctx;

	ASSERT(EVP_MD_size(h) == HMAC_SHA3_256_BUFLEN);

	if (dlen > INT_MAX) {
		return -1;
	}

	if ((ctx = HMAC_CTX_new()) == NULL) {
		return -1;
	}
	HMAC_Init_ex(ctx, key, klen, h, NULL);
	HMAC_Update(ctx, data, dlen);
	HMAC_Final(ctx, buf, &nbytes);
	HMAC_CTX_free(ctx);

	return (size_t)nbytes;
}

static void __constructor
openssl_crypto_register(void)
{
	static const crypto_ops_t openssl_ops = {
		.create		= openssl_crypto_create,
		.destroy	= NULL,
		.encrypt	= openssl_crypto_encrypt,
		.decrypt	= openssl_crypto_decrypt,
	};
	crypto_engine_register("openssl", &openssl_ops);
}
