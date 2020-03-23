/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
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
#include "crypto_impl.h"
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
	case CHACHA20_POLY1305:
		/* Note: OpenSSL uses IETF (RFC 7539) variation. */
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

	switch (crypto->cipher) {
	case AES_256_GCM:
	case CHACHA20_POLY1305:
		/*
		 * Both ciphers use 128-bit authentication tag.
		 */
		crypto->tlen = 16;
		break;
	default:
		crypto->tlen = 0;
	}
	return 0;
}

/*
 * openssl_crypto_encrypt: see crypto_encrypt() for description.
 */
static ssize_t
openssl_crypto_encrypt(const crypto_t *crypto,
    const void *inbuf, size_t inlen, void *outbuf, size_t outlen __unused)
{
	const EVP_CIPHER *cipher = crypto->ctx;
	EVP_CIPHER_CTX *ctx;
	unsigned char *bufp;
	ssize_t nbytes = -1;
	int len;

	/* Note: OpenSSL APIs take signed int. */
	ASSERT(inlen <= INT_MAX);

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
		return -1;
	}
	if (EVP_EncryptInit_ex(ctx, cipher, NULL, crypto->key, crypto->iv) != 1) {
		nbytes = -1;
		goto err;
	}
	bufp = outbuf;
	nbytes = 0;

	/* AEAD: process any AE associated data  */
	if (crypto->ae_cipher && crypto->aad &&
	    EVP_EncryptUpdate(ctx, NULL, &len,
	    crypto->aad, crypto->aad_len) != 1) {
		nbytes = -1;
		goto err;
	}

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

	/* If AE cipher: obtain the authentication tag. */
	if (crypto->ae_cipher && EVP_CIPHER_CTX_ctrl(ctx,
	    EVP_CTRL_AEAD_GET_TAG, crypto->tlen, crypto->tag) != 1) {
		nbytes = -1;
		goto err;
	}
err:
	EVP_CIPHER_CTX_free(ctx);
	return nbytes;
}

/*
 * openssl_crypto_decrypt: see crypto_decrypt() description.
 */
static ssize_t
openssl_crypto_decrypt(const crypto_t *crypto,
    const void *inbuf, size_t inlen, void *outbuf, size_t outlen __unused)
{
	const EVP_CIPHER *cipher = crypto->ctx;
	EVP_CIPHER_CTX *ctx;
	unsigned char *bufp;
	ssize_t nbytes = -1;
	int len;

	/* Note: OpenSSL APIs take signed int. */
	ASSERT(inlen <= INT_MAX);

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
		return -1;
	}
	if (EVP_DecryptInit_ex(ctx, cipher, NULL, crypto->key, crypto->iv) != 1) {
		goto err;
	}
	bufp = outbuf;
	nbytes = 0;

	/* AEAD: process any AE associated data. */
	if (crypto->ae_cipher && crypto->aad &&
	    EVP_DecryptUpdate(ctx, NULL, &len,
	    crypto->aad, crypto->aad_len) != 1) {
		nbytes = -1;
		goto err;
	}

	if (EVP_DecryptUpdate(ctx, bufp, &len, inbuf, inlen) != 1) {
		nbytes = -1;
		goto err;
	}
	nbytes += len;

	/* If AE cipher: verify the authentication tag. */
	if (crypto->ae_cipher && EVP_CIPHER_CTX_ctrl(ctx,
	    EVP_CTRL_AEAD_SET_TAG, crypto->tlen, crypto->tag) != 1) {
		nbytes = -1;
		goto err;
	}

	if (EVP_DecryptFinal_ex(ctx, bufp + nbytes, &len) != 1) {
		nbytes = -1;
		goto err;
	}
	nbytes += len;
err:
	EVP_CIPHER_CTX_free(ctx);
	return nbytes;
}

static ssize_t
openssl_crypto_hmac(const crypto_t *crypto, const void *data, size_t data_len,
    const void *aad, size_t aad_len, unsigned char buf[static HMAC_MAX_BUFLEN])
{
	ssize_t nbytes = -1;
	const EVP_MD *h;
	HMAC_CTX *ctx;
	unsigned ret;

	switch (crypto->hmac_id) {
	case HMAC_SHA256:
		h = EVP_sha256();
		break;
	case HMAC_SHA3_256:
		h = EVP_sha3_256();
		break;
	default:
		errno = ENOTSUP;
		return -1;
	}
	ASSERT(EVP_MD_size(h) <= HMAC_MAX_BUFLEN);

	if ((ctx = HMAC_CTX_new()) == NULL) {
		return -1;
	}
	if (HMAC_Init_ex(ctx, crypto->auth_key, crypto->alen, h, NULL) != 1) {
		goto out;
	}
	if (aad && HMAC_Update(ctx, aad, aad_len) != 1) {
		goto out;
	}
	if (data && HMAC_Update(ctx, data, data_len) != 1) {
		goto out;
	}
	if (HMAC_Final(ctx, buf, &ret) != 1) {
		goto out;
	}
	nbytes = ret;
out:
	HMAC_CTX_free(ctx);
	return nbytes;
}

static void __constructor(101)
openssl_crypto_register(void)
{
	static const crypto_ops_t openssl_ops = {
		.create		= openssl_crypto_create,
		.destroy	= NULL,
		.encrypt	= openssl_crypto_encrypt,
		.decrypt	= openssl_crypto_decrypt,
		.hmac		= openssl_crypto_hmac,
	};
	crypto_engine_register("openssl", &openssl_ops);
}
