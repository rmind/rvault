/*
 * Copyright (c) 2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * mbedtls wrapper for the symmetric ciphers and HMAC.
 */

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>

#define	__CRYPTO_PRIVATE
#include "crypto_impl.h"
#include "utils.h"

static mbedtls_cipher_type_t
get_mbedtls_cipher(crypto_cipher_t c)
{
	switch (c) {
	case AES_256_CBC:
		return MBEDTLS_CIPHER_AES_256_CBC;
	case AES_256_GCM:
		return MBEDTLS_CIPHER_AES_256_GCM;
	case CHACHA20_POLY1305:
		return MBEDTLS_CIPHER_CHACHA20_POLY1305;
	default:
		break;
	}
	return MBEDTLS_CIPHER_NONE;
}

static int
mbedtls_crypto_create(crypto_t *crypto)
{
	mbedtls_cipher_context_t *ctx;
	mbedtls_cipher_type_t cipher;

	cipher = get_mbedtls_cipher(crypto->cipher);
	if (cipher == MBEDTLS_CIPHER_NONE) {
		return -1;
	}
	if ((ctx = calloc(1, sizeof(mbedtls_cipher_context_t))) == NULL) {
		return -1;
	}
	mbedtls_cipher_setup(ctx, mbedtls_cipher_info_from_type(cipher));
	crypto->ctx = ctx;

	crypto->key_len = mbedtls_cipher_get_key_bitlen(ctx) / 8;
	crypto->iv_len = mbedtls_cipher_get_iv_size(ctx);
	crypto->block_size = mbedtls_cipher_get_block_size(ctx);

	switch (crypto->cipher) {
	case AES_256_GCM:
	case CHACHA20_POLY1305:
		crypto->tag_len = 16;
		break;
	default:
		crypto->tag_len = 0;
		break;
	}
	return 0;
}

static void
mbedtls_crypto_destroy(crypto_t *crypto)
{
	mbedtls_cipher_context_t *ctx = crypto->ctx;
	mbedtls_cipher_free(ctx);
	free(ctx);
}

/*
 * mbedtls_crypto_encrypt: see crypto_encrypt() for description.
 */
static ssize_t
mbedtls_crypto_encrypt(const crypto_t *crypto,
    const void *inbuf, size_t inlen, void *outbuf, size_t outlen __unused)
{
	mbedtls_cipher_context_t *ctx = crypto->ctx;
	size_t nbytes;
	int ret;

	if (mbedtls_cipher_setkey(ctx, crypto->key, crypto->key_len * 8,
	    MBEDTLS_ENCRYPT) != 0) {
		errno = EINVAL;
		return -1;
	}

	switch (crypto->cipher) {
	case AES_256_CBC:
		ret = mbedtls_cipher_crypt(ctx, crypto->iv, crypto->iv_len,
		    inbuf, inlen, outbuf, &nbytes);
		break;
	case AES_256_GCM:
	case CHACHA20_POLY1305:
		ret = mbedtls_cipher_auth_encrypt(ctx,
		    crypto->iv, crypto->iv_len, crypto->aad, crypto->aad_len,
		    inbuf, inlen, outbuf, &nbytes,
		    crypto->tag, crypto->tag_len);
		break;
	default:
		abort();
	}

	return (ret == 0) ? (ssize_t)nbytes : -1;
}

/*
 * mbedtls_crypto_decrypt: see crypto_decrypt() for description.
 */
static ssize_t
mbedtls_crypto_decrypt(const crypto_t *crypto,
    const void *inbuf, size_t inlen, void *outbuf, size_t outlen __unused)
{
	mbedtls_cipher_context_t *ctx = crypto->ctx;
	size_t nbytes;
	int ret;

	if (mbedtls_cipher_setkey(ctx, crypto->key, crypto->key_len * 8,
	    MBEDTLS_DECRYPT) != 0) {
		errno = EINVAL;
		return -1;
	}

	switch (crypto->cipher) {
	case AES_256_CBC:
		ret = mbedtls_cipher_crypt(ctx, crypto->iv, crypto->iv_len,
		    inbuf, inlen, outbuf, &nbytes);
		break;
	case AES_256_GCM:
	case CHACHA20_POLY1305:
		ret = mbedtls_cipher_auth_decrypt(ctx,
		    crypto->iv, crypto->iv_len, crypto->aad, crypto->aad_len,
		    inbuf, inlen, outbuf, &nbytes,
		    crypto->tag, crypto->tag_len);
		break;
	default:
		abort();
	}

	return (ret == 0) ? (ssize_t)nbytes : -1;
}

static ssize_t
mbedtls_crypto_hmac(const crypto_t *crypto, const void *data, size_t dlen,
    const void *aad, size_t aad_len, unsigned char buf[static HMAC_MAX_BUFLEN])
{
	const mbedtls_md_info_t *md;
	mbedtls_md_context_t ctx;
	ssize_t ret = -1;
	size_t nbytes;

	switch (crypto->hmac_id) {
	case HMAC_SHA256:
		md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
		nbytes = 32;
		break;
	default:
		errno = ENOTSUP;
		return -1;
	}
	ASSERT(nbytes <= HMAC_MAX_BUFLEN);

	mbedtls_md_init(&ctx);
	if (mbedtls_md_setup(&ctx, md, 1) != 0)
		goto out;
	if (mbedtls_md_hmac_starts(&ctx, crypto->auth_key,
	    crypto->auth_key_len) != 0)
		goto out;
	if (aad && mbedtls_md_hmac_update(&ctx, aad, aad_len) != 0)
		goto out;
	if (data && mbedtls_md_hmac_update(&ctx, data, dlen) != 0)
		goto out;
	if (mbedtls_md_hmac_finish(&ctx, buf) != 0)
		goto out;
	ret = nbytes;
out:
	mbedtls_md_free(&ctx);
	return ret;
}

static void __constructor(102)
mbedtls_crypto_register(void)
{
	static const crypto_ops_t mbedtls_ops = {
		.create		= mbedtls_crypto_create,
		.destroy	= mbedtls_crypto_destroy,
		.encrypt	= mbedtls_crypto_encrypt,
		.decrypt	= mbedtls_crypto_decrypt,
		.hmac		= mbedtls_crypto_hmac,
	};
	crypto_engine_register("mbedtls", &mbedtls_ops);
}
