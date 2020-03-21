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
	case CHACHA20:
		return MBEDTLS_CIPHER_CHACHA20;
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

	crypto->klen = mbedtls_cipher_get_key_bitlen(ctx) / 8;
	crypto->ilen = mbedtls_cipher_get_iv_size(ctx);
	crypto->blen = mbedtls_cipher_get_block_size(ctx);

	switch (crypto->cipher) {
	case AES_256_GCM:
	case CHACHA20_POLY1305:
		crypto->tlen = 16;
		break;
	default:
		crypto->tlen = 0;
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

	if (mbedtls_cipher_setkey(ctx, crypto->key, crypto->klen * 8,
	    MBEDTLS_ENCRYPT) != 0) {
		errno = EINVAL;
		return -1;
	}

	switch (crypto->cipher) {
	case AES_256_CBC:
	case CHACHA20:
		ret = mbedtls_cipher_crypt(ctx, crypto->iv, crypto->ilen,
		    inbuf, inlen, outbuf, &nbytes);
		break;
	case AES_256_GCM:
	case CHACHA20_POLY1305:
		ret = mbedtls_cipher_auth_encrypt(ctx,
		    crypto->iv, crypto->ilen, NULL, 0,
		    inbuf, inlen, outbuf, &nbytes,
		    crypto->tag, crypto->tlen);
		break;
	default:
		abort();
	}

	return (ret == 0) ? nbytes : -1;
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

	if (mbedtls_cipher_setkey(ctx, crypto->key, crypto->klen * 8,
	    MBEDTLS_DECRYPT) != 0) {
		errno = EINVAL;
		return -1;
	}

	switch (crypto->cipher) {
	case AES_256_CBC:
	case CHACHA20:
		ret = mbedtls_cipher_crypt(ctx, crypto->iv, crypto->ilen,
		    inbuf, inlen, outbuf, &nbytes);
		break;
	case AES_256_GCM:
	case CHACHA20_POLY1305:
		ret = mbedtls_cipher_auth_decrypt(ctx,
		    crypto->iv, crypto->ilen, NULL, 0,
		    inbuf, inlen, outbuf, &nbytes,
		    crypto->tag, crypto->tlen);
		break;
	default:
		abort();
	}

	return (ret == 0) ? nbytes : -1;
}

static ssize_t
mbedtls_crypto_hmac(const crypto_t *crypto, const void *data, size_t dlen,
    const void *aad, size_t aad_len, unsigned char buf[static HMAC_MAX_BUFLEN])
{
	const mbedtls_md_info_t *md;
	mbedtls_md_type_t md_type;
	ssize_t nbytes = -1;

	switch (crypto->hmac_id) {
	case HMAC_SHA256:
		md_type = MBEDTLS_MD_SHA256;
		nbytes = 32;
		break;
	default:
		errno = ENOTSUP;
		return -1;
	}
	ASSERT(nbytes <= HMAC_MAX_BUFLEN);

	if ((md = mbedtls_md_info_from_type(md_type)) == NULL) {
		return -1;
	}
	if (mbedtls_md_hmac(md, crypto->auth_key, crypto->alen,
	    data, dlen, buf) != 0) {
		return -1;
	}
	return nbytes;
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
