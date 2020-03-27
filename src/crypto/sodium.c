/*
 * Copyright (c) 2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * libsodium wrapper for the symmetric ciphers and HMAC.
 */

#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include <sodium.h>

#define	__CRYPTO_PRIVATE
#include "crypto_impl.h"
#include "utils.h"

static int
sodium_crypto_create(crypto_t *crypto)
{
	static bool sodium_init_done = false;

	if (!sodium_init_done) {
		if (sodium_init() == -1) {
			return -1;
		}
		sodium_init_done = true;
	}

	switch (crypto->cipher) {
	case AES_256_GCM:
		if (!crypto_aead_aes256gcm_is_available()) {
			errno = ENOTSUP;
			return -1;
		}
		crypto->key_len = crypto_aead_aes256gcm_KEYBYTES;
		crypto->iv_len = crypto_aead_aes256gcm_NPUBBYTES;
		crypto->block_size = 1; // GCM does not require padding
		crypto->tag_len = crypto_aead_aes256gcm_ABYTES;
		break;
	case CHACHA20_POLY1305:
		crypto->key_len = crypto_aead_chacha20poly1305_IETF_KEYBYTES;
		crypto->iv_len = crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
		crypto->block_size = 1; // stream cipher, no padding
		crypto->tag_len = crypto_aead_chacha20poly1305_IETF_ABYTES;
		break;
	default:
		errno = ENOTSUP;
		return -1;
	}
	return 0;
}

/*
 * sodium_crypto_encrypt: see crypto_encrypt() for description.
 */
static ssize_t
sodium_crypto_encrypt(const crypto_t *crypto,
    const void *inbuf, size_t inlen, void *outbuf, size_t outlen __unused)
{
	int ret;

	switch (crypto->cipher) {
	case AES_256_GCM:
		ret = crypto_aead_aes256gcm_encrypt_detached(outbuf,
		    crypto->tag, NULL, inbuf, inlen, crypto->aad,
		    crypto->aad_len, NULL, crypto->iv, crypto->key);
		break;
	case CHACHA20_POLY1305:
		ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached(outbuf,
		    crypto->tag, NULL, inbuf, inlen, crypto->aad,
		    crypto->aad_len, NULL, crypto->iv, crypto->key);
		break;
	default:
		abort();
	}

	return (ret == 0) ? (ssize_t)inlen : -1;
}

/*
 * sodium_crypto_decrypt: see crypto_decrypt() for description.
 */
static ssize_t
sodium_crypto_decrypt(const crypto_t *crypto,
    const void *inbuf, size_t inlen, void *outbuf, size_t outlen __unused)
{
	int ret;

	switch (crypto->cipher) {
	case AES_256_GCM:
		ret = crypto_aead_aes256gcm_decrypt_detached(outbuf,
		    NULL, inbuf, inlen, crypto->tag, crypto->aad,
		    crypto->aad_len, crypto->iv, crypto->key);
		break;
	case CHACHA20_POLY1305:
		ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached(outbuf,
		    NULL, inbuf, inlen, crypto->tag, crypto->aad,
		    crypto->aad_len, crypto->iv, crypto->key);
		break;
	default:
		abort();
	}

	return (ret == 0) ? (ssize_t)inlen : -1;
}

static ssize_t
sodium_crypto_hmac(const crypto_t *crypto, const void *data, size_t dlen,
    const void *aad, size_t aad_len, unsigned char buf[static HMAC_MAX_BUFLEN])
{
	crypto_auth_hmacsha256_state sha256;

	switch (crypto->hmac_id) {
	case HMAC_SHA256:
		if (crypto_auth_hmacsha256_init(&sha256,
		    crypto->auth_key, crypto->auth_key_len) == -1) {
			return -1;
		}
		if (aad && crypto_auth_hmacsha256_update(&sha256,
		    aad, aad_len) == -1) {
			return -1;
		}
		if (data && crypto_auth_hmacsha256_update(&sha256,
		    data, dlen) == -1) {
			return -1;
		}
		if (crypto_auth_hmacsha256_final(&sha256, buf) == -1) {
			return -1;
		}
		return crypto_auth_hmacsha256_BYTES;
	default:
		break;
	}

	errno = ENOTSUP;
	return -1;
}

static void __constructor(102)
sodium_crypto_register(void)
{
	static const crypto_ops_t sodium_ops = {
		.create		= sodium_crypto_create,
		.destroy	= NULL,
		.encrypt	= sodium_crypto_encrypt,
		.decrypt	= sodium_crypto_decrypt,
		.hmac		= sodium_crypto_hmac,
	};
	crypto_engine_register("sodium", &sodium_ops);
}
