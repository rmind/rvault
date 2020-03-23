/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * Cryptographic module: abstracts crypto libraries and provides
 * a uniform API for the symmetric encryption and HMAC.
 *
 * Implements HMAC-based generic composition using the EtM scheme.
 * Authenticated encryption (AE) is enforced.  If AE-cipher is not
 * used, then the AE tag is "emulated" using the HMAC-based scheme.
 * Crypto object without any form of AE is not supported.
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#define	__CRYPTO_PRIVATE
#include "crypto_impl.h"
#include "crypto.h"
#include "utils.h"

#define	CRYPTO_MIN_KEY_LEN	32

/*
 * Available crypto engines (libraries).
 */
typedef struct {
	const char *		name;
	const crypto_ops_t *	ops;
} cipher_engine_t;

static cipher_engine_t		crypto_engines[CRYPTO_MAX_ENGINES];
static unsigned			crypto_engines_count = 0;

/*
 * Available ciphers for symmetric encryption and MAC algorithms.
 */

static const struct {
	const char *		name;
	crypto_cipher_t		id;
} cipher_str2id[] = {
#if !defined(USE_AE_CIPHERS_ONLY)
	{ "aes-256-cbc",	AES_256_CBC		},
#endif
	{ "aes-256-gcm",	AES_256_GCM		},
	{ "chacha20-poly1305",	CHACHA20_POLY1305	},
	{ NULL,			CIPHER_NONE		},
};

static const struct {
	const char *		name;
	crypto_hmac_t		id;
} mac_str2id[] = {
	{ "sha-256",		HMAC_SHA256		},
	{ "sha3-256",		HMAC_SHA3_256		},
	{ NULL,			HMAC_NONE		},
};

/*
 * crypto_engine_register: add a new cryptographic library.
 */
int
crypto_engine_register(const char *name, const crypto_ops_t *ops)
{
	if (crypto_engines_count == CRYPTO_MAX_ENGINES) {
		return -1;
	}
	crypto_engines[crypto_engines_count].name = name;
	crypto_engines[crypto_engines_count].ops = ops;
	crypto_engines_count++;
	return 0;
}

/*
 * crypto_cipher_list: get a list of available ciphers.
 * Note: populates the list on first invocation.
 */
const char **
crypto_cipher_list(unsigned *nitems)
{
	static const char *cipher_list[__arraycount(cipher_str2id)];
	static unsigned cipher_count = 0;

	if (!cipher_count) {
		while (cipher_str2id[cipher_count].name) {
			cipher_list[cipher_count] =
			    cipher_str2id[cipher_count].name;
			cipher_count++;
		}
		ASSERT(cipher_count > 0);
	}
	*nitems = cipher_count;
	return cipher_list;
}

/*
 * crypto_cipher_id: get the cipher type from the name.
 */
crypto_cipher_t
crypto_cipher_id(const char *cipher)
{
	for (unsigned i = 0; cipher_str2id[i].name != NULL; i++) {
		if (strcasecmp(cipher, cipher_str2id[i].name) == 0) {
			return cipher_str2id[i].id;
		}
	}
	return CIPHER_NONE;
}

/*
 * crypto_hmac_id: get the HMAC type from the name.
 */
crypto_hmac_t
crypto_hmac_id(const char *cipher)
{
	for (unsigned i = 0; mac_str2id[i].name != NULL; i++) {
		if (strcasecmp(cipher, mac_str2id[i].name) == 0) {
			return mac_str2id[i].id;
		}
	}
	return HMAC_NONE;
}

static const crypto_ops_t *
crypto_select_library(void)
{
	const char *crypto_lib = getenv("RVAULT_CRYPTO_LIB");
	const crypto_ops_t *crypto_ops = NULL;

	/*
	 * Use the chosen crypto library; otherwise, just pick the first one.
	 */
	if (crypto_lib) {
		for (unsigned i = 0; i < crypto_engines_count; i++) {
			const cipher_engine_t *eng = &crypto_engines[i];

			if (strcmp(eng->name, crypto_lib) == 0) {
				crypto_ops = eng->ops;
				break;
			}
		}
	} else if (crypto_engines_count) {
		crypto_ops = crypto_engines[0].ops;
	}
	return crypto_ops;
}

/*
 * crypto_create: construct a new crypto object.
 */
crypto_t *
crypto_create(crypto_cipher_t c, crypto_hmac_t hmac_id)
{
	const crypto_ops_t *crypto_ops;
	crypto_t *crypto;

	ASSERT(c != CIPHER_NONE);
	ASSERT(hmac_id != HMAC_NONE);

	/*
	 * Construct the crypto object.
	 */
	if ((crypto_ops = crypto_select_library()) == NULL) {
		errno = ENOTSUP;
		return NULL;
	}
	if ((crypto = calloc(1, sizeof(crypto_t))) == NULL) {
		return NULL;
	}
	crypto->cipher = c;
	crypto->ops = crypto_ops;
	crypto->hmac_id = hmac_id;

	if (crypto->ops->create(crypto) == -1) {
		goto err;
	}
	ASSERT(crypto->klen >= CRYPTO_MIN_KEY_LEN);
	crypto->alen = CRYPTO_MIN_KEY_LEN;

	/*
	 * Determine the AE mechanism.
	 */
	if (crypto->tlen == 0) {
		ssize_t tlen;

		if ((tlen = crypto_hmac_len(hmac_id)) == -1) {
			goto err;
		}
		crypto->tlen = tlen;
		crypto->ae_cipher = false;
	} else {
		crypto->ae_cipher = true;
	}

	/*
	 * Allocate the buffers.
	 */
	if ((crypto->iv = malloc(crypto->ilen)) == NULL) {
		goto err;
	}
	if ((crypto->key = malloc(crypto->klen)) == NULL) {
		goto err;
	}
	if ((crypto->auth_key = malloc(crypto->alen)) == NULL) {
		goto err;
	}
	if ((crypto->tag = malloc(crypto->tlen)) == NULL) {
		goto err;
	}

	return crypto;
err:
	crypto_destroy(crypto);
	return NULL;
}

/*
 * crypto_gen_iv: allocate and set the Initialization Vector (IV).
 */
void *
crypto_gen_iv(crypto_t *crypto, size_t *len)
{
	const size_t iv_len = crypto->ilen;
	void *iv;

	ASSERT(iv_len > 0);

	if ((iv = malloc(iv_len)) == NULL) {
		return NULL;
	}
	if (crypto_getrandbytes(iv, iv_len) == -1) {
		free(iv);
		return NULL;
	}
	*len = iv_len;
	return iv;
}

/*
 * crypto_set_iv: copy and assign the Initialization Vector (IV).
 */
int
crypto_set_iv(crypto_t *crypto, const void *iv, size_t len)
{
	if (crypto->ilen != len) {
		errno = EINVAL;
		return -1;
	}
	memcpy(crypto->iv, iv, crypto->ilen);
	crypto->iv_set = true;
	return 0;
}

/*
 * crypto_set_passphrasekey: generate the key from the given passphrase.
 */
int
crypto_set_passphrasekey(crypto_t *crypto, const char *passphrase,
    const void *kp, size_t kp_len)
{
	const size_t dlen = crypto->klen + crypto->alen;
	void *dkey, *akey;

	ASSERT(crypto->klen >= CRYPTO_MIN_KEY_LEN);
	ASSERT(crypto->alen >= CRYPTO_MIN_KEY_LEN);

	/*
	 * Derive encryption key and the authentication key.
	 * To satisfy the EtM scheme, we need these to be two independent
	 * keys (Bellare and Namprempre, 2007).
	 */

	if ((dkey = malloc(dlen)) == NULL) {
		return -1;
	}
	if (kdf_passphrase_genkey(passphrase, kp, kp_len, dkey, dlen) == -1) {
		free(dkey);
		return -1;
	}

	memcpy(crypto->key, dkey, crypto->klen);
	akey = (uint8_t *)dkey + crypto->klen;
	memcpy(crypto->auth_key, akey, crypto->alen);

	crypto_memzero(dkey, dlen);
	free(dkey);

	crypto->enc_key_set = true;
	crypto->auth_key_set = true;
	return 0;
}

/*
 * crypto_set_key: copy and assign the key.
 */
int
crypto_set_key(crypto_t *crypto, const void *key, size_t len)
{
	if (crypto->klen != len) {
		return -1;
	}
	memcpy(crypto->key, key, crypto->klen);
	crypto->enc_key_set = true;
	return 0;
}

const void *
crypto_get_key(const crypto_t *crypto, size_t *key_len)
{
	ASSERT(crypto->enc_key_set);
	*key_len = crypto->klen;
	return crypto->key;
}

ssize_t
crypto_get_keylen(const crypto_t *crypto)
{
	ASSERT(crypto->klen > 0);
	return crypto->klen;
}

/*
 * crypto_set_authkey: copy and assign the authentication key.
 */
int
crypto_set_authkey(crypto_t *crypto, const void *akey, size_t len)
{
	if (crypto->alen != len) {
		return -1;
	}
	memcpy(crypto->auth_key, akey, crypto->alen);
	crypto->auth_key_set = true;
	return 0;
}

const void *
crypto_get_authkey(const crypto_t *crypto, size_t *akey_len)
{
	ASSERT(crypto->auth_key_set);
	*akey_len = crypto->alen;
	return crypto->auth_key;
}

ssize_t
crypto_get_authkeylen(const crypto_t *crypto)
{
	ASSERT(crypto->alen > 0);
	return crypto->alen;
}

bool
crypto_cipher_ae_p(const crypto_t *crypto)
{
	return crypto->ae_cipher;
}

/*
 * crypto_set_aad: set the additional authenticated data (AAD).
 *
 * => The caller must keep the reference valid for encrypt/decrypt.
 */
int
crypto_set_aad(crypto_t *crypto, const void *aad, size_t aad_len)
{
	crypto->aad = aad;
	crypto->aad_len = aad_len;
	return 0;
}

/*
 * crypto_set_aetag: set the authenticated encryption (AE) tag or HMAC.
 */
int
crypto_set_aetag(crypto_t *crypto, const void *tag, size_t len)
{
	if (crypto->tlen != len) {
		return -1;
	}
	memcpy(crypto->tag, tag, crypto->tlen);
	return 0;
}

/*
 * crypto_get_aetaglen: return the AE tag or HMAC length.
 */
size_t
crypto_get_aetaglen(const crypto_t *crypto)
{
	return crypto->tlen;
}

const void *
crypto_get_aetag(crypto_t *crypto, size_t *tag_len)
{
	*tag_len = crypto->tlen;
	return crypto->tag;
}

size_t
crypto_get_buflen(const crypto_t *crypto, size_t length)
{
	/*
	 * As per OpenSSL documentation:
	 * - Encryption: in_bytes + cipher_block_size - 1
	 * - Decryption: in_bytes + cipher_block_size
	 *
	 * Just add a block size, to keep it simple.
	 */
	return length + crypto->blen;
}

static bool
crypto_setup_done_p(const crypto_t *crypto)
{
	return crypto->iv_set && crypto->enc_key_set &&
	    (crypto->ae_cipher || crypto->auth_key_set);
}

/*
 * crypto_encrypt: encrypt the data given in the input buffer.
 *
 * => Output buffer size must be be at least crypto_get_buflen(inlen).
 * => Returns the number of bytes written or -1 on failure.
 * => Note: the number of bytes written may be greater than the original
 *    length of data (e.g. due to padding).
 */
ssize_t
crypto_encrypt(crypto_t *crypto, const void *inbuf, size_t inlen,
    void *outbuf, size_t outlen)
{
	const ssize_t tlen = crypto->tlen;
	ssize_t ret = -1;

	if (!crypto_setup_done_p(crypto)) {
		errno = EINVAL;
		goto out;
	}
	if (inlen > INT_MAX || roundup(inlen, crypto->blen) > outlen) {
		errno = EINVAL;
		goto out;
	}
	ret = crypto->ops->encrypt(crypto, inbuf, inlen, outbuf, outlen);
	if (ret == -1) {
		goto out;
	}

	/* If non-AE cipher (but using AE), HMAC using the EtM scheme. */
	if (!crypto->ae_cipher) {
		if (crypto->ops->hmac(crypto, outbuf, ret,
		    crypto->aad, crypto->aad_len, crypto->tag) != tlen) {
			ret = -1;
			goto out;
		}
	}
out:
	crypto->aad = NULL;
	crypto->aad_len = 0;
	return ret;
}

/*
 * crypto_decrypt: decrypt the data given in the input buffer.
 *
 * => Output buffer size must be be at least crypto_get_buflen(inlen).
 * => Returns the number of bytes written or -1 on failure.
 * => Note: return value represents the original data length.
 */
ssize_t
crypto_decrypt(crypto_t *crypto, const void *inbuf, size_t inlen,
    void *outbuf, size_t outlen)
{
	const ssize_t tlen = crypto->tlen;
	ssize_t ret = -1;

	if (!crypto_setup_done_p(crypto)) {
		errno = EINVAL;
		goto out;
	}
	if (inlen > INT_MAX || roundup(inlen, crypto->blen) > outlen) {
		errno = EINVAL;
		goto out;
	}

	/* If non-AE cipher (but using AE), verify the HMAC. */
	if (!crypto->ae_cipher) {
		unsigned char hmac_buf[HMAC_MAX_BUFLEN];

		if (crypto->ops->hmac(crypto, inbuf, inlen,
		    crypto->aad, crypto->aad_len, hmac_buf) != tlen) {
			goto out;
		}
		if (memcmp(crypto->tag, hmac_buf, tlen) != 0) {
			goto out;
		}
	}
	ret = crypto->ops->decrypt(crypto, inbuf, inlen, outbuf, outlen);
out:
	crypto->aad = NULL;
	crypto->aad_len = 0;
	return ret;
}

/*
 * crypto_hmac: perform HMAC using the authentication key.
 *
 * => Returns the number of bytes produced or -1 on error.
 */
ssize_t
crypto_hmac(const crypto_t *crypto, const void *data, size_t dlen,
    unsigned char buf[static HMAC_MAX_BUFLEN])
{
	if (!crypto->auth_key_set) {
		errno = EINVAL;
		return -1;
	}
	if (dlen > INT_MAX) {
		errno = EFBIG;
		return -1;
	}
	return crypto->ops->hmac(crypto, data, dlen, NULL, 0, buf);
}

ssize_t
crypto_hmac_len(const crypto_hmac_t hmac_id)
{
	switch (hmac_id) {
	case HMAC_SHA256:
	case HMAC_SHA3_256:
		return 32;
	default:
		break;
	}
	errno = EINVAL;
	return -1;
}

void
crypto_destroy(crypto_t *crypto)
{
	if (crypto->ops->destroy) {
		crypto->ops->destroy(crypto);
	}
	if (crypto->key) {
		crypto_memzero(crypto->key, crypto->klen);
		free(crypto->key);
	}
	if (crypto->auth_key) {
		crypto_memzero(crypto->auth_key, crypto->alen);
		free(crypto->auth_key);
	}
	if (crypto->tag) {
		free(crypto->tag);
	}
	if (crypto->iv) {
		free(crypto->iv);
	}
	free(crypto);
}
