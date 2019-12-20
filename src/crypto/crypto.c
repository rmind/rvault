/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#define	__CRYPTO_PRIVATE
#include "crypto.h"
#include "utils.h"

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
 * Available ciphers for symmetric encryption.
 */
static const struct {
	const char *		name;
	crypto_cipher_t		id;
} cipher_str2id[] = {
	{ "aes-256-cbc",	AES_256_CBC		},
	{ "aes-256-gcm",	AES_256_GCM		},
	{ "chacha20",		CHACHA20		},
	{ "chacha20-poly1305",	CHACHA20_POLY1305	},
	{ NULL,			CIPHER_NONE		},
};

static const char *		cipher_list[__arraycount(cipher_str2id)];
static unsigned			cipher_count = 0;

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
	if (!cipher_count) {
		while (cipher_str2id[cipher_count].name) {
			cipher_list[cipher_count] =
			    cipher_str2id[cipher_count].name;
			cipher_count++;
		}
	}
	*nitems = cipher_count;
	return cipher_list;
}

/*
 * crypto_cipher_id: get the cipher type from name.
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
 * crypto_create: construct a new crypto object.
 */
crypto_t *
crypto_create(crypto_cipher_t c)
{
	crypto_t *crypto;

	if ((crypto = calloc(1, sizeof(crypto_t))) == NULL) {
		return NULL;
	}
	crypto->cipher = c;
	if ((crypto->ops = crypto_engines[0].ops) == NULL) { // FIXME
		goto err;
	}
	if (crypto->ops->create(crypto) == -1) {
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
		return -1;
	}
	if ((crypto->iv = malloc(crypto->ilen)) == NULL) {
		return -1;
	}
	memcpy(crypto->iv, iv, crypto->ilen);
	return 0;
}

/*
 * crypto_set_passphrasekey: generate the key from the given passphrase.
 */
int
crypto_set_passphrasekey(crypto_t *crypto, const char *passphrase,
    const void *kp, size_t kp_len)
{
	int ret;

	if ((crypto->key = malloc(crypto->klen)) == NULL) {
		return -1;
	}
	ret = kdf_passphrase_genkey(passphrase, kp, kp_len,
	    crypto->key, crypto->klen);
	if (ret == -1) {
		crypto_memzero(crypto->key, crypto->klen);
		free(crypto->key);
		crypto->key = NULL;
		return -1;
	}
	return 0;
}

/*
 * crypto_set_key: copy and assign the key.
 */
int
crypto_set_key(crypto_t *crypto, const void *key, size_t len)
{
	void *nkey;

	if (crypto->klen != len) {
		return -1;
	}
	if ((nkey = malloc(crypto->klen)) == NULL) {
		return -1;
	}
	if (crypto->key) {
		/* Allow resetting the key. */
		crypto_memzero(crypto->key, crypto->klen);
		free(crypto->key);
	}
	memcpy(nkey, key, crypto->klen);
	crypto->key = nkey;
	return 0;
}

const void *
crypto_get_key(const crypto_t *crypto, size_t *key_len)
{
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
 * crypto_using_ae: indicate the cipher uses authenticated encryption (AE).
 */
bool
crypto_using_ae(const crypto_t *crypto)
{
	return crypto->tlen != 0;
}

/*
 * crypto_set_tag: set the authentication tag; applicable for the ciphers
 * which support AE, e.g. AES in GCM mode or Chacha20 with Poly1305.
 */
int
crypto_set_tag(crypto_t *crypto, const void *tag, size_t len)
{
	if (crypto->tlen != len) {
		return -1;
	}
	if (!crypto->tag && (crypto->tag = malloc(crypto->tlen)) == NULL) {
		return -1;
	}
	memcpy(crypto->tag, tag, crypto->tlen);
	return 0;
}

const void *
crypto_get_tag(crypto_t *crypto, size_t *tag_len)
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

/*
 * crypto_encrypt: encrypt the data given in the input buffer.
 *
 * => Output buffer size must be be at least crypto_get_buflen(inlen).
 * => Returns the number of bytes written or -1 on failure.
 * => Note: the number of bytes written may be greater than the original
 *    length of data (e.g. due to padding).
 */
ssize_t
crypto_encrypt(const crypto_t *crypto, const void *inbuf, size_t inlen,
    void *outbuf, size_t outlen)
{
	if (crypto->key == NULL || crypto->iv == NULL) {
		errno = EINVAL;
		return -1;
	}
	return crypto->ops->encrypt(crypto, inbuf, inlen, outbuf, outlen);
}

/*
 * crypto_decrypt: decrypt the data given in the input buffer.
 *
 * => Output buffer size must be be at least crypto_get_buflen(inlen).
 * => Returns the number of bytes written or -1 on failure.
 * => Note: return value represents the original data length.
 */
ssize_t
crypto_decrypt(const crypto_t *crypto, const void *inbuf, size_t inlen,
    void *outbuf, size_t outlen)
{
	if (crypto->key == NULL || crypto->iv == NULL) {
		errno = EINVAL;
		return -1;
	}
	return crypto->ops->decrypt(crypto, inbuf, inlen, outbuf, outlen);
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
	if (crypto->iv) {
		free(crypto->iv);
	}
	if (crypto->tag) {
		free(crypto->tag);
	}
	free(crypto);
}
