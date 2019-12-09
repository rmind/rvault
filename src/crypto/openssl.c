/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * OpenSSL wrapper for the symmetric ciphers and HMAC.
 *
 * Note: by default, OpenSSL uses PKCS padding.
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
#if 0 // TODO: more work in encrypt/decrypt
	case AES_256_GCM:
		cipher = EVP_aes_256_gcm();
		break;
#endif
	case CHACHA20:
		cipher = EVP_chacha20();
		break;
	default:
		return NULL;
	}
	return cipher;
}

crypto_t *
crypto_create(crypto_cipher_t c)
{
	const EVP_CIPHER *cipher;
	crypto_t *cf;

	if ((cf = calloc(1, sizeof(crypto_t))) == NULL) {
		return NULL;
	}
	if ((cipher = get_openssl_cipher(c)) == NULL) {
		goto err;
	}
	cf->cipher = c;
	cf->ctx = (void *)(uintptr_t)cipher;
	cf->klen = EVP_CIPHER_key_length(cipher);
	cf->ilen = EVP_CIPHER_iv_length(cipher);
	cf->blen = EVP_CIPHER_block_size(cipher);
	return cf;
err:
	crypto_destroy(cf);
	return NULL;
}

/*
 * crypto_set_passphrasekey: generate the key from the given passphrase.
 */
int
crypto_set_passphrasekey(crypto_t *cf, const char *passphrase,
    const void *kp, size_t kp_len)
{
	int ret;

	if ((cf->key = malloc(cf->klen)) == NULL) {
		return -1;
	}
	ret = kdf_passphrase_genkey(passphrase, kp, kp_len, cf->key, cf->klen);
	if (ret == -1) {
		crypto_memzero(cf->key, cf->klen);
		free(cf->key);
		cf->key = NULL;
		return -1;
	}
	return 0;
}

/*
 * crypto_set_key: copy and assign the key.
 */
int
crypto_set_key(crypto_t *cf, const void *key, size_t len)
{
	if (cf->klen != len) {
		return -1;
	}
	if ((cf->key= malloc(cf->klen)) == NULL) {
		return -1;
	}
	memcpy(cf->key, key, cf->klen);
	return 0;
}

/*
 * crypto_set_iv: copy and assign the Initialization Vector (IV).
 */
int
crypto_set_iv(crypto_t *cf, const void *iv, size_t len)
{
	if (cf->ilen != len) {
		return -1;
	}
	if ((cf->iv = malloc(cf->ilen)) == NULL) {
		return -1;
	}
	memcpy(cf->iv, iv, cf->ilen);
	return 0;
}

void
crypto_destroy(crypto_t *cf)
{
	if (cf->key) {
		crypto_memzero(cf->key, cf->klen);
		free(cf->key);
	}
	if (cf->iv) {
		free(cf->iv);
	}
	free(cf);
}

/*
 * crypto_gen_iv: allocate and set the Initialization Vector (IV).
 */
void *
crypto_gen_iv(const crypto_cipher_t c, size_t *len)
{
	const EVP_CIPHER *cipher;
	size_t iv_len;
	void *iv;

	if ((cipher = get_openssl_cipher(c)) == NULL) {
		return NULL;
	}
	iv_len = EVP_CIPHER_iv_length(cipher);
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

ssize_t
crypto_get_keylen(const crypto_cipher_t c)
{
	const EVP_CIPHER *cipher;

	if ((cipher = get_openssl_cipher(c)) == NULL) {
		return -1;
	}
	return EVP_CIPHER_key_length(cipher);
}

const void *
crypto_get_key(const crypto_t *cf, size_t *key_len)
{
	*key_len = cf->klen;
	return cf->key;
}

size_t
crypto_get_buflen(const crypto_t *cf, size_t length)
{
	/*
	 * As per OpenSSL documentation:
	 * - Encryption: in_bytes + cipher_block_size - 1
	 * - Decryption: in_bytes + cipher_block_size
	 * Alternatively, can also just use EVP_MAX_BLOCK_LENGTH.
	 */
	return length + cf->blen;
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
crypto_encrypt(const crypto_t *cf, const void *inbuf, size_t inlen,
    void *outbuf, size_t outlen)
{
	const EVP_CIPHER *cipher = cf->ctx;
	EVP_CIPHER_CTX *ctx;
	unsigned char *bufp;
	ssize_t nbytes = -1;
	int len;

	if (cf->key == NULL || cf->iv == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* Note: OpenSSL APIs take signed int. */
	if (inlen > INT_MAX || roundup(inlen, cf->blen) > outlen) {
		return -1;
	}
	if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
		return -1;
	}
	if (EVP_EncryptInit_ex(ctx, cipher, NULL, cf->key, cf->iv) != 1) {
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
 * crypto_decrypt: decrypt the data given in the input buffer.
 *
 * => Output buffer size must be be at least crypto_get_buflen(inlen).
 * => Returns the number of bytes written or -1 on failure.
 * => Note: return value represents the original data length.
 */
ssize_t
crypto_decrypt(const crypto_t *cf, const void *inbuf, size_t inlen,
    void *outbuf, size_t outlen)
{
	const EVP_CIPHER *cipher = cf->ctx;
	EVP_CIPHER_CTX *ctx;
	unsigned char *bufp;
	ssize_t nbytes = -1;
	int len;

	if (cf->key == NULL || cf->iv == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* Note: OpenSSL APIs take signed int. */
	if (inlen > INT_MAX || roundup(inlen, cf->blen) > outlen) {
		return -1;
	}
	if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
		return -1;
	}
	if (EVP_DecryptInit_ex(ctx, cipher, NULL, cf->key, cf->iv) != 1) {
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

ssize_t
hmac_sha3_256(const void *key, size_t klen, const void *data, size_t dlen,
    void *buf, size_t buflen)
{
	const EVP_MD *h = EVP_sha3_256();
	unsigned nbytes;
	HMAC_CTX *ctx;

	if (buflen < (size_t)EVP_MD_size(h) || dlen > INT_MAX) {
		return -1;
	}
	if ((ctx = HMAC_CTX_new()) == NULL) {
		return -1;
	}
	HMAC_Init_ex(ctx, key, klen, EVP_sha3_256(), NULL);
	HMAC_Update(ctx, data, dlen);
	HMAC_Final(ctx, buf, &nbytes);
	HMAC_CTX_free(ctx);

	return (size_t)nbytes;
}
