/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_CRYPTO_H_
#define	_CRYPTO_H_

/*
 * WARNING: used in the on-disk format; keep backwards compatibility.
 */
typedef enum {
	CIPHER_NONE	= 0,
	AES_256_CBC,
	AES_256_GCM,
	CHACHA20,
	CHACHA20_POLY1305,
} crypto_cipher_t;

#ifdef __CRYPTO_PRIVATE
struct crypto {
	/* AES type. */
	crypto_cipher_t	cipher;

	/* Key, IV and block lengths. */
	size_t		klen;
	size_t		ilen;
	size_t		blen;

	/* Key and IV buffers. */
	void *		key;
	void *		iv;

	/* Arbitrary implementation-defined context. */
	void *		ctx;
};
#endif

typedef struct crypto crypto_t;

/*
 * Randomness and zeroing suitable for cryptographic purposes.
 */
ssize_t		crypto_getrandbytes(void *, size_t);
void		crypto_memzero(void *, size_t);

/*
 * Key derivation function (KDF) API.
 */
void *		kdf_create_params(size_t *);
int		kdf_passphrase_genkey(const char *, const void *, size_t,
		    void *, size_t);

/*
 * Symmetric encryption/decryption API.
 */
crypto_cipher_t	crypto_cipher_id(const char *);
crypto_t *	crypto_create(crypto_cipher_t);
void		crypto_destroy(crypto_t *);
void *		crypto_gen_iv(const crypto_cipher_t, size_t *);

int		crypto_set_passphrasekey(crypto_t *, const char *,
		    const void *, size_t);
int		crypto_set_key(crypto_t *, const void *, size_t);
int		crypto_set_iv(crypto_t *, const void *, size_t);

size_t		crypto_get_buflen(const crypto_t *, size_t);
const void *	crypto_get_key(const crypto_t *, size_t *);
ssize_t		crypto_get_keylen(const crypto_cipher_t);

ssize_t		crypto_encrypt(const crypto_t *, const void *, size_t,
		    void *, size_t);
ssize_t		crypto_decrypt(const crypto_t *, const void *, size_t,
		    void *, size_t);

/*
 * HMAC API.
 */

#define	HMAC_SHA3_256_BUFLEN	32

ssize_t		hmac_sha3_256(const void *, size_t, const void *, size_t,
		    void *, size_t);

#endif
