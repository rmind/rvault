/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_CRYPTO_H_
#define	_CRYPTO_H_

#include <stdbool.h>

/*
 * WARNING: used in the on-disk format; keep backwards compatibility.
 */
typedef enum {
	CIPHER_NONE		= 0,
	AES_256_CBC		= 1,
	AES_256_GCM		= 2,
	CHACHA20		= 3,
	CHACHA20_POLY1305	= 4,
} crypto_cipher_t;

#define	CRYPTO_CIPHER_PRIMARY	AES_256_CBC
#define	CRYPTO_CIPHER_SECONDARY	CHACHA20

typedef struct crypto crypto_t;

#ifdef __CRYPTO_PRIVATE

#define	CRYPTO_MAX_ENGINES	16

typedef struct crypto_ops {
	int		(*create)(struct crypto *);
	void		(*destroy)(struct crypto *);
	ssize_t		(*encrypt)(const crypto_t *, const void *,
			    size_t, void *, size_t);
	ssize_t		(*decrypt)(const crypto_t *, const void *,
			    size_t, void *, size_t);
} crypto_ops_t;

struct crypto {
	crypto_cipher_t	cipher;

	/* Key, IV, block and tag lengths. */
	size_t		klen;
	size_t		ilen;
	size_t		blen;
	size_t		tlen;

	/* Key, IV and tag buffers. */
	void *		key;
	void *		iv;
	void *		tag;

	/* Arbitrary implementation-defined context and operations. */
	void *		ctx;
	const crypto_ops_t *ops;
};

int		crypto_engine_register(const char *, const crypto_ops_t *);

#endif

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

const char **	crypto_cipher_list(unsigned *);
crypto_cipher_t	crypto_cipher_id(const char *);

crypto_t *	crypto_create(crypto_cipher_t);
void		crypto_destroy(crypto_t *);

void *		crypto_gen_iv(crypto_t *, size_t *);
int		crypto_set_iv(crypto_t *, const void *, size_t);

int		crypto_set_passphrasekey(crypto_t *, const char *,
		    const void *, size_t);
int		crypto_set_key(crypto_t *, const void *, size_t);
const void *	crypto_get_key(const crypto_t *, size_t *);
ssize_t		crypto_get_keylen(const crypto_t *);

size_t		crypto_get_taglen(const crypto_t *);
int		crypto_set_tag(crypto_t *, const void *, size_t);
const void *	crypto_get_tag(crypto_t *, size_t *);

size_t		crypto_get_buflen(const crypto_t *, size_t);

ssize_t		crypto_encrypt(const crypto_t *, const void *, size_t,
		    void *, size_t);
ssize_t		crypto_decrypt(const crypto_t *, const void *, size_t,
		    void *, size_t);

/*
 * HMAC API.
 */

#define	HMAC_SHA3_256_BUFLEN	32

ssize_t		hmac_sha3_256(const void *, size_t, const void *, size_t,
		    unsigned char [static HMAC_SHA3_256_BUFLEN]);

#endif
