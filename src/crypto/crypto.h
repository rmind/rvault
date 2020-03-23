/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_CRYPTO_H_
#define	_CRYPTO_H_

#include <stdint.h>
#include <stdbool.h>

/*
 * WARNING: the constants below are used in the on-disk format.
 *
 * KEEP BACKWARDS COMPATIBILITY!
 */

typedef enum {
	CIPHER_NONE		= 0,
	AES_256_CBC		= 1,
	AES_256_GCM		= 2,
	CIPHER_RESERVED0	= 3,
	CHACHA20_POLY1305	= 4,
} crypto_cipher_t;

#define	CRYPTO_CIPHER_PRIMARY	AES_256_GCM
#define	CRYPTO_CIPHER_SECONDARY	CHACHA20_POLY1305

typedef enum {
	HMAC_NONE		= 0,
	HMAC_SHA256		= 1,
	HMAC_SHA3_256		= 2,
} crypto_hmac_t;

#define	CRYPTO_HMAC_PRIMARY	HMAC_SHA256

#define	HMAC_MAX_BUFLEN		64

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

const char **	crypto_cipher_list(unsigned *);
crypto_cipher_t	crypto_cipher_id(const char *);
crypto_hmac_t	crypto_hmac_id(const char *);

crypto_t *	crypto_create(crypto_cipher_t, crypto_hmac_t);
void		crypto_destroy(crypto_t *);
bool		crypto_cipher_ae_p(const crypto_t *);

void *		crypto_gen_iv(crypto_t *, size_t *);
int		crypto_set_iv(crypto_t *, const void *, size_t);

int		crypto_set_passphrasekey(crypto_t *, const char *,
		    const void *, size_t);
int		crypto_set_key(crypto_t *, const void *, size_t);
const void *	crypto_get_key(const crypto_t *, size_t *);
ssize_t		crypto_get_keylen(const crypto_t *);
int		crypto_set_authkey(crypto_t *, const void *, size_t);
const void *	crypto_get_authkey(const crypto_t *, size_t *);
ssize_t		crypto_get_authkeylen(const crypto_t *);

int		crypto_set_aetag(crypto_t *, const void *, size_t);
size_t		crypto_get_aetaglen(const crypto_t *);
const void *	crypto_get_aetag(crypto_t *, size_t *);
int		crypto_set_aad(crypto_t *, const void *, size_t);

size_t		crypto_get_buflen(const crypto_t *, size_t);

ssize_t		crypto_encrypt(crypto_t *, const void *, size_t,
		    void *, size_t);
ssize_t		crypto_decrypt(crypto_t *, const void *, size_t,
		    void *, size_t);

/*
 * HMAC API.
 */

ssize_t		crypto_hmac(const crypto_t *, const void *, size_t,
		    unsigned char [static HMAC_MAX_BUFLEN]);
ssize_t		crypto_hmac_len(const crypto_hmac_t);

#endif
