/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_CRYPTO_IMPL_H_
#define	_CRYPTO_IMPL_H_

#if !defined(__CRYPTO_PRIVATE)
#error "only to be used by the crypto modules"
#endif

#include "crypto.h"

#define	CRYPTO_MAX_ENGINES	4

typedef struct crypto_ops {
	int		(*create)(struct crypto *);
	void		(*destroy)(struct crypto *);
	ssize_t		(*encrypt)(const crypto_t *, const void *,
			    size_t, void *, size_t);
	ssize_t		(*decrypt)(const crypto_t *, const void *,
			    size_t, void *, size_t);
	ssize_t		(*hmac)(const crypto_t *, const void *, size_t,
			    const void *, size_t,
			    unsigned char [static HMAC_MAX_BUFLEN]);
} crypto_ops_t;

struct crypto {
	crypto_cipher_t	cipher;
	unsigned	ae_cipher : 1,
			iv_set : 1,
			enc_key_set : 1,
			auth_key_set : 1;

	/* Key, IV and block lengths. */
	size_t		klen;
	size_t		ilen;
	size_t		blen;

	/* Key, IV and AE tag buffers. */
	void *		key;
	void *		iv;

	/*
	 * AEAD cipher or HMAC-based generic composition using the EtM
	 * scheme.  In the latter case, the HMAC is used for the AE with
	 * the authentication key.
	 */
	crypto_hmac_t	hmac_id;
	void *		auth_key;
	size_t		alen;

	/*
	 * The following is used for both AE solutions:
	 * - AE tag buffer and its length.
	 * - Additional authenticated data (AAD).
	 */
	void *		tag;
	size_t		tlen;
	const void *	aad;
	size_t		aad_len;

	/* Arbitrary implementation-defined context and operations. */
	void *		ctx;
	const crypto_ops_t *ops;
};

int	crypto_engine_register(const char *, const crypto_ops_t *);

#endif
