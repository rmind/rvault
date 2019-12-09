/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <limits.h>
#include <errno.h>

#ifdef LIBSCRYPT_KDF
#include <scrypt-kdf.h>
#else
#include <libscrypt.h>
#define	scrypt_kdf	libscrypt_scrypt
#endif

#include "crypto.h"
#include "sys.h"
#include "utils.h"

#define	KDF_MIN_MS		50	// 50 milliseconds
#define	KDF_VERIFY_N		10

/*
 * Key derivation function (KDF).
 *
 * WARNING: used in the on-disk format; keep backwards compatibility.
 */
enum {
	KDF_NONE	= 0,
	KDF_SCRYPT	= 1,
};

#define	KDF_SALT_LEN		16	// 128-bit salt

/*
 * KDF parameters for on-disk storage.
 */
typedef struct {
	uint8_t		kdf;
	uint8_t		_pad[3];

	/*
	 * KDF_SCRYPT parameters.
	 */
	uint64_t	n;
	uint8_t		salt[KDF_SALT_LEN];

} __attribute__((packed)) kdf_params_t;

#define	SCRYPT_N_BITS		(sizeof(uint64_t) * CHAR_BIT)
#define SCRYPT_N_MIN_SHIFT	14	// cost parameter: 2^14 as a minimum
#define SCRYPT_N_DEFAULT	(UINT64_C(1) << SCRYPT_N_MIN_SHIFT);
#define	KDF_SCRYPT_r		8	// block size
#define	KDF_SCRYPT_p		16	// parallelization parameter

static int64_t
measure_kdf(const uint64_t n)
{
	const uint8_t passphrase[] = "calibration";
	const uint8_t salt[] = "salt";
	struct timespec tv1, tv2;
	uint8_t buf[32];

	clock_gettime(CLOCK_MONOTONIC, &tv1);
	if (scrypt_kdf(passphrase, sizeof(passphrase), salt, sizeof(salt),
	    n, KDF_SCRYPT_r, KDF_SCRYPT_p, buf, sizeof(buf)) == -1) {
		return -1;
	}
	clock_gettime(CLOCK_MONOTONIC, &tv2);

	return ((int64_t)(tv2.tv_sec - tv1.tv_sec) * 1000) +
	    ((int64_t)(tv2.tv_nsec - tv1.tv_nsec) / 1000000);
}

/*
 * kdf_calibrate: find the N value which satisfies the minimum CPU-time
 * computation requirement.
 */
static uint64_t
kdf_calibrate(void)
{
	unsigned retry = 3;

	while (retry--) {
		int64_t ms, sum = 0;
		uint64_t n;

		/*
		 * Measure and find the N value crossing the time requirement.
		 */
		for (unsigned i = SCRYPT_N_MIN_SHIFT; i < SCRYPT_N_BITS; i++) {
			n = UINT64_C(1) << i;
			ms = measure_kdf(n);
			if (ms > KDF_MIN_MS) {
				break;
			}
		}

		/*
		 * Basic verification that it wasn't just a fluctuation.
		 */
		for (unsigned i = 0; i < KDF_VERIFY_N; i++) {
			sum += measure_kdf(n); // sum to count the mean
		}
		if ((sum / KDF_VERIFY_N) > KDF_MIN_MS) {
			/* Success: return the N value. */
			return n;
		}
	}
	return SCRYPT_N_DEFAULT;
}

/*
 * kdf_create_params: create and return the KDF parameters.
 */
void *
kdf_create_params(size_t *len)
{
	kdf_params_t *kp;
	uint64_t n;

	n = kdf_calibrate();
	if ((kp = calloc(1, sizeof(kdf_params_t))) == NULL) {
		return NULL;
	}
	kp->kdf = KDF_SCRYPT;
	kp->n = htobe64(n);
	if (crypto_getrandbytes(kp->salt, KDF_SALT_LEN) == -1) {
		free(kp);
		return NULL;
	}
	*len = sizeof(kdf_params_t);
	return kp;
}

/*
 * kdf_passphrase_genkey: generate cryptographic key for a passphrase.
 *
 * - Alogrithm: scrypt KDF.
 * - PBKDF2 is dated; perhaps support Argon2 as an alternative.
 *
 * => Return 0 on success and -1 on failure.
 */
int
kdf_passphrase_genkey(const char *passphrase, const void *kpbuf, size_t kplen,
    void *buf, size_t buflen)
{
	const size_t len = strlen(passphrase);
	const unsigned char *salt;
	uint64_t n;

	if (kpbuf) {
		const kdf_params_t *kp = kpbuf;

		if (kplen < sizeof(kdf_params_t)) {
			return -1;
		}
		if (kp->kdf != KDF_SCRYPT) {
			return -1;
		}
		n = be64toh(kp->n);
		salt = kp->salt;
	} else {
		static unsigned char zero_salt[KDF_SALT_LEN]; // zeroed
		n = SCRYPT_N_DEFAULT;
		salt = zero_salt;
	}

	return scrypt_kdf((const void *)passphrase, len, salt, KDF_SALT_LEN,
	    n, KDF_SCRYPT_r, KDF_SCRYPT_p, buf, buflen);
}
