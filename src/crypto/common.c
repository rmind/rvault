/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <errno.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

#include "crypto.h"
#include "sys.h"

/*
 * crypto_getrandbytes: get random bytes for cryptographic purposes.
 *
 * => Returns the number of bytes filled or -1 on failure.
 */
ssize_t
crypto_getrandbytes(void *buf, size_t len)
{
	ssize_t nbytes = -1;

#ifdef __linux__
	while ((nbytes = getrandom(buf, len, 0)) == -1) {
		if (errno == EINTR)
			continue;
	}
#else
	int fd;

	if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		return -1;
	}
	nbytes = fs_read(fd, buf, len);
	close(fd);
#endif
	return nbytes;
}


/*
 * crypto_memzero: explicit (secure) zeroing.
 */

void *(* volatile memset_funcptr)(void *, int, size_t) = memset;

void
crypto_memzero(void *buf, size_t len)
{
#if 0
	memset_s(buf, len, 0, len);
#else
	volatile void *bufv = (volatile void *)buf;
	(*memset_funcptr)((void *)(uintptr_t)bufv, 0, len);
#endif
}

/*
 * crypto_cipher_id: get the cipher type from name.
 */
crypto_cipher_t
crypto_cipher_id(const char *cipher)
{
	static const struct cipher_str2id_s {
		const char *	name;
		crypto_cipher_t	id;
	} cipher_str2id[] = {
		{ "aes-256-cbc",	AES_256_CBC		},
		{ "aes-256-gcm",	AES_256_GCM		},
		{ "chacha20",		CHACHA20		},
		{ "chacha20-poly1305",	CHACHA20_POLY1305	},
		{ NULL,			CIPHER_NONE		},
	};
	for (unsigned i = 0; cipher_str2id[i].name != NULL; i++) {
		if (strcasecmp(cipher, cipher_str2id[i].name) == 0) {
			return cipher_str2id[i].id;
		}
	}
	return CIPHER_NONE;
}

