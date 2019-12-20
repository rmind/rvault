/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

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

static volatile unsigned char crypto_memzero_xor;

void
crypto_memzero(void *buf, size_t len)
{
	volatile unsigned char *bufp = (volatile void *)buf;

	for (size_t i = 0; i < len; i++) {
		crypto_memzero_xor ^= bufp[i];
		bufp[i] = 0;
	}
}
