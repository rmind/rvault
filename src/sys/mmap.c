/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <sys/mman.h>
#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>

#include "sys.h"
#include "crypto.h"

/* Linux/BSD compat. */
#ifndef MAP_ANON
#define	MAP_ANON	MAP_ANONYMOUS
#endif

/*
 * Linux-specific flags.
 */
#ifndef MADV_DONTFORK
#define	MADV_DONTFORK	0
#endif
#ifndef MADV_WIPEONFORK
#define	MADV_WIPEONFORK	0
#endif
#ifndef MADV_DONTDUMP
#define	MADV_DONTDUMP	0
#endif

/*
 * BSD minherit(2).
 */

#if defined(MAP_INHERIT_NONE)
// NetBSD
#elif defined(INHERIT_NONE)
// FreeBSD
#define	MAP_INHERIT_NONE	INHERIT_NONE
#elif defined(VM_INHERIT_NONE)
// Darwin
#define	MAP_INHERIT_NONE	VM_INHERIT_NONE
#endif

void *
safe_mmap(size_t len, int fd, mmap_flag_t flags)
{
	const unsigned map_type = (fd > 0) ? MAP_FILE : MAP_ANON;
	const bool writeable = (flags & MMAP_WRITEABLE) != 0;
	void *addr;

	addr = mmap(NULL, len, PROT_READ | (writeable ? PROT_WRITE : 0),
	    MAP_PRIVATE | map_type, fd, 0);
	if (addr == MAP_FAILED) {
		return NULL;
	}

	mprotect(addr, len, PROT_READ | (writeable ? PROT_WRITE : 0) |
	    MADV_DONTFORK | MADV_WIPEONFORK | MADV_DONTDUMP);
#ifdef MAP_INHERIT_NONE
	minherit(addr, len, MAP_INHERIT_NONE);
#endif
	return addr;
}

void
safe_munmap(void *addr, size_t len, mmap_flag_t flags)
{
	if (flags & MMAP_ERASE) {
		crypto_memzero(addr, len);
	}
	munmap(addr, len);
}
