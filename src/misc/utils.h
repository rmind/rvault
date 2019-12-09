/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_UTILS_H_
#define	_UTILS_H_

#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <assert.h>

/*
 * A regular assert (debug/diagnostic only).
 */

#if defined(DEBUG)
#define	ASSERT		assert
#else
#define	ASSERT(x)
#endif

/*
 * Branch prediction macros.
 */

#ifndef __predict_true
#define	__predict_true(x)	__builtin_expect((x) != 0, 1)
#define	__predict_false(x)	__builtin_expect((x) != 0, 0)
#endif

/*
 * Various C helpers and attribute macros.
 */

#ifndef __constructor
#define	__constructor		__attribute__((constructor))
#endif

#ifndef __packed
#define	__packed		__attribute__((__packed__))
#endif

#ifndef __aligned
#define	__aligned(x)		__attribute__((__aligned__(x)))
#endif

#ifndef __unused
#define	__unused		__attribute__((__unused__))
#endif

#ifndef __arraycount
#define	__arraycount(__x)	(sizeof(__x) / sizeof(__x[0]))
#endif

#ifndef __noinline
#define	__noinline		__attribute__((__noinline__))
#endif

#ifndef __always_inline
#define	__always_inline		__attribute__((__always_inline__))
#endif

#ifndef __UNCONST
#define	__UNCONST(a)		((void *)(unsigned long)(const void *)(a))
#endif

/*
 * Minimum, maximum and rounding macros.
 */

#ifndef MIN
#define	MIN(x, y)	((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#define	MAX(x, y)	((x) > (y) ? (x) : (y))
#endif

#ifndef roundup
#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))
#endif

#ifndef rounddown
#define	rounddown(x,y)	(((x)/(y))*(y))
#endif

#ifndef roundup2
#define	roundup2(x,m)	((((x) - 1) | ((m) - 1)) + 1)
#endif

/*
 * Find first/last bit and ilog2().
 */

#ifdef __linux__
#ifndef fls
static inline int
fls(int x)
{
	return x ? (sizeof(int) * CHAR_BIT) - __builtin_clz(x) : 0;
}
#endif
#ifndef flsl
static inline int
flsl(long x)
{
	return x ? (sizeof(long) * CHAR_BIT) - __builtin_clzl(x) : 0;
}
#endif
#endif

#ifndef ilog2
#define	ilog2(x)	(flsl(x) - 1)
#endif

/*
 * Byte-order conversions.
 */
#if defined(__linux__) || defined(sun)
#include <endian.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#include <arpa/inet.h>
#define	be16toh(x)	ntohs(x)
#define	be32toh(x)	ntohl(x)
#define	htobe16(x)	htons(x)
#define	htobe32(x)	htonl(x)
#define	be64toh(x)	OSSwapBigToHostInt64(x)
#define	htobe64(x)	OSSwapHostToBigInt64(x)
#else
#include <sys/endian.h>
#endif

#ifndef static_assert
#define	static_assert(x, ...)
#endif

#if defined(__APPLE__) && !defined(clock_gettime)

/*
 * clock_gettime() support for older OS X versions.
 */

#include <mach/clock.h>
#include <mach/mach.h>
#include <time.h>

static inline int
darwin_clock_gettime(struct timespec *tv)
{
	clock_serv_t clocksvc;
	mach_timespec_t mts;

	host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &clocksvc);
	clock_get_time(clocksvc, &mts);
	mach_port_deallocate(mach_task_self(), clocksvc);

	tv->tv_sec = mts.tv_sec;
	tv->tv_nsec = mts.tv_nsec;
	return 0;
}

#define	clock_gettime(c,t)	darwin_clock_gettime(t)
#endif

#endif
