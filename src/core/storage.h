/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_STORAGE_H_
#define	_STORAGE_H_

#include "utils.h"

/*
 * rvault storage ABI.
 */

#define	RVAULT_ABI_VER		3
#define	RVAULT_META_FILE	"rvault.metadata"
#define	RVAULT_SDB_FILE		"rvault.sdb"

#define	RVAULT_FOBJ_PREF	"RV:"
#define	RVAULT_FOBJ_PREFLEN	(sizeof(RVAULT_FOBJ_PREF) - 1)

/*
 * A few helper routines.
 */
#define	STORAGE_ALIGNMENT	UINT64_C(8)
#define	STORAGE_ALIGN(x)	roundup2((size_t)(x), STORAGE_ALIGNMENT)
#define	STORAGE_PTROFF(p, off)	((void *)((uintptr_t)(p) + (uintptr_t)(off)))

/*
 * Vault information/metadata structure.  On-disk layout:
 *
 *	+------------------+
 *	| header           |
 *	| [padding]        |
 *	+------------------+
 *	| IV 0             |
 *	+------------------+
 *	| IV 1 [optional]  |
 *	+------------------+
 *	| KDF params (KP)  |
 *	+------------------+
 *	| HMAC             |
 *	+------------------+
 *	| [padding]        |
 *	+------------------+
 *
 * CAUTION: All values must be converted to big-endian for storage.
 */

#define	RVAULT_FLAG_NOAUTH	(1U << 0)	// authentication disabled

typedef struct {
	uint8_t		ver;
	uint8_t		flags;

	uint8_t		cipher0;
	uint8_t		cipher1;
	uint8_t		hmac_id;
	uint8_t		reserved;

	uint8_t		iv0_len;
	uint8_t		iv1_len;
	uint8_t		kp_len;
	uint8_t		hmac_len;

	uint8_t		uid[16];
} __attribute__((packed)) rvault_hdr_t;

#define	RVAULT_HDR_LEN		STORAGE_ALIGN(sizeof(rvault_hdr_t))

#define	RVAULT_HDR_TO_IV0(h)	(STORAGE_PTROFF((h), RVAULT_HDR_LEN))

#define	RVAULT_HDR_TO_KP(h)	\
    ((void *)((uintptr_t)(RVAULT_HDR_TO_IV0(h)) + (h)->iv0_len + (h)->iv1_len))

#define	RVAULT_HDR_TO_HMAC(h)	\
    ((void *)((uintptr_t)(RVAULT_HDR_TO_KP(h)) + (h)->kp_len))

#define	RVAULT_HMAC_DATALEN(h)	\
    (RVAULT_HDR_LEN + (h)->iv0_len + (h)->iv1_len + (h)->kp_len)

#define	RVAULT_FILE_LEN(h)	(RVAULT_HMAC_DATALEN(h) + (h)->hmac_len)

/*
 * Encrypted file object.  On-disk layout:
 *
 *	+-----------------------+
 *	| header		|
 *	| [padding]		|
 *	+-----------------------+
 *	| AE TAG or HMAC	|
 *	| [padding]		|
 *	+-----------------------+
 *	| encrypted binary data	|
 *	| [padding]		|
 *	+-----------------------+
 *
 * CAUTION: All values must be converted to big-endian for storage.
 */

typedef struct {
	uint8_t		ver;
	uint8_t		flags;
	uint8_t		aetag_len;
	uint8_t		edata_pad;
	uint64_t	data_len;
	uint64_t	cdata_len;
	uint64_t	mtime;
} __attribute__((packed)) fileobj_hdr_t;

#define	FILEOBJ_HDR_LEN		STORAGE_ALIGN(sizeof(fileobj_hdr_t))
#define	FILEOBJ_AETAG_LEN(h)	((h)->aetag_len)
#define	FILEOBJ_DATA_LEN(h)	(be64toh((h)->data_len))
#define	FILEOBJ_EDATA_LEN(h)	(FILEOBJ_DATA_LEN(h) + (h)->edata_pad)
#define	FILEOBJ_GETMETA_LEN(t)	(FILEOBJ_HDR_LEN + STORAGE_ALIGN(t))

#define	FILEOBJ_HDR_TO_AETAG(h)	STORAGE_PTROFF((h), FILEOBJ_HDR_LEN)

#define	FILEOBJ_HDR_TO_DATA(h)	\
    STORAGE_PTROFF((h), FILEOBJ_GETMETA_LEN(FILEOBJ_AETAG_LEN(h)))

#define	FILEOBJ_FILE_LEN(h)	\
    (FILEOBJ_GETMETA_LEN(FILEOBJ_AETAG_LEN(h)) + FILEOBJ_EDATA_LEN(h))

/*
 * "Safe-buffer" API.
 */

typedef struct {
	void *	buf;		// buffer address
	size_t	buf_size;	// buffer (allocation) size
} sbuffer_t;

void *	sbuffer_alloc(sbuffer_t *, size_t);
void *	sbuffer_move(sbuffer_t *, size_t);
void	sbuffer_free(sbuffer_t *);

/*
 * Storage API.
 */

ssize_t	storage_write_data(rvault_t *, int, const void *, size_t);
ssize_t	storage_read_data(rvault_t *, int, size_t, sbuffer_t *);
ssize_t	storage_read_length(rvault_t *, int);

#endif
