/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_STORAGE_H_
#define	_STORAGE_H_

#include "utils.h"

#define	STORAGE_ALIGNMENT	UINT64_C(8)
#define	STORAGE_ALIGN(x)	roundup2((size_t)(x), STORAGE_ALIGNMENT)

/*
 * Vault information/metadata structure.  On-disk layout:
 *
 *	+-----------------------+
 *	| header		|
 *	| [padding]		|
 *	+-----------------------+
 *	| initialization vector |
 *	+-----------------------+
 *	| KDF parameters        |
 *	+-----------------------+
 *	| HMAC			|
 *	+-----------------------+
 */

#define	RVAULT_FL_AUTH	(1U << 0)	// authentication enabled

typedef struct {
	uint8_t		ver;
	uint8_t		cipher;
	uint8_t		flags;
	uint8_t		kp_len;
	uint16_t	iv_len;
} __attribute__((packed)) rvault_hdr_t;

#define	RVAULT_HDR_LEN		STORAGE_ALIGN(sizeof(rvault_hdr_t))

#define	RVAULT_HDR_TO_IV(h)	((void *)((uintptr_t)(h) + RVAULT_HDR_LEN))

#define	RVAULT_HDR_TO_KP(h)	\
    ((void *)((uintptr_t)(RVAULT_HDR_TO_IV(h)) + be16toh((h)->iv_len)))

#define	RVAULT_HDR_TO_HMAC(h)	\
    ((void *)((uintptr_t)(RVAULT_HDR_TO_KP(h)) + (h)->kp_len))

#define	RVAULT_HMAC_DATALEN(h)	\
    (RVAULT_HDR_LEN + be16toh((h)->iv_len) + (h)->kp_len)

#define	RVAULT_FILE_LEN(h)	(RVAULT_HMAC_DATALEN(h) + HMAC_SHA3_256_BUFLEN)

/*
 * Encrypted file object.  On-disk layout:
 *
 *	+-----------------------+
 *	| header		|
 *	| [padding]		|
 *	+-----------------------+
 *	| encrypted binary data	|
 *	| [padding]		|
 *	+-----------------------+
 *	| AE TAG or HMAC	|
 *	+-----------------------+
 */

typedef struct {
	uint8_t		ver;
	uint8_t		cipher;
	uint8_t		aetag_len;
	uint8_t		edata_pad;
	uint64_t	edata_len;
} __attribute__((packed)) fileobj_hdr_t;

#define	FILEOBJ_HDR_LEN		STORAGE_ALIGN(sizeof(fileobj_hdr_t))

#define	FILEOBJ_HDR_TO_DATA(h)	((void *)((uintptr_t)(h) + FILEOBJ_HDR_LEN))

#define	FILEOBJ_HDR_TO_AETAG(h)	\
    ((void *)((uintptr_t)FILEOBJ_HDR_TO_DATA(h) + FILEOBJ_EDATA_LEN(h)))

#define	FILEOBJ_EDATA_LEN(h)	be64toh((h)->edata_len)

#define	FILEOBJ_AETAG_LEN(h)	((h)->aetag_len)

#define	FILEOBJ_HMAC_DATALEN(h)	(FILEOBJ_HDR_LEN + FILEOBJ_EDATA_LEN(h))

#define	FILEOBJ_DATA_LEN(h)	(FILEOBJ_EDATA_LEN(h) - (h)->edata_pad)

#define	FILEOBJ_FILE_LEN(h)	(FILEOBJ_HMAC_DATALEN(h) + (h)->aetag_len)

int	storage_write_data(rvault_t *, int, const void *, size_t);
void *	storage_read_data(rvault_t *, int, size_t, size_t *);
ssize_t	storage_read_length(rvault_t *, int);

void *	sbuffer_alloc(size_t);
void *	sbuffer_move(void *, size_t, size_t);
void	sbuffer_free(void *, size_t);

#endif
