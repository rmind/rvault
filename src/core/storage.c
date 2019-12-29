/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>

#include "rvault.h"
#include "storage.h"
#include "fileobj.h"
#include "crypto.h"
#include "sys.h"
#include "utils.h"

/*
 * "Secure" buffer API.  Takes extra care to erase the data on destruction.
 */

void *
sbuffer_alloc(size_t len)
{
	return safe_mmap(len, -1, MMAP_WRITEABLE);
}

void *
sbuffer_move(void *buf, size_t len, size_t newlen)
{
	void *nbuf = NULL;

	if (newlen && (nbuf = sbuffer_alloc(newlen)) == NULL) {
		return NULL;
	}
	if (buf) {
		ASSERT(len > 0);
		if (nbuf) {
			ASSERT(newlen > 0);
			memcpy(nbuf, buf, MIN(len, newlen));
		} else {
			ASSERT(newlen == 0);
		}
		sbuffer_free(buf, len);
	} else {
		ASSERT(len == 0);
	}
	return nbuf;
}

void
sbuffer_free(void *buf, size_t len)
{
	safe_munmap(buf, len, MMAP_ERASE);
}

/*
 * HMAC computation and verification for file objects.
 */

static int
storage_hmac_compute(rvault_t *vault, const void *buf, size_t len,
    uint8_t hmac[static HMAC_SHA3_256_BUFLEN])
{
	const void *key;
	size_t key_len;

	key = crypto_get_key(vault->crypto, &key_len);
	ASSERT(key != NULL);

	return hmac_sha3_256(key, key_len, buf, len, hmac) == -1 ? -1 : 0;
}

static int
storage_hmac_verify(rvault_t *vault, const void *buf, size_t len,
    const fileobj_hdr_t *hdr)
{
	const void *hmac_onfile = FILEOBJ_HDR_TO_AETAG(hdr);
	uint8_t hmac[HMAC_SHA3_256_BUFLEN];

	if (FILEOBJ_AETAG_LEN(hdr) != HMAC_SHA3_256_BUFLEN) {
		return -1;
	}
	if (storage_hmac_compute(vault, buf, len, hmac) == -1) {
		return -1;
	}
	return memcmp(hmac_onfile, hmac, HMAC_SHA3_256_BUFLEN) ? -1 : 0;
}

/*
 * storage_write_data: encrypt the given buffer and write to the file.
 *
 * => Constructs metadata and stores together with encrypted data.
 * => Computes the HMAC on the metadata and the pre-encrypted data.
 * => Returns the total number of bytes written to the file.
 */
int
storage_write_data(rvault_t *vault, int fd, const void *buf, size_t len)
{
	fileobj_hdr_t *hdr;
	size_t max_buf_len, file_len, tag_len, enc_len;
	uint8_t hmac[HMAC_SHA3_256_BUFLEN];
	const void *tag;
	void *enc_buf;
	ssize_t nbytes;

	/*
	 * Allocate memory for the full sync.  Ensure the header area,
	 * including the padding, is fully zeroed for a stable HMAC/tag.
	 */
	enc_len = crypto_get_buflen(vault->crypto, len);
	max_buf_len = FILEOBJ_HDR_LEN + enc_len;
	tag_len = crypto_get_taglen(vault->crypto);
	max_buf_len += MAX(HMAC_SHA3_256_BUFLEN, tag_len);
	if ((hdr = malloc(max_buf_len)) == NULL) {
		app_log(LOG_ERR, "buffer allocation failed");
		return -1;
	}
	memset(hdr, 0, FILEOBJ_HDR_LEN);

	/*
	 * Encrypt the file.
	 */
	enc_buf = FILEOBJ_HDR_TO_DATA(hdr);
	nbytes = crypto_encrypt(vault->crypto, buf, len, enc_buf, enc_len);
	if (nbytes == -1) {
		app_log(LOG_ERR, "encryption failed");
		goto err;
	}

	/*
	 * Setup the header.
	 */
	hdr->ver = RVAULT_ABI_VER;
	hdr->cipher = vault->cipher;
	hdr->aetag_len = -1; // to be set
	hdr->edata_len = htobe64(nbytes);
	hdr->edata_pad = (size_t)nbytes - len;
	ASSERT(hdr->edata_pad < UINT8_MAX);

	/*
	 * Compute the AE tag or HMAC and a adjust the file length.
	 */
	if ((tag = crypto_get_tag(vault->crypto, &tag_len)) == NULL) {
		if (storage_hmac_compute(vault, buf, len, hmac) == -1) {
			nbytes = -1;
			goto err;
		}
		tag_len = HMAC_SHA3_256_BUFLEN;
		tag = hmac;
	}
	memcpy(FILEOBJ_HDR_TO_AETAG(hdr), tag, tag_len);
	file_len = FILEOBJ_HDR_LEN + nbytes + tag_len;
	hdr->aetag_len = tag_len;

	/*
	 * Write the file to the disk.
	 */
	if (lseek(fd, 0, SEEK_SET) == -1 || ftruncate(fd, 0) == -1) {
		nbytes = -1;
		goto err;
	}
	if (fs_write(fd, hdr, file_len) != (ssize_t)file_len) {
		nbytes = -1;
		goto err;
	}
	fs_sync(fd, NULL);
	nbytes = file_len;
err:
	free(hdr);
	return nbytes;
}

/*
 * storage_read_data: decrypt the data in the file and return a buffer.
 *
 * => Returns a buffer with decrypted data and its length in 'lenp'.
 * => Verifies the data using HMAC.
 */
void *
storage_read_data(rvault_t *vault, int fd, size_t file_len, size_t *lenp)
{
	fileobj_hdr_t *hdr;
	const void *enc_buf;
	void *buf = NULL;
	size_t buf_len;
	ssize_t nbytes;
	bool use_ae;

	/*
	 * Memory-map the data file.  Perform some integrity checks,
	 * including the length verifications.
	 */
	if (file_len < FILEOBJ_HDR_LEN) {
		app_log(LOG_ERR, "data file corrupted");
		errno = EIO;
		return NULL;
	}
	hdr = safe_mmap(file_len, fd, 0);
	if (hdr == NULL) {
		return NULL;
	}
	buf_len = FILEOBJ_EDATA_LEN(hdr);
	if (file_len < FILEOBJ_FILE_LEN(hdr) || buf_len > file_len) {
		app_log(LOG_ERR, "data file corrupted");
		errno = EIO;
		goto out;
	}
	if (buf_len == 0) {
		buf = NULL;
		*lenp = 0;
		goto out;
	}

	/*
	 * Obtain and set the AE tag.
	 */
	use_ae = crypto_get_taglen(vault->crypto) != 0;
	if (use_ae && crypto_set_tag(vault->crypto,
	    FILEOBJ_HDR_TO_AETAG(hdr), FILEOBJ_AETAG_LEN(hdr)) == -1) {
		app_log(LOG_ERR, "failed to obtain the AE tag");
		goto out;
	}

	/*
	 * Allocate a buffer and decrypt the data into it.
	 */
	if ((buf = sbuffer_alloc(buf_len)) == NULL) {
		app_log(LOG_ERR, "buffer allocation failed");
		goto out;
	}
	enc_buf = FILEOBJ_HDR_TO_DATA(hdr);
	nbytes = crypto_decrypt(vault->crypto, enc_buf, buf_len, buf, buf_len);
	if (nbytes == -1 || FILEOBJ_DATA_LEN(hdr) != (size_t)nbytes) {
		app_log(LOG_ERR, "decryption failed");
		sbuffer_free(buf, buf_len);
		buf = NULL;
		goto out;
	}

	/*
	 * Verify the HMAC.  Note: it is safe to use the lengths here.
	 */
	if (!use_ae && storage_hmac_verify(vault, buf, nbytes, hdr) == -1) {
		app_log(LOG_ERR, "HMAC verification failed");
		sbuffer_free(buf, buf_len);
		buf = NULL;
		goto out;
	}
	*lenp = nbytes;
out:
	safe_munmap(hdr, file_len, 0);
	return buf;
}

ssize_t
storage_read_length(rvault_t *vault __unused, int fd)
{
	unsigned char buf[FILEOBJ_HDR_LEN];
	fileobj_hdr_t *hdr = (void *)buf;

	if (fs_read(fd, hdr, FILEOBJ_HDR_LEN) != FILEOBJ_HDR_LEN) {
		app_log(LOG_ERR, "data file corrupted");
		errno = EIO;
		return -1;
	}
	return FILEOBJ_DATA_LEN(hdr);
}
