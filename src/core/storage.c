/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
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
#include <time.h>
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
sbuffer_alloc(sbuffer_t *sbuf, size_t len)
{
	void *buf;

	buf = safe_mmap(len, -1, MMAP_WRITEABLE);
	if (!buf) {
		return NULL;
	}
	sbuf->buf = buf;
	sbuf->buf_size = len;
	return buf;
}

void *
sbuffer_move(sbuffer_t *sbuf, size_t newlen)
{
	void *nbuf = NULL;

	if (sbuf->buf_size == newlen) {
		return sbuf->buf;
	}
	if (newlen) {
		if ((nbuf = safe_mmap(newlen, -1, MMAP_WRITEABLE)) == NULL) {
			return NULL;
		}
	}
	if (sbuf->buf) {
		ASSERT(sbuf->buf_size > 0);
		if (nbuf) {
			ASSERT(newlen > 0);
			memcpy(nbuf, sbuf->buf, MIN(sbuf->buf_size, newlen));
		} else {
			ASSERT(newlen == 0);
		}
		safe_munmap(sbuf->buf, sbuf->buf_size, MMAP_ERASE);
	} else {
		ASSERT(sbuf->buf_size == 0);
	}
	sbuf->buf = nbuf;
	sbuf->buf_size = newlen;
	return nbuf;
}

void
sbuffer_free(sbuffer_t *sbuf)
{
	safe_munmap(sbuf->buf, sbuf->buf_size, MMAP_ERASE);
	sbuf->buf = NULL;
	sbuf->buf_size = 0;
}

/*
 * storage_write_data: encrypt the given buffer and write to the file.
 *
 * => Constructs metadata and stores together with encrypted data.
 * => On success: returns the total number of bytes written to the file.
 * => On error: return -1 and sets 'errno'.
 */
ssize_t
storage_write_data(rvault_t *vault, int fd, const void *buf, size_t len)
{
	crypto_t *crypto = vault->crypto;
	fileobj_hdr_t *hdr;
	size_t max_buf_len, file_len, tag_len, enc_len;
	const void *tag;
	void *enc_buf;
	ssize_t nbytes;

	/*
	 * AEAD or HMAC-based generic composition using the EtM scheme.
	 * It must have been enforced at the vault level.
	 */
	tag_len = crypto_get_aetaglen(crypto);
	ASSERT(tag_len > 0);

	/*
	 * Allocate memory for the full sync.  Ensure the header area,
	 * including the padding, is fully zeroed for a stable AE tag.
	 */
	enc_len = crypto_get_buflen(crypto, len);
	max_buf_len = FILEOBJ_GETMETA_LEN(tag_len) + enc_len;
	if ((hdr = malloc(max_buf_len)) == NULL) {
		app_log(LOG_ERR, "buffer allocation failed");
		return -1;
	}
	memset(hdr, 0, FILEOBJ_GETMETA_LEN(tag_len));

	/*
	 * Setup the header and set it as the AAD.
	 */
	hdr->ver = RVAULT_ABI_VER;
	hdr->aetag_len = tag_len;
	hdr->data_len = htobe64(len);
	hdr->cdata_len = htobe64(0);
	hdr->edata_pad = 0; // to be set
	hdr->mtime = htobe64(time(NULL));

	if (crypto_set_aad(crypto, hdr, FILEOBJ_HDR_LEN) == -1) {
		app_log(LOG_ERR, "crypto_set_aad() failed");
		return -1;
	}

	/*
	 * Encrypt the file.
	 */
	enc_buf = FILEOBJ_HDR_TO_DATA(hdr);
	nbytes = crypto_encrypt(crypto, buf, len, enc_buf, enc_len);
	if (nbytes == -1) {
		app_log(LOG_ERR, "encryption failed");
		goto err;
	}

	/*
	 * Obtain the AE tag and copy it over.
	 */
	if ((tag = crypto_get_aetag(crypto, &tag_len)) == NULL) {
		app_log(LOG_ERR, "crypto_get_aetag() failed");
		nbytes = -1;
		goto err;
	}
	memcpy(FILEOBJ_HDR_TO_AETAG(hdr), tag, tag_len);

	/*
	 * Set the AE signature length and adjust the file length.
	 * We also store the pad bytes to ease the verification on read.
	 */
	file_len = FILEOBJ_GETMETA_LEN(tag_len) + nbytes;
	hdr->edata_pad = (size_t)nbytes - len;

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
 * => AE verification is performed for metadata and data.
 * => On success: returns decrypted data length and fills 'sbuf'.
 * => On error: returns -1 and sets 'errno'.
 */
ssize_t
storage_read_data(rvault_t *vault, int fd, size_t file_len, sbuffer_t *sbuf)
{
	const size_t tag_len = crypto_get_aetaglen(vault->crypto);
	fileobj_hdr_t *hdr, *ae_hdr = NULL;
	const void *enc_buf, *ae_tag;
	ssize_t nbytes = -1;
	sbuffer_t tmpsbuf;
	void *buf = NULL;
	size_t buf_len;

	/*
	 * Memory-map the data file.  Perform basic integrity checks,
	 * including the length verifications.
	 */
	if (file_len < FILEOBJ_HDR_LEN) {
		app_log(LOG_ERR, "data file corrupted");
		errno = EIO;
		return -1;
	}
	hdr = safe_mmap(file_len, fd, 0);
	if (hdr == NULL) {
		return -1;
	}
	if (FILEOBJ_FILE_LEN(hdr) != (uint64_t)file_len ||
	    FILEOBJ_AETAG_LEN(hdr) != (uint64_t)tag_len) {
		app_log(LOG_ERR, "data file corrupted");
		errno = EIO;
		goto out;
	}
	buf_len = FILEOBJ_EDATA_LEN(hdr);
	if (buf_len == 0) {
		goto out;
	}

	/*
	 * Obtain and set the AE tag.
	 */
	ae_tag = FILEOBJ_HDR_TO_AETAG(hdr);
	if (crypto_set_aetag(vault->crypto, ae_tag, tag_len) == -1) {
		app_log(LOG_ERR, "failed to obtain the AE tag");
		goto out;
	}

	/*
	 * Set the adjusted header as AAD to verify.
	 */
	if ((ae_hdr = malloc(FILEOBJ_HDR_LEN)) == NULL) {
		app_elog(LOG_ERR, "%s: malloc() failed", __func__);
		goto out;
	}
	memcpy(ae_hdr, hdr, FILEOBJ_HDR_LEN);
	ae_hdr->edata_pad = 0;

	if (crypto_set_aad(vault->crypto, ae_hdr, FILEOBJ_HDR_LEN) == -1) {
		app_log(LOG_ERR, "crypto_set_aad() failed");
		goto out;
	}

	/*
	 * Allocate a buffer and decrypt the data.  Note: AEAD or HMAC-based
	 * verification will be performed by the crypto_decrypt() primitive.
	 */
	memset(&tmpsbuf, 0, sizeof(sbuffer_t));
	if ((buf = sbuffer_alloc(&tmpsbuf, buf_len)) == NULL) {
		app_log(LOG_ERR, "buffer allocation failed");
		goto out;
	}
	enc_buf = FILEOBJ_HDR_TO_DATA(hdr);
	nbytes = crypto_decrypt(vault->crypto, enc_buf, buf_len, buf, buf_len);
	if (nbytes == -1 || FILEOBJ_DATA_LEN(hdr) != (size_t)nbytes) {
		app_log(LOG_ERR, "decryption failed");
		sbuffer_free(sbuf);
		nbytes = -1;
		goto out;
	}
	memcpy(sbuf, &tmpsbuf, sizeof(sbuffer_t));
out:
	safe_munmap(hdr, file_len, 0);
	free(ae_hdr);
	return nbytes;
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
