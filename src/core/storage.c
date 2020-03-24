/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * Storage
 *
 * Implements a mechanism for encrypting a memory buffer and writing
 * it into a file with the relevant metadata and vice versa, that is,
 * reading and decrypting the file and providing the data in a memory
 * buffer (represented as sbuffer_t).
 *
 * The storage mechanism concerns: 1) providing sufficient low-level
 * primitives for the file object (fileobj_t) interface)  2) the ABI
 * of the file metadata  3) authenticated encryption at a file level.
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
 * storage_new_obj: compute the lengths, allocate the memory buffer as
 * well as populate the file header.
 */
static fileobj_hdr_t *
storage_new_obj(const rvault_t *vault, size_t len, size_t cdata_len)
{
	crypto_t *crypto = vault->crypto;
	const size_t etarget = cdata_len ? cdata_len : len;
	size_t max_len, meta_len, aetag_len;
	fileobj_hdr_t *hdr;

	/*
	 * AEAD or HMAC-based generic composition using the EtM scheme.
	 * It must have been enforced at the vault level.
	 */
	aetag_len = crypto_get_aetaglen(crypto);
	ASSERT(aetag_len > 0);

	/*
	 * Allocate memory for the full sync.  Ensure the header area,
	 * including the padding, is fully zeroed for a stable AE tag.
	 */
	meta_len = FILEOBJ_GETMETA_LEN(aetag_len);
	max_len = meta_len + crypto_get_buflen(crypto, etarget);
	if ((hdr = malloc(max_len)) == NULL) {
		app_log(LOG_ERR, "buffer allocation failed");
		return NULL;
	}
	memset(hdr, 0, meta_len);

	/*
	 * Setup the header and set it as the AAD.
	 */
	hdr->ver = RVAULT_ABI_VER;
	hdr->flags = vault->compress ? FILEOBJ_FLAG_LZ4 : 0;
	hdr->aetag_len = aetag_len;
	hdr->data_len = htobe64(len);
	hdr->cdata_len = htobe64(cdata_len);
	hdr->edata_pad = 0; // to be set
	hdr->mtime = htobe64(time(NULL));
	return hdr;
}

/*
 * storage_encrypt: encrypt the buffer and compute the AE tag; populates
 * the memory areas represented by fileobj_hdr_t.
 */
static ssize_t
storage_encrypt(rvault_t *vault, fileobj_hdr_t *hdr,
    const void *buf, const size_t len)
{
	crypto_t *crypto = vault->crypto;
	size_t aetag_len, enc_len;
	const void *aetag;
	ssize_t nbytes;
	void *enc_buf;

	enc_buf = FILEOBJ_HDR_TO_DATA(hdr);
	enc_len = crypto_get_buflen(crypto, len);
	ASSERT(FILEOBJ_ETARGET_LEN(hdr) == len);

	/*
	 * Set the header as AAD.  Encrypt the file.
	 */
	if (crypto_set_aad(crypto, hdr, FILEOBJ_HDR_LEN) == -1) {
		app_log(LOG_ERR, "crypto_set_aad() failed");
		return -1;
	}
	nbytes = crypto_encrypt(crypto, buf, len, enc_buf, enc_len);
	if (nbytes == -1) {
		app_log(LOG_ERR, "encryption failed");
		return -1;
	}

	/*
	 * Obtain the AE tag and copy it over.
	 */
	if ((aetag = crypto_get_aetag(crypto, &aetag_len)) == NULL) {
		app_log(LOG_ERR, "crypto_get_aetag() failed");
		return -1;
	}
	memcpy(FILEOBJ_HDR_TO_AETAG(hdr), aetag, aetag_len);

	/* Set the pad bytes to ease the verification on read. */
	hdr->edata_pad = (size_t)nbytes - len;
	return FILEOBJ_GETMETA_LEN(aetag_len) + nbytes;
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
	fileobj_hdr_t *hdr;
	size_t data_len = len, cdata_len = 0;
	sbuffer_t sbuf;
	ssize_t nbytes;

	ASSERT(len > 0);
	memset(&sbuf, 0, sizeof(sbuffer_t));

	/*
	 * Compress the data.
	 */
	if (vault->compress) {
		if ((nbytes = lz4_compress_buf(buf, len, &sbuf)) == -1) {
			app_log(LOG_ERR, "compression failed");
			return -1;
		}
		cdata_len = nbytes;
		buf = sbuf.buf;
		len = nbytes;
	}

	/*
	 * Construct file object and encrypt.
	 */
	if ((hdr = storage_new_obj(vault, data_len, cdata_len)) == NULL) {
		nbytes = -1;
		goto err;
	}
	if ((nbytes = storage_encrypt(vault, hdr, buf, len)) == -1) {
		goto err;
	}
	ASSERT(FILEOBJ_FILE_LEN(hdr) == (size_t)nbytes);

	/*
	 * Write the file to the disk.
	 */
	if (lseek(fd, 0, SEEK_SET) == -1 || ftruncate(fd, 0) == -1) {
		nbytes = -1;
		goto err;
	}
	if (fs_write(fd, hdr, nbytes) != nbytes) {
		nbytes = -1;
		goto err;
	}
	fs_sync(fd, NULL);
err:
	if (vault->compress) {
		sbuffer_free(&sbuf);
	}
	free(hdr);
	return nbytes;
}

/*
 * storage_map_obj: memory-map the data file.
 *
 * => Perform basic integrity checks, including the length verifications.
 * => On success, return the pointer to the header; otherwise, NULL.
 */
static fileobj_hdr_t *
storage_map_obj(rvault_t *vault, int fd, size_t file_len)
{
	fileobj_hdr_t *hdr;
	size_t aetag_len;

	if (file_len < FILEOBJ_HDR_LEN) {
		app_log(LOG_ERR, "data file corrupted");
		errno = EIO;
		return NULL;
	}
	if ((hdr = safe_mmap(file_len, fd, 0)) == NULL) {
		return NULL;
	}
	aetag_len = crypto_get_aetaglen(vault->crypto);
	if (FILEOBJ_FILE_LEN(hdr) != (uint64_t)file_len ||
	    FILEOBJ_AETAG_LEN(hdr) != (uint64_t)aetag_len) {
		app_log(LOG_ERR, "data file corrupted");
		errno = EIO;
		goto out;
	}
	return hdr;
out:
	safe_munmap(hdr, file_len, 0);
	return NULL;
}

/*
 * storage_decrypt: verify and decrypt the data into the given buffer.
 */
static ssize_t
storage_decrypt(rvault_t *vault, const fileobj_hdr_t *hdr, sbuffer_t *sbuf)
{
	fileobj_hdr_t *ae_hdr = NULL;
	size_t ae_tag_len, edata_len, buflen;
	const void *enc_buf, *ae_tag;
	ssize_t nbytes = -1;
	sbuffer_t tmpsbuf;
	void *buf = NULL;

	/*
	 * Obtain and set the AE tag.
	 */
	ae_tag = FILEOBJ_HDR_TO_AETAG(hdr);
	ae_tag_len = FILEOBJ_AETAG_LEN(hdr);
	if (crypto_set_aetag(vault->crypto, ae_tag, ae_tag_len) == -1) {
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
	edata_len = FILEOBJ_EDATA_LEN(hdr);
	buflen = crypto_get_buflen(vault->crypto, edata_len);
	if ((buf = sbuffer_alloc(&tmpsbuf, buflen)) == NULL) {
		app_log(LOG_ERR, "buffer allocation failed");
		goto out;
	}
	enc_buf = FILEOBJ_HDR_TO_DATA(hdr);
	nbytes = crypto_decrypt(vault->crypto, enc_buf, edata_len, buf, buflen);
	if (nbytes == -1 || FILEOBJ_ETARGET_LEN(hdr) != (size_t)nbytes) {
		app_log(LOG_ERR, "decryption failed");
		sbuffer_free(&tmpsbuf);
		nbytes = -1;
		goto out;
	}
	sbuffer_replace(&tmpsbuf, sbuf);
out:
	free(ae_hdr);
	return nbytes;
}

static ssize_t
storage_decompress(const fileobj_hdr_t *hdr, sbuffer_t *sbuf)
{
	const size_t cdata_len = FILEOBJ_CDATA_LEN(hdr);
	const ssize_t data_len = FILEOBJ_DATA_LEN(hdr);
	sbuffer_t tmpsbuf;
	void *buf;

	if ((buf = sbuffer_alloc(&tmpsbuf, data_len)) == NULL) {
		app_log(LOG_ERR, "buffer allocation failed");
		return -1;
	}
	if (lz4_decompress_buf(sbuf->buf, cdata_len, &tmpsbuf) != data_len) {
		sbuffer_free(&tmpsbuf);
		return -1;
	}
	sbuffer_replace(&tmpsbuf, sbuf);
	return data_len;
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
	fileobj_hdr_t *hdr;
	ssize_t nbytes = -1;
	sbuffer_t tmpsbuf;

	if ((hdr = storage_map_obj(vault, fd, file_len)) == NULL) {
		return -1;
	}
	if (FILEOBJ_EDATA_LEN(hdr) == 0) {
		/*
		 * Note: it is currently an error to have no encrypted data.
		 * Empty file is represented as an empty file.
		 */
		goto out;
	}
	memset(&tmpsbuf, 0, sizeof(sbuffer_t));
	if ((nbytes = storage_decrypt(vault, hdr, &tmpsbuf)) == -1) {
		/* Note: tmpsbuf will not be filled. */
		goto out;
	}
	if ((hdr->flags & FILEOBJ_FLAG_LZ4) != 0) {
		nbytes = storage_decompress(hdr, &tmpsbuf);
		if (nbytes == -1) {
			app_log(LOG_ERR, "decompression failed");
			sbuffer_free(&tmpsbuf);
			goto out;
		}
	}
	ASSERT(FILEOBJ_DATA_LEN(hdr) == (size_t)nbytes);
	sbuffer_replace(&tmpsbuf, sbuf);
out:
	safe_munmap(hdr, file_len, 0);
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
