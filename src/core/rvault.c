/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

#include "rvault.h"
#include "fileobj.h"
#include "storage.h"
#include "crypto.h"
#include "sys.h"

#define	RVAULT_META_MODE	0600

/*
 * open_metadata: normalize the path, check that it points to a directory,
 * open (or create) the vault metadata file
 *
 * => Returns the file descriptor or -1 on error.
 * => On success, also return the normalized base path.
 */
static int
open_metadata(const char *path, char **normalized_path, int flags)
{
	char *rpath, *fpath = NULL;
	struct stat st;
	int fd;

	if ((rpath = realpath(path, NULL)) == NULL) {
		app_log(LOG_CRIT, APP_NAME": location `%s' not found", path);
		return -1;
	}
	if (stat(rpath, &st) == -1 || (st.st_mode & S_IFMT) != S_IFDIR) {
		app_log(LOG_CRIT,
		    APP_NAME": path `%s' is not a directory", rpath);
		goto err;
	}
	if (asprintf(&fpath, "%s/%s", rpath, RVAULT_META_FILE) == -1) {
		app_log(LOG_CRIT, APP_NAME": could not allocate memory");
		goto err;
	}
	if ((fd = open(fpath, flags, RVAULT_META_MODE)) == -1) {
		app_log(LOG_CRIT, APP_NAME": could not %s `%s': %s",
		    (flags & O_CREAT) ? "create" : "open", fpath,
		    strerror(errno));
		goto err;
	}
	free(fpath);

	if (normalized_path) {
		*normalized_path = rpath;
	} else {
		free(rpath);
	}
	return fd;
err:
	free(rpath);
	free(fpath);
	return -1;
}

/*
 * open_metadata_mmap: get the read-only mapping of the vault metadata.
 */
static void *
open_metadata_mmap(const char *base_path, char **normalized_path, size_t *flen)
{
	ssize_t len;
	void *addr;
	int fd;

	if ((fd = open_metadata(base_path, normalized_path, O_RDONLY)) == -1) {
		return NULL;
	}
	if ((len = fs_file_size(fd)) < (ssize_t)RVAULT_HDR_LEN) {
		app_log(LOG_CRIT, "rvault: metadata file corrupted");
		free(*normalized_path);
		*normalized_path = NULL;
		close(fd);
		return NULL;
	}
	addr = safe_mmap(len, fd, 0);
	close(fd);
	*flen = len;
	return addr;
}

static int
rvault_hmac_compute(crypto_t *crypto, const rvault_hdr_t *hdr,
    uint8_t hmac[static HMAC_SHA3_256_BUFLEN])
{
	const void *key;
	size_t key_len;

	key = crypto_get_key(crypto, &key_len);
	ASSERT(key != NULL);

	if (hmac_sha3_256(key, key_len, (const void *)hdr,
	    RVAULT_HMAC_DATALEN(hdr), hmac) == -1) {
		return -1;
	}
	return 0;
}

static int
rvault_hmac_verify(crypto_t *crypto, const rvault_hdr_t *hdr)
{
	const void *hmac_rec = RVAULT_HDR_TO_HMAC(hdr);
	uint8_t hmac_comp[HMAC_SHA3_256_BUFLEN];

	if (rvault_hmac_compute(crypto, hdr, hmac_comp) == -1) {
		return -1;
	}
	return memcmp(hmac_rec, hmac_comp, HMAC_SHA3_256_BUFLEN) ? -1 : 0;
}

/*
 * rvault_init: initialize a new vault.
 */
int
rvault_init(const char *path, const char *pwd,
    const char *cipher_str, unsigned flags)
{
	crypto_cipher_t cipher;
	crypto_t *crypto = NULL;
	rvault_hdr_t *hdr = NULL;
	void *iv = NULL, *kp = NULL;
	uint8_t hmac[HMAC_SHA3_256_BUFLEN];
	size_t file_len, iv_len, kp_len;
	int ret = -1, fd;

	/*
	 * Initialize the metadata:
	 * - Determine the cipher.
	 * - Generate the KDF parameters.
	 * - Generate the IV.
	 */
	if (cipher_str) {
		if ((cipher = crypto_cipher_id(cipher_str)) == CIPHER_NONE) {
			app_log(LOG_CRIT,
			    APP_NAME": invalid or unsupported cipher `%s'",
			    cipher_str);
			goto err;
		}
	} else {
		/* Choose a default. */
		cipher = CRYPTO_CIPHER_PRIMARY;
	}
	if ((crypto = crypto_create(cipher)) == NULL) {
		goto err;
	}
	if ((iv = crypto_gen_iv(crypto, &iv_len)) == NULL) {
		goto err;
	}
	if ((kp = kdf_create_params(&kp_len)) == NULL) {
		goto err;
	}
	ASSERT(kp_len <= UINT8_MAX);
	ASSERT(iv_len <= UINT16_MAX);

	/*
	 * Derive the key: it will be needed for HMAC.
	 */
	if (crypto_set_passphrasekey(crypto, pwd, kp, kp_len) == -1) {
		goto err;
	}

	/*
	 * Setup the vault header.
	 * - Calculate the total length.
	 * - Set the header values.
	 * - Copy over the IV and KDF parameters.
	 */
	file_len = RVAULT_HDR_LEN + iv_len + kp_len + HMAC_SHA3_256_BUFLEN;
	if ((hdr = calloc(1, file_len)) == NULL) {
		goto err;
	}
	ASSERT(cipher <= UINT8_MAX);
	ASSERT(flags <= UINT8_MAX);

	hdr->ver = RVAULT_ABI_VER;
	hdr->cipher = cipher;
	hdr->flags = flags;
	hdr->kp_len = kp_len;
	hdr->iv_len = htobe16(iv_len);
	memcpy(RVAULT_HDR_TO_IV(hdr), iv, iv_len);
	memcpy(RVAULT_HDR_TO_KP(hdr), kp, kp_len);

	/*
	 * Compute the HMAC and write it to the file.  Copy it over.
	 */
	if (rvault_hmac_compute(crypto, hdr, hmac) != 0) {
		goto err;
	}
	memcpy(RVAULT_HDR_TO_HMAC(hdr), hmac, HMAC_SHA3_256_BUFLEN);

	/*
	 * Open the metadata file and store the record.
	 */
	fd = open_metadata(path, NULL, O_CREAT | O_EXCL | O_WRONLY | O_SYNC);
	if (fd == -1) {
		goto err;
	}
	if (fs_write(fd, hdr, file_len) != (ssize_t)file_len) {
		close(fd);
		goto err;
	}
	fs_sync(fd, path);
	close(fd);
	ret = 0;
err:
	if (crypto) {
		crypto_destroy(crypto);
	}
	/* Note: free() takes NULL. */
	free(hdr);
	free(iv);
	free(kp);
	return ret;
}

/*
 * rvault_open: open the vault at the given directory.
 */
rvault_t *
rvault_open(const char *path, const char *pwd)
{
	rvault_t *vault;
	rvault_hdr_t *hdr;
	size_t file_len, iv_len, kp_len;
	const void *iv, *kp;

	if ((vault = calloc(1, sizeof(rvault_t))) == NULL) {
		return NULL;
	}
	LIST_INIT(&vault->file_list);

	hdr = open_metadata_mmap(path, &vault->base_path, &file_len);
	if (hdr == NULL) {
		goto err;
	}
	if (hdr->ver != RVAULT_ABI_VER) {
		app_log(LOG_CRIT, "rvault: incompatible vault version %u\n"
		    "Hint: vault might have been created using a newer "
		    "application version", hdr->ver);
		goto err;
	}
	iv_len = be16toh(hdr->iv_len);
	kp_len = hdr->kp_len;

	/*
	 * Verify the lengths: we can trust iv_len and kp_len after this.
	 */
	if (RVAULT_FILE_LEN(hdr) != file_len) {
		goto err;
	}
	iv = RVAULT_HDR_TO_IV(hdr);
	kp = RVAULT_HDR_TO_KP(hdr);

	/*
	 * Create the crypto object.  Set the IV and key.
	 */
	if ((vault->crypto = crypto_create(hdr->cipher)) == NULL) {
		goto err;
	}
	if (crypto_set_iv(vault->crypto, iv, iv_len) == -1) {
		goto err;
	}
	if (crypto_set_passphrasekey(vault->crypto, pwd, kp, kp_len) == -1) {
		goto err;
	}
	vault->cipher = hdr->cipher;

	/*
	 * Verify the HMAC.  Note: need the crypto object to obtain the key.
	 */
	if (rvault_hmac_verify(vault->crypto, hdr) != 0) {
		app_log(LOG_CRIT, "rvault: verification failed: "
		    "invalid passphrase?");
		goto err;
	}
	return vault;
err:
	rvault_close(vault);
	return NULL;
}

static void
rvault_close_files(rvault_t *vault)
{
	fileobj_t *fobj;

	while ((fobj = LIST_FIRST(&vault->file_list)) != NULL) {
		/* Closing removes the file-object from the list. */
		fileobj_close(fobj);
	}
	ASSERT(vault->file_count == 0);
}

/*
 * rvault_close: close the vault, safely destroying the in-memory key.
 */
void
rvault_close(rvault_t *vault)
{
	rvault_close_files(vault);

	if (vault->base_path) {
		free(vault->base_path);
	}
	if (vault->crypto) {
		crypto_destroy(vault->crypto);
	}
	free(vault);
}

/*
 * rvault_iter_dir: iterate the directory in the vault.
 */
int
rvault_iter_dir(rvault_t *vault, const char *path,
    void *arg, dir_iter_t iterfunc)
{
	struct dirent *dp;
	char *vpath;
	DIR *dirp;

	if ((vpath = rvault_resolve_path(vault, path, NULL)) == NULL) {
		return -1;
	}
	dirp = opendir(vpath);
	if (dirp == NULL) {
		free(vpath);
		return -1;
	}
	free(vpath);

	while ((dp = readdir(dirp)) != NULL) {
		const char *vname = dp->d_name;
		char *name;

		if (vname[0] == '.') {
			continue;
		}
		if (!strncmp(vname, RVAULT_META_PREF, RVAULT_META_PREFLEN)) {
			continue;
		}

		name = rvault_resolve_vname(vault, vname, NULL);
		if (name == NULL) {
			closedir(dirp);
			return -1;
		}
		iterfunc(arg, name, dp);
		free(name);
	}
	closedir(dirp);
	return 0;
}
