/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * rvault: a secure and authenticated store for secrets and small documents.
 * It uses _envelope encryption_ and OTP or other authentication mechanism
 * together with server.
 *
 * Solution and cryptography
 *
 *	There are two keys: 1) K_p -- a local key generated from a passphrase;
 *	2) K_e -- a randomly generated key used to encrypt/decrypt the data.
 *
 *	Initialization:
 *
 *	- User (client) securely registers itself with the server, presenting
 *	its unique identification (UID) and authentication details, e.g. the
 *	OTP secret / token sequence.
 *
 *	- Envelope encryption: client generates K_p and K_e and encrypts
 *	K_e using K_p, producing K_s.  It then sends K_s to the server and
 *	destroys all keys.  None of the keys are stored locally.
 *
 *	- The server then stores UID, authentication details and K_s.
 *
 *	Data access:
 *
 *	- The user is asked for a passphrase to re-generate the K_p.
 *
 *	- To access the data (one file or mount a file system), the client
 *	needs to authenticate with the server by sending UID and the OTP
 *	token.  Upon successful authentication, the server responds with K_s.
 *
 *	- The client then obtains K_e by decrypting K_s with K_p.  The data
 *	can now be encrypted/decrypted.
 *
 *	- The keys are safely destroyed after the access (or unmount of the
 *	file system).  The access time may also be time-limited (e.g. forced
 *	unmount with key destruction after 5 minutes of inactivity).
 *
 * Algorithms
 *
 *	- scrypt for the key derivation function (KDF).
 *	- The passphrase is salted with a random value stored locally.
 *	- The client-server communication is over TLS *only*.
 *	- Authentication with the server using TOTP (RFC 6238).
 *	- AES 256 GCM and Chacha20 Poly1305 ciphers using AEAD.
 *	- HMAC SHA256 or SHA-3 for a composite AE scheme -- see below.
 *
 * Authenticated Encryption (AE) scheme
 *
 *	AE is achieved using an AEAD cipher.  However, it is not feasible
 *	for authenticating separate encrypted objects which can change
 *	independently, e.g. file chunks, file name vs data or the whole
 *	file tree.  For this purpose, HMAC-based _generic composition_
 *	with the Encrypt-then-MAC scheme (EtM; also called EtA) is used.
 *
 *	EtM has been proven to provide INT-CTXT and IND-CCA (assuming
 *	SUF-CMA) security properties (Bellare and Namprempre, 2007).
 *
 * References
 *
 *	2010, N. Ferguson, B. Schneier and T. Kohno,
 *	"Cryptography Engineering: Design Principles and Practical Applications",
 *	Wiley Publishing; 1st Edition edition.
 *
 *	2007, M. Bellare and C. Namprempre, "Authenticated Encryption: Relations
 *	among notions and analysis of the generic composition paradigm",
 *	http://cseweb.ucsd.edu/~mihir/papers/oem.pdf
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
#include "recovery.h"
#include "sys.h"

#define	RVAULT_META_MODE	0600

static void
usage_srvurl(void)
{
	app_log(LOG_CRIT,
	    APP_NAME ": please specify the server URL.\n\n"
	    "  " APP_NAME " -s URL COMMAND\n"
	    "    or\n"
	    "  RVAULT_SERVER=URL " APP_NAME " COMMAND\n"
	    "\n"
	    "e.g.: https://api.example.org\n"
	    "\n"
	);
}

/*
 * get_vault_path: normalize the path and check that it points to a directory.
 */
static char *
get_vault_path(const char *path)
{
	struct stat st;
	char *rpath;

	if ((rpath = realpath(path, NULL)) == NULL) {
		app_log(LOG_CRIT, APP_NAME": location `%s' not found", path);
		return NULL;
	}
	if (stat(rpath, &st) == -1 || (st.st_mode & S_IFMT) != S_IFDIR) {
		app_log(LOG_CRIT,
		    APP_NAME": path `%s' is not a directory", rpath);
		free(rpath);
		return NULL;
	}
	return rpath;
}

/*
 * open_metadata: open (or create) the vault metadata file.
 *
 * => Returns the file descriptor or -1 on error.
 * => On success, also return the normalized base path.
 */
static int
open_metadata(const char *path, char **normalized_path, int flags)
{
	char *rpath, *fpath = NULL;
	int fd;

	if ((rpath = get_vault_path(path)) == NULL) {
		return -1;
	}
	if (asprintf(&fpath, "%s/%s", rpath, RVAULT_META_FILE) == -1) {
		app_log(LOG_CRIT, APP_NAME": could not allocate memory");
		goto err;
	}
	if ((fd = open(fpath, flags, RVAULT_META_MODE)) == -1) {
		app_elog(LOG_CRIT, APP_NAME": could not %s `%s'",
		    (flags & O_CREAT) ? "create" : "open", fpath);
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
void *
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
		if (normalized_path) {
			free(*normalized_path);
			*normalized_path = NULL;
		}
		close(fd);
		return NULL;
	}
	addr = safe_mmap(len, fd, 0);
	close(fd);
	*flen = len;
	return addr;
}

static ssize_t
rvault_hmac_compute(crypto_t *crypto, const rvault_hdr_t *hdr,
    uint8_t hmac[static HMAC_MAX_BUFLEN])
{
	const void *buf = (const void *)hdr;
	const size_t len = RVAULT_HMAC_DATALEN(hdr);
	return crypto_hmac(crypto, buf, len, hmac);
}

static int
rvault_hmac_verify(crypto_t *crypto, const rvault_hdr_t *hdr)
{
	const void *hmac_rec = RVAULT_HDR_TO_HMAC(hdr);
	const ssize_t hmac_len = hdr->hmac_len;
	uint8_t hmac_comp[HMAC_MAX_BUFLEN];

	/* Note: must verify the 'hmac_len' before comparing. */
	if (rvault_hmac_compute(crypto, hdr, hmac_comp) != hmac_len) {
		return -1;
	}
	return memcmp(hmac_rec, hmac_comp, hmac_len) ? -1 : 0;
}

/*
 * rvault_init: initialize a new vault.
 */
int
rvault_init(const char *path, const char *server, const char *pwd,
    const char *uid_str, const char *cipher_str, const char *mac_str,
    unsigned flags)
{
	crypto_cipher_t cipher;
	crypto_hmac_t hmac_id;
	crypto_t *crypto = NULL;
	rvault_hdr_t *hdr = NULL;
	void *iv = NULL, *kp = NULL, *uid = NULL;
	size_t file_len, iv_len, kp_len, uid_len;
	uint8_t hmac[HMAC_MAX_BUFLEN];
	ssize_t hmac_len;
	int ret = -1, fd;

	/*
	 * Determine the cipher and MAC.
	 * Choose a default, if none specified.
	 */
	if (cipher_str) {
		if ((cipher = crypto_cipher_id(cipher_str)) == CIPHER_NONE) {
			app_log(LOG_CRIT,
			    APP_NAME": invalid or unsupported cipher `%s'",
			    cipher_str);
			goto err;
		}
	} else {
		cipher = CRYPTO_CIPHER_PRIMARY;
	}
	if (mac_str) {
		if ((hmac_id = crypto_hmac_id(mac_str)) == HMAC_NONE) {
			app_log(LOG_CRIT,
			    APP_NAME": invalid or unsupported MAC `%s'",
			    mac_str);
			goto err;
		}
	} else {
		hmac_id = CRYPTO_HMAC_PRIMARY;
	}

	/*
	 * Initialize the metadata:
	 * - Generate the IV / nonce.
	 * - Generate the KDF parameters.
	 */
	if ((crypto = crypto_create(cipher, hmac_id)) == NULL) {
		if (errno == ENOTSUP) {
			app_log(LOG_CRIT,
			    APP_NAME": the `%s' cipher is not supported "
			    "on your system", cipher_str);
		}
		goto err;
	}
	if ((iv = crypto_gen_iv(crypto, &iv_len)) == NULL) {
		goto err;
	}
	if (crypto_set_iv(crypto, iv, iv_len) == -1) {
		goto err;
	}
	if ((kp = kdf_create_params(&kp_len)) == NULL) {
		goto err;
	}

	/*
	 * Derive the key: it will be needed for HMAC.
	 */
	if (crypto_set_passphrasekey(crypto, pwd, kp, kp_len) == -1) {
		goto err;
	}
	hmac_len = crypto_hmac_len(hmac_id);
	ASSERT(hmac_len > 0);

	/*
	 * Setup the vault header.
	 * - Calculate the total length.
	 * - Set the header values.
	 * - Copy over the IV and KDF parameters.
	 */
	file_len = RVAULT_HDR_LEN + iv_len + kp_len + hmac_len;
	if ((hdr = calloc(1, file_len)) == NULL) {
		goto err;
	}

	ASSERT(cipher <= UINT8_MAX);
	ASSERT(flags <= UINT8_MAX);
	ASSERT(kp_len <= UINT8_MAX);
	ASSERT(iv_len <= UINT8_MAX);
	ASSERT(hmac_len <= UINT8_MAX);

	hdr->ver = RVAULT_ABI_VER;
	hdr->flags = flags;
	hdr->cipher0 = cipher;
	hdr->cipher1 = CIPHER_NONE;
	hdr->hmac_id = hmac_id;

	hdr->kp_len = kp_len;
	hdr->iv0_len = iv_len;
	hdr->iv1_len = 0;
	hdr->hmac_len = hmac_len;

	memcpy(RVAULT_HDR_TO_IV0(hdr), iv, iv_len);
	memcpy(RVAULT_HDR_TO_KP(hdr), kp, kp_len);

	/*
	 * Copy over the UID.
	 */
	uid = hex_read_arbitrary_buf(uid_str, strlen(uid_str), &uid_len);
	if (uid == NULL || uid_len != sizeof(hdr->uid)) {
		app_log(LOG_CRIT, APP_NAME": invalid user ID (UID); "
		    "it must be UUID in hex representation.");
		goto err;
	}
	memcpy(hdr->uid, uid, uid_len);

	/*
	 * If using authentication with envelope-encryption:
	 * - Generate and assign the effective encryption key.
	 * - Register with the remote and post the envelope-encrypted key.
	 */
	if ((flags & RVAULT_FLAG_NOAUTH) == 0) {
		rvault_t vault; // XXX placeholder

		if (!server) {
			usage_srvurl();
			goto err;
		}

		memset(&vault, 0, sizeof(rvault_t));
		vault.server_url = server;
		vault.crypto = crypto;
		vault.hmac_id = hdr->hmac_id;
		memcpy(vault.uid, uid, uid_len);

		if (rvault_key_set(&vault) == -1) {
			app_log(LOG_DEBUG, "%s() failed", __func__);
			goto err;
		}
	}

	/*
	 * Now that the effective encryption key has been decided,
	 * compute the HMAC and write it to the file.  Copy it over.
	 */
	if (rvault_hmac_compute(crypto, hdr, hmac) != hmac_len) {
		goto err;
	}
	memcpy(RVAULT_HDR_TO_HMAC(hdr), hmac, hmac_len);

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
	free(uid);
	return ret;
}

static rvault_t *
rvault_open_hdr(rvault_hdr_t *hdr, const char *server, const size_t file_len)
{
	rvault_t *vault;
	const void *iv;
	size_t iv_len;

	/* Verify the ABI version. */
	if (hdr->ver != RVAULT_ABI_VER) {
		app_log(LOG_CRIT, APP_NAME": incompatible vault version %u\n"
		    "Hint: vault might have been created using a %s "
		    "application version", hdr->ver,
		    (hdr->ver > RVAULT_ABI_VER) ?
		    "newer" : "no longer supported");
		return NULL;
	}

	/*
	 * Verify the lengths: we can trust the *length* values to
	 * represent the accessible memory areas after this.
	 *
	 * Ensure that the HMAC algorithm is set.  This must be done
	 * even if using the AE cipher.
	 */
	if (RVAULT_FILE_LEN(hdr) != file_len || hdr->hmac_id == HMAC_NONE) {
		app_log(LOG_CRIT, "rvault: metadata file corrupted");
		return NULL;
	}
	iv_len = hdr->iv0_len;
	iv = RVAULT_HDR_TO_IV0(hdr);

	/*
	 * Create and initialize the vault object.
	 */
	if ((vault = calloc(1, sizeof(rvault_t))) == NULL) {
		return NULL;
	}
	vault->cipher = hdr->cipher0;
	vault->hmac_id = hdr->hmac_id;
	vault->server_url = server;
	LIST_INIT(&vault->file_list);

	static_assert(sizeof(vault->uid) == sizeof(hdr->uid), "UUID length");
	memcpy(vault->uid, hdr->uid, sizeof(hdr->uid));

	/*
	 * Create the crypto object and set the IV.
	 */
	vault->crypto = crypto_create(vault->cipher, vault->hmac_id);
	if (!vault->crypto) {
		if (errno == ENOTSUP) {
			app_log(LOG_CRIT,
			    APP_NAME": the used cipher is not supported "
			    "on your system (change the library)", NULL);
		}
		goto err;
	}
	if (crypto_set_iv(vault->crypto, iv, iv_len) == -1) {
		goto err;
	}
	return vault;
err:
	rvault_close(vault);
	return NULL;
}

/*
 * rvault_open: open the vault at the given directory.
 */
rvault_t *
rvault_open(const char *path, const char *server, const char *pwd)
{
	rvault_t *vault = NULL;
	char *base_path = NULL;
	rvault_hdr_t *hdr;
	size_t file_len, kp_len;
	const void *kp;

	hdr = open_metadata_mmap(path, &base_path, &file_len);
	if (hdr == NULL) {
		goto err;
	}
	vault = rvault_open_hdr(hdr, server, file_len);
	if (vault == NULL) {
		goto err;
	}
	vault->base_path = base_path;

	/*
	 * Set the vault key.
	 *
	 * NOTE: rvault_open_hdr() verified the header lengths for us,
	 * therefore we can trust the 'kp_len' at this point.
	 */
	kp_len = hdr->kp_len;
	kp = RVAULT_HDR_TO_KP(hdr);
	if (crypto_set_passphrasekey(vault->crypto, pwd, kp, kp_len) == -1) {
		goto err;
	}

	/*
	 * Authenticate and fetch the key.
	 */
	if ((hdr->flags & RVAULT_FLAG_NOAUTH) == 0) {
		if (!server) {
			usage_srvurl();
			goto err;
		}
		if (rvault_key_get(vault) == -1) {
			goto err;
		}
	}

	/*
	 * Verify the HMAC.  Note: need the crypto object to obtain the
	 * authentication key.
	 */
	if (rvault_hmac_verify(vault->crypto, hdr) != 0) {
		app_log(LOG_CRIT, APP_NAME": verification failed: "
		    "invalid passphrase?");
		goto err;
	}
	safe_munmap(hdr, file_len, 0);

	return vault;
err:
	if (hdr) {
		safe_munmap(hdr, file_len, 0);
	}
	if (vault) {
		rvault_close(vault);
	}
	return NULL;
}

/*
 * rvault_open_ekey: open vault for recovery using a given effective key.
 */
rvault_t *
rvault_open_ekey(const char *path, const char *recovery)
{
	rsection_t *sections;
	rvault_t *vault = NULL;
	char *base_path = NULL;
	size_t hdrlen, keylen, akeylen;
	rvault_hdr_t *hdr;
	void *key, *akey;
	FILE *fp;

	/*
	 * Open and parse the recovery file.
	 */
	if ((fp = fopen(recovery, "r")) == NULL) {
		app_elog(LOG_CRIT, APP_NAME": could not open `%s'", recovery);
		return NULL;
	}
	sections = rvault_recovery_import(fp);
	fclose(fp);
	if (!sections) {
		return NULL;
	}

	/* Get the sections. */
	hdr = sections[RECOVERY_METADATA].buf;
	hdrlen = sections[RECOVERY_METADATA].nbytes;

	key = sections[RECOVERY_EKEY].buf;
	keylen = sections[RECOVERY_EKEY].nbytes;

	akey = sections[RECOVERY_AKEY].buf;
	akeylen = sections[RECOVERY_AKEY].nbytes;

	/*
	 * Create the "recovery" vault object using the metadata.
	 */
	if ((base_path = get_vault_path(path)) == NULL) {
		goto err;
	}
	vault = rvault_open_hdr(hdr, NULL, hdrlen);
	if (vault == NULL) {
		goto err;
	}
	vault->base_path = base_path;
	base_path = NULL;

	/*
	 * Set the keys.
	 */
	if (crypto_set_key(vault->crypto, key, keylen) == -1) {
		rvault_close(vault);
		vault = NULL;
		goto err;
	}
	if (crypto_set_authkey(vault->crypto, akey, akeylen) == -1) {
		rvault_close(vault);
		vault = NULL;
		goto err;
	}
err:
	rvault_recovery_release(sections);
	free(base_path);
	return vault;
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

		/* "." and ".." are somewhat special cases. */
		if (strcmp(vname, ".") == 0 || strcmp(vname, "..") == 0) {
			iterfunc(arg, vname, dp);
			continue;
		}

		/*
		 * Skip any files which do not have rvault prefix.  This is
		 * primarily because other applications or the user might,
		 * for whatever reason, litter in the vault directory, e.g.
		 * there may be temporary/hidden files.
		 */
		if (strncmp(vname, RVAULT_FOBJ_PREF, RVAULT_FOBJ_PREFLEN)) {
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
