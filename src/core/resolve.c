/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "rvault.h"
#include "utils.h"

/*
 * rvault_unhex_aedata: parse the hex string which contains data and,
 * optionally, an AE tag separated by ":".
 */
int
rvault_unhex_aedata(const char *hex, void **datap, size_t *len,
    void **tagp, size_t *taglen)
{
	void *data = NULL, *tag = NULL;
	char *s = NULL, *taghex;

	if ((taghex = strchr(hex, ':')) != NULL) {
		const unsigned off = (uintptr_t)taghex - (uintptr_t)hex + 1;

		if ((s = strndup(hex, off)) == NULL) {
			goto err;
		}
		tag = hex_read_arbitrary_buf(taghex, strlen(taghex), taglen);
		if (tag == NULL) {
			goto err;
		}
		hex = s;
	}
	if ((data = hex_read_arbitrary_buf(hex, strlen(hex), len)) == NULL) {
		goto err;
	}
	free(s);

	*datap = data;
	*tagp = tag;
	return 0;
err:
	free(data);
	free(tag);
	free(s);
	return -1;
}

static ssize_t
get_path_component(rvault_t *vault, const char *pc, size_t len, FILE *fp)
{
	unsigned char buf[PATH_MAX + 1];
	ssize_t ret, nbytes;

	if (!vault->crypto) {
		/* For testing purposes. */
		return fprintf(fp, "%.*s", (int)len, pc);
	}
	if (crypto_get_buflen(vault->crypto, len) > sizeof(buf)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	ret = crypto_encrypt(vault->crypto, pc, len, buf, sizeof(buf));
	if (ret == -1 || (nbytes = hex_write(fp, buf, ret)) < 0) {
		return -1;
	}
	if (crypto_get_taglen(vault->crypto)) {
		size_t tag_len;
		const void *tag;

		if (fputc(':', fp) < 0) {
			return -1;
		}
		tag = crypto_get_tag(vault->crypto, &tag_len);
		if ((ret = hex_write(fp, tag, tag_len)) < 0) {
			return -1;
		}
		nbytes += tag_len;
	}
	return nbytes;
}

/*
 * Wrapper for strchrnul() since many systems don't have it.
 */
static char *
local_strchrnul(const char *p, int ch)
{
	while (*p && *p != (const char)ch) {
		p++;
	}
	return (void *)(uintptr_t)p;
}

/*
 * rvault_resolve_path: resolve the plain path within the vault namespace,
 * returning an absolute path to the encrypted file object.
 *
 * => Allocates memory and returns the path; the caller must free it.
 * => Returns the path length (without NUL terminator).
 */
char *
rvault_resolve_path(rvault_t *vault, const char *path, size_t *rlen)
{
	char *fpath = NULL, *buf = NULL;
	const char *pc, *p;
	size_t len = 0, pclen;
	FILE *fp = NULL;

	if ((fp = open_memstream(&buf, &len)) == NULL) {
		return NULL;
	}

	/*
	 * Normalize: handle "." and "..", as well as trailing "/".
	 */
	for (pc = path, p = path; *p != '\0'; pc = p + 1) {
		p = local_strchrnul(pc, '/');
		pclen = (uintptr_t)p - (uintptr_t)pc;

		if (pclen == 0 || (pclen == 1 && pc[0] == '.')) {
			/* Just skip. */
			continue;
		}
		if (pclen == 2 && strncmp(pc, "..", 2) == 0) {
			long off;

			/*
			 * Trim the last component.
			 */
			if (fflush(fp) != 0) {
				goto err;
			}
			if ((off = ftell(fp)) > 0) {
				while (off && buf[off] != '/') {
					off--;
				}
				fseek(fp, off, SEEK_SET);
			}
			continue;
		}
		if (fputs("/", fp) < 0) {
			goto err;
		}
		if (get_path_component(vault, pc, pclen, fp) == -1) {
			goto err;
		}
	}

	/*
	 * Force NUL terminator as the cursor might have been rewound.
	 * Finally, flush before accessing the buffer.
	 */
	if (fputc('\0', fp) < 0 || fflush(fp) != 0) {
		goto err;
	}

	len = (size_t)asprintf(&fpath, "%s/%s",
	    vault->base_path ? vault->base_path : "",
	    (*buf == '/') ? (buf + 1) : buf);
	if (rlen) {
		*rlen = len;
	}
err:
	fclose(fp);
	free(buf);

	if (!fpath) {
		app_log(LOG_ERR, "%s: failed to resolve `%s'", __func__, path);
		errno = ENOENT;
	} else {
		app_log(LOG_DEBUG, "%s: `%s' -> `%s'", __func__, path, fpath);
	}
	return fpath;
}

/*
 * rvault_resolve_vname: resolve vault name to the decrypted form.
 */
char *
rvault_resolve_vname(rvault_t *vault, const char *vname, size_t *rlen)
{
	void *buf = NULL, *tag = NULL;
	size_t blen, len, tlen;
	char *name = NULL;
	ssize_t nbytes;

	if (rvault_unhex_aedata(vname, &buf, &len, &tag, &tlen) == -1) {
		goto err;
	}
	if (tag && crypto_set_tag(vault->crypto, tag, tlen) == -1) {
		app_log(LOG_ERR, "%s: invalid AE tag", __func__);
		free(tag);
		goto err;
	}
	free(tag);

	blen = crypto_get_buflen(vault->crypto, len);
	if ((name = malloc(blen + 1)) == NULL) {
		goto err;
	}
	nbytes = crypto_decrypt(vault->crypto, buf, len, name, blen);
	if (nbytes == -1) {
		free(name);
		name = NULL;
		errno = EINVAL;
		goto err;
	}
	name[nbytes] = '\0';
	if (rlen) {
		*rlen = nbytes;
	}
err:
	free(buf);

	if (name == NULL) {
		app_log(LOG_ERR, "%s: failed to resolve `%s'", __func__, vname);
	}
	return name;
}
