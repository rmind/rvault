/*
 * Copyright (c) 2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * Recover file and its format.
 *
 * - Exporting and importing of the recovery file.
 * - File format: implements 'sections' to separate and label the data.
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include "rvault.h"
#include "storage.h"
#include "recovery.h"
#include "sys.h"

#define	RVAULT_MAX_METALEN	4096	// sanity check for metadata length
#define	CRYPTO_MAX_KEYLEN	1024	// sanity check for key length

static unsigned
get_section(const char *line)
{
	if (strcasestr(line, "metadata")) {
		return RECOVERY_METADATA;
	}
	if (strcasestr(line, "ekey")) {
		return RECOVERY_EKEY;
	}
	if (strcasestr(line, "akey")) {
		return RECOVERY_AKEY;
	}
	return RECOVERY_NSECTIONS;
}

static int
fill_section(rsection_t *sec, void *buf, size_t len)
{
	if (!sec->buf && (sec->buf = calloc(1, sec->bufsize)) == NULL) {
		app_elog(LOG_ERR, "malloc() failed");
		return -1;
	}
	if (sec->nbytes + len > sec->bufsize) {
		app_log(LOG_CRIT, APP_NAME": invalid recovery file.");
		return -1;
	}
	memcpy((uint8_t *)sec->buf + sec->nbytes, buf, len);
	sec->nbytes += len;
	return 0;
}

/*
 * rvault_recovery_export: write a recovery file with metadata and key.
 */
void
rvault_recovery_export(rvault_t *vault, FILE *fp)
{
	rvault_hdr_t *hdr;
	size_t key_len, akey_len, file_len;
	const void *key, *akey;

	fputs("# METADATA:\n", fp);
	hdr = open_metadata_mmap(vault->base_path, NULL, &file_len);
	hex_write_wrapped(fp, hdr, file_len);
	fputs("\n", fp);

	fputs("# EKEY:\n", fp);
	key = crypto_get_key(vault->crypto, &key_len);
	hex_write_wrapped(fp, key, key_len);
	fputs("\n", fp);

	fputs("# AKEY:\n", fp);
	akey = crypto_get_authkey(vault->crypto, &akey_len);
	hex_write_wrapped(fp, akey, akey_len);
	fputs("\n", fp);

	safe_munmap(hdr, file_len, 0);
}

/*
 * rvault_recovery_import: parse recovery file and import metadata with key.
 */
rsection_t *
rvault_recovery_import(FILE *fp)
{
	rsection_t *sections;
	unsigned idx = RECOVERY_NSECTIONS;
	ssize_t len, ret = 0;
	char *line = NULL;
	size_t lsize = 0;

	sections = calloc(1, sizeof(rsection_t) * RECOVERY_NSECTIONS);
	if (sections == NULL) {
		app_elog(LOG_ERR, "malloc() failed");
		return NULL;
	}
	sections[RECOVERY_METADATA].bufsize = RVAULT_MAX_METALEN;
	sections[RECOVERY_EKEY].bufsize = CRYPTO_MAX_KEYLEN;
	sections[RECOVERY_AKEY].bufsize = CRYPTO_MAX_KEYLEN;

	/*
	 * Read the sections in the recovery file.
	 */
	while ((len = getline(&line, &lsize, fp)) > 0 && ret == 0) {
		size_t blen;
		void *buf;

		/*
		 * Get/check the section.
		 */
		if (line[0] == '#') {
			idx = get_section(line);
			continue;
		}
		if (idx == RECOVERY_NSECTIONS) {
			app_log(LOG_CRIT, APP_NAME": invalid recovery file.\n"
			    "Hint: malformed or unknown sections?");
			ret = -1;
			goto err;
		}

		/*
		 * Read the line of hex.
		 */
		buf = hex_read_arbitrary_buf(line, len, &blen);
		crypto_memzero(line, len);
		if (buf == NULL) {
			/* Might be an empty line. */
			continue;
		}

		/*
		 * Append to the relevant buffer.
		 */
		ret = fill_section(&sections[idx], buf, blen);
		crypto_memzero(buf, blen);
		free(buf);
		if (ret == -1) {
			goto err;
		}
	}
	for (unsigned i = 0; i < RECOVERY_NSECTIONS; i++) {
		if (!sections[i].buf) {
			app_log(LOG_CRIT, APP_NAME": invalid recovery file.");
			ret = -1;
			break;
		}
	}
err:
	free(line);
	if (ret == -1) {
		rvault_recovery_release(sections);
		sections = NULL;
	}
	return sections;
}

void
rvault_recovery_release(rsection_t *sections)
{
	for (unsigned i = 0; i < RECOVERY_NSECTIONS; i++) {
		rsection_t *sec = &sections[i];

		if (sec->buf) {
			crypto_memzero(sec->buf, sec->bufsize);
			free(sec->buf);
		}
	}
	free(sections);
}
