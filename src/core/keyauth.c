/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>

#include "rvault.h"
#include "http_req.h"
#include "utils.h"

static const char api_reg_json[] = "{\"uid\": \"%s\", \"key\": \"%s\" }";
static const char api_auth_json[] = "{\"uid\": \"%s\", \"code\": \"%s\" }";

static char *
api_url(const char *server_url, const char *route)
{
	const char prefix[] = "https://";
	const char suffix[] = "/api/v1";
	char *api_url = NULL;
	bool api_path;

	if (strncasecmp(server_url, prefix, sizeof(prefix) - 1) != 0) {
		app_log(LOG_CRIT, APP_NAME": invalid URL "
		    "(must start with %s)", prefix);
		return NULL;
	}
	api_path = strcasestr(server_url, suffix) != NULL;
	if (asprintf(&api_url, "%s/%s/%s", server_url,
	    api_path ? "" : suffix + 1, route) == -1) {
		return NULL;
	}
	app_log(LOG_DEBUG, "%s: URL [%s]", __func__, api_url);
	return api_url;
}

static int
http_api_request(rvault_t *vault, http_req_t *req, const char *route,
    const char *fmt, const char *arg)
{
	char *uid = NULL, *payload = NULL, *url = NULL;
	int ret = -1;

	req->type = HTTP_POST;

	uid = hex_write_str(vault->uid, sizeof(vault->uid));
	if (!uid || asprintf(&payload, fmt, uid, arg) == -1) {
		goto out;
	}
	req->reqbuf = payload;

	if ((url = api_url(vault->server_url, route)) == NULL) {
		goto out;
	}
	if (http_request(url, req) == -1) {
		goto out;
	}
	if (!HTTP_REQ_OK(req)) {
		app_log(LOG_CRIT, "Server-side error (HTTP %d): %s",
		    req->status, req->buf ? req->buf : "-");
		goto out;
	}
	ret = 0;
out:
	free(payload);
	free(url);
	free(uid);
	return ret;
}

int
rvault_key_set(rvault_t *vault)
{
	crypto_t *crypto = vault->crypto;
	void *key = NULL, *ekey = NULL;
	char *ekey_hex = NULL;
	ssize_t nbytes, ret = -1;
	size_t klen, blen, tlen;
	http_req_t req;

	memset(&req, 0, sizeof(http_req_t));

	/*
	 * Prepare the buffers.
	 */
	klen = crypto_get_keylen(crypto);
	if ((key = malloc(klen)) == NULL) {
		goto out;
	}
	blen = crypto_get_buflen(crypto, klen);
	if ((ekey = malloc(blen)) == NULL) {
		goto out;
	}

	/*
	 * Envelope encryption:
	 * - Generate a random key.
	 * - Encrypt it with the derived key.
	 *
	 * NOTE: Authenticated encryption is already achieved with HMAC
	 * on the vault header and the application-level authentication,
	 * so cipher-level AE tag is not strictly necessary.
	 */
	if (crypto_getrandbytes(key, klen) == -1) {
		goto out;
	}
	if ((nbytes = crypto_encrypt(crypto, key, klen, ekey, blen)) == -1) {
		goto out;
	}
	if ((ekey_hex = hex_write_str(ekey, nbytes)) == NULL) {
		goto out;
	}
	if ((tlen = crypto_get_taglen(crypto)) != 0) {
		const void *tag = crypto_get_tag(crypto, &tlen);
		char *tag_hex, *s;

		if ((tag_hex = hex_write_str(tag, tlen)) == NULL) {
			goto out;
		}
		if (asprintf(&s, "%s:%s", ekey_hex, tag_hex) == -1) {
			free(tag_hex);
			goto out;
		}
		free(tag_hex);
		ekey_hex = s;
	}

	/*
	 * Make an API call to register the key.
	 */
	if (http_api_request(vault, &req, "register",
	    api_reg_json, ekey_hex) == -1) {
		goto out;
	}
	printf("%s\n", req.buf ? (const char *)req.buf : "-");

	/*
	 * Re-set the active key.
	 */
	ret = crypto_set_key(crypto, key, klen);
out:
	/*
	 * Destroy the buffers.
	 */
	if (ekey_hex) {
		crypto_memzero(ekey_hex, strlen(ekey_hex));
		free(ekey_hex);
	}
	if (ekey) {
		crypto_memzero(ekey, blen);
		free(ekey);
	}
	if (key) {
		crypto_memzero(key, klen);
		free(key);
	}
	http_req_free(&req);
	return ret;
}

int
rvault_key_get(rvault_t *vault)
{
	crypto_t *crypto = vault->crypto;
	void *ekey = NULL, *key = NULL, *tag = NULL;
	size_t clen = 0, blen, tlen;
	char *s, *code;
	http_req_t req;
	ssize_t klen;
	int ret = -1;

	memset(&req, 0, sizeof(http_req_t));

	/*
	 * Get the TOTP code.  Trim spaces and other possible separators.
	 */
	if ((s = getpass("Authentication code: ")) == NULL) {
		app_log(LOG_CRIT, APP_NAME": missing authentication code");
		return -1;
	}
	code = s;
	while (*s) {
		const char ch = *s;

		if (isalnum((unsigned char)ch)) {
			code[clen++] = ch;
		}
		s++;
	}
	code[clen] = '\0';

	/*
	 * Make an API call to authenticate.
	 */
	if (http_api_request(vault, &req, "auth", api_auth_json, code) == -1) {
		goto out;
	}
	if (req.buf == NULL) {
		app_log(LOG_CRIT, APP_NAME": no key from the server");
		goto out;
	}

	/*
	 * Get the key and the AE tag (if any).
	 */
	if (rvault_unhex_aedata(req.buf, &ekey, &blen, &tag, &tlen) == -1) {
		app_log(LOG_CRIT, APP_NAME": the key received from the "
		    "server is invalid");
		goto out;
	}
	if (tag && crypto_set_tag(crypto, tag, tlen) == -1) {
		app_log(LOG_CRIT, APP_NAME": invalid AE tag");
		free(tag);
		goto out;
	}
	free(tag);

	/*
	 * Decrypt one layer using the derived key.
	 */
	if ((key = malloc(blen)) == NULL) {
		goto out;
	}
	if ((klen = crypto_decrypt(crypto, ekey, blen, key, blen)) == -1) {
		app_log(LOG_CRIT, APP_NAME": the key received from the "
		    "server is invalid");
		goto out;
	}

	/*
	 * Re-set the active key.
	 */
	if (crypto_set_key(crypto, key, klen) == -1) {
		goto out;
	}
	ret = 0;
out:
	if (ekey) {
		crypto_memzero(ekey, blen);
	}
	if (key) {
		crypto_memzero(key, blen);
	}
	crypto_memzero(code, clen);
	http_req_free(&req);
	return ret;
}
