/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "http_req.h"
#include "rvault.h"
#include "crypto.h"
#include "utils.h"

static size_t
write_data(void *buf, size_t size, size_t nmemb, void *ctx)
{
	const size_t nbytes = size * nmemb;
	http_req_t *req = ctx;
	uint8_t *nbuf;

	if (nbytes == 0) {
		return 0;
	}
	if ((nbuf = malloc(req->len + nbytes)) == NULL) {
		return (size_t)-1; // curl will treat is as an error
	}
	if (req->buf) {
		/*
		 * Copy over the previous buffer.  Erase the previous
		 * buffer -- it may contain the key.
		 */
		memcpy(nbuf, req->buf, req->len);
		crypto_memzero(req->buf, req->len);
		free(req->buf);
	}
	memcpy(nbuf + req->len, buf, nbytes);
	req->len += nbytes;
	req->buf = nbuf;
	return nbytes;
}

int
http_api_request(const char *url, http_req_t *req)
{
	CURL *curl;
	CURLcode res;
	long verify;
	int ret = -1;

	/*
	 * Initialize the HTTPS request.
	 */
	if ((curl = curl_easy_init()) == NULL) {
		return -1;
	}
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
	if ((res = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK) {
		app_log(LOG_ERR, "http without TLS is not allowed");
		goto out;
	}
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)req);

	/*
	 * Perform the HTTPS request.
	 */
	if ((res = curl_easy_perform(curl)) != CURLE_OK) {
		goto out;
	}
	res = curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &verify);
	if (res != CURLE_OK || verify != 0) {
		goto out;
	}
	ret = 0;
out:
	if (res != CURLE_OK) {
		const char *errmsg = curl_easy_strerror(res);
		app_log(LOG_ERR, "http request failed: %s", errmsg);
		ret = -1;
	}
	curl_easy_cleanup(curl);
	return ret;
}
