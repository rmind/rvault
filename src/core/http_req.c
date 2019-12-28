/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include <curl/curl.h>

#include "rvault.h"
#include "crypto.h"
#include "http_req.h"
#include "utils.h"

static size_t
write_data(void *buf, size_t size, size_t nmemb, void *ctx)
{
	const size_t nbytes = size * nmemb;
	http_req_t *req = ctx;

	if (nbytes && fwrite(buf, size, nmemb, req->fp) != nbytes) {
		return (size_t)-1; // curl will treat is as an error
	}
	return nbytes;
}

int
http_request(const char *url, http_req_t *req)
{
	CURL *curl;
	long verify, status;
	CURLcode res;
	int ret = -1;

	/*
	 * Initialize the HTTPS request.
	 */
	if ((curl = curl_easy_init()) == NULL) {
		return -1;
	}
	//FIXME: curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
	if ((res = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK) {
		app_log(LOG_ERR, "http without TLS is not allowed");
		goto out;
	}
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

	switch (req->type) {
	case HTTP_GET:
		curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
		break;
	case HTTP_POST:
		if (req->reqbuf) {
			const size_t bodylen = strlen(req->reqbuf);
			void *reqbuf = __UNCONST(req->reqbuf);

			req->reqfp = fmemopen(reqbuf, bodylen, "r");
			curl_easy_setopt(curl, CURLOPT_READDATA, req->reqfp);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, bodylen);
		}
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		break;
	default:
		errno = EINVAL;
		goto out;
	}
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

	req->fp = open_memstream((char **)&req->buf, &req->len);
	if (req->fp == NULL) {
		goto out;
	}
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
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
	req->status = (int)status;
	ret = 0;
out:
	if (res != CURLE_OK) {
		const char *errmsg = curl_easy_strerror(res);
		app_log(LOG_ERR, "http request failed: %s", errmsg);
		ret = -1;
	}
	curl_easy_cleanup(curl);
	if (req->reqfp) {
		fclose(req->reqfp);
		req->reqfp = NULL;
	}
	if (req->fp) {
		fclose(req->fp);
		req->fp = NULL;
	}
	return ret;
}

void
http_req_free(http_req_t *req)
{
	if (req->buf) {
		crypto_memzero(req->buf, req->len);
		free(req->buf);
	}
	memset(req, 0, sizeof(http_req_t));
}
