/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_HTTP_REQ_H_
#define	_HTTP_REQ_H_

typedef struct {
	int		type;
	void *		buf;
	size_t		len;
} http_req_t;

int	http_api_request(const char *, http_req_t *);

#endif
