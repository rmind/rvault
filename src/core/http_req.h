/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_HTTP_REQ_H_
#define	_HTTP_REQ_H_

enum { HTTP_GET, HTTP_POST };

typedef struct {
	int		type;
	void *		buf;
	size_t		len;
	FILE *		fp;

	const char *	reqbuf;
	int		status;
} http_req_t;

#define	HTTP_REQ_OK(r)	((r)->status >= 200 && (r)->status < 300)

int	http_request(const char *, http_req_t *);
void	http_req_free(http_req_t *);

#endif
