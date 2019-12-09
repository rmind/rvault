/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utils.h"

#define	BINARY_SAMPLE_TEXT	"hello world"
#define	BINARY_SAMPLE_HEX	"6865 6c6c 6f20 776f 726c 64"

static const unsigned char binary_sample[] = {
	0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64
};

static void
test_basic_write(void)
{
	ssize_t nbytes;
	char *buf = NULL;
	size_t len;
	FILE *fp;

	fp = open_memstream(&buf, &len);
	assert(fp);

	nbytes = hex_write_wrapped(fp, binary_sample, sizeof(binary_sample));
	assert(nbytes > 0);
	fclose(fp);

	assert(buf != NULL);
	assert(nbytes == sizeof(BINARY_SAMPLE_HEX) - 1);
	assert(strncmp(BINARY_SAMPLE_HEX, buf, nbytes) == 0);
	free(buf);
}

static void
test_basic_read(void)
{
	char *s, *buf;
	size_t len;
	FILE *fp;

	s = strdup(BINARY_SAMPLE_HEX);
	assert(s);

	fp = fmemopen(s, sizeof(BINARY_SAMPLE_HEX), "r");
	assert(fp);

	buf = hex_read_arbitrary(fp, &len);
	assert(len == sizeof(BINARY_SAMPLE_TEXT) - 1);
	assert(strcmp(buf, BINARY_SAMPLE_TEXT) == 0);
	free(buf);

	fclose(fp);
	free(s);
}

static void
test_basic_read_unaligned(void)
{
	char s[] = { '9', '\0' }, *buf;
	size_t len;
	FILE *fp;

	fp = fmemopen(s, sizeof(s), "r");
	assert(fp);

	buf = hex_read_arbitrary(fp, &len);
	assert(buf && len == 1);
	assert(buf[0] == '\t');
	free(buf);
	fclose(fp);
}

int
main(void)
{
	test_basic_write();
	test_basic_read();
	test_basic_read_unaligned();
	return 0;
}
