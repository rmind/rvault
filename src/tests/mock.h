/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_MOCK_H_
#define	_MOCK_H_

#define	TEST_TEXT	"the quick brown fox jumped over the lazy dog"
#define	TEST_TEXT_LEN	(sizeof(TEST_TEXT) - 1)

#define	TEST_UUID	"a4fcd889-b7be-404a-ae15-2840c22f4b9a"

int		get_tmp_file(void);
void		corrupt_byte_at(int, off_t, unsigned char *);

char *		get_vault_dir(void);
void		cleanup_vault_dir(char *);

rvault_t *	get_vault(const char *, char **);
void		cleanup_vault(rvault_t *, char *);

void *		hex_readmem_arbitrary(const char *, size_t, size_t *);

#endif
