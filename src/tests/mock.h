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

#define	TEST_AAD	"le vif"
#define	TEST_AAD_LEN	(sizeof(TEST_AAD) - 1)

#define	TEST_UUID	"a4fcd889-b7be-404a-ae15-2840c22f4b9a"

int		mock_get_tmpfile(char **);
void		mock_corrupt_byte_at(int, off_t, unsigned char *);

char *		mock_get_vault_dir(void);
void		mock_cleanup_vault_dir(char *);

rvault_t *	mock_get_vault(const char *, char **);
void		mock_cleanup_vault(rvault_t *, char *);

void		mock_vault_fwrite(rvault_t *, const char *, const char *);
void		mock_vault_fcheck(rvault_t *, const char *, const char *);

void *		hex_readmem_arbitrary(const char *, size_t, size_t *);

#endif
