/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_MOCK_H_
#define	_MOCK_H_

#define	TEST_TEXT	"the quick brown fox jumped over the lazy dog"

int		get_tmp_file(void);
void		corrupt_byte_at(int, off_t, unsigned char *);

char *		get_vault_dir(void);
void		cleanup_vault_dir(char *);

rvault_t *	get_vault(const char *, char **);
void		cleanup_vault(rvault_t *, char *);

#endif
