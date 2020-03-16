/*
 * Copyright (c) 2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_RECOVERY_H_
#define	_RECOVERY_H_

enum {
	RECOVERY_METADATA = 0, RECOVERY_EKEY, RECOVERY_AKEY,
	RECOVERY_NSECTIONS
};

typedef struct {
	void *		buf;
	size_t		bufsize;
	size_t		nbytes;
} rsection_t;

void		rvault_recovery_export(rvault_t *, FILE *);
rsection_t *	rvault_recovery_import(FILE *);
void		rvault_recovery_release(rsection_t *);

#endif
