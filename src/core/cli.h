/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_CLI_H_
#define	_CLI_H_

void		usage_srvurl(bool);
rvault_t *	open_vault(const char *, const char *);
int		sdb_cli(const char *, const char *, int, char **);

#endif
