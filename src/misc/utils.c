/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <sys/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>
#include <err.h>

#include "sys.h"
#include "utils.h"

#define	BUF_SIZE		(1024)
#define	BUF_GROW_SIZE		(1024)

/*
 * hex_write: print the binary buffer.
 */
ssize_t
hex_write(FILE *stream, const void *buf, size_t len)
{
	const uint8_t *b = buf;
	size_t nbytes = 0;

	while (len--) {
		int ret;

		if ((ret = fprintf(stream, "%02x", *b)) < 0) {
			return -1;
		}
		nbytes += ret;
		b++;
	}
	fflush(stream);
	return nbytes;
}

char *
hex_write_str(const void *buf, size_t len)
{
	char *str = NULL;
	size_t slen;
	FILE *fp;

	if ((fp = open_memstream(&str, &slen)) == NULL) {
		return NULL;
	}
	if (hex_write(fp, buf, len) == -1) {
		fclose(fp);
		free(str);
		return NULL;
	}
	fclose(fp);
	return str;
}

/*
 * hex_write_wrapped: print the binary buffer data in hex blocks.
 */
ssize_t
hex_write_wrapped(FILE *stream, const void *buf, size_t len)
{
	const uint8_t *b = buf;
	unsigned long n = 0;
	size_t nbytes = 0;
	int ret;

	/*
	 * Settings:
	 * - Block of 4 hex characters (2 bytes) and a space.
	 * - Up to 12 blocks per row, so they fit in 76 columns.
	 */
	while (len >= 2) {
		const char endb = (++n % 12 == 0) ? '\n' : ' ';

		ret = fprintf(stream, "%02x %02x%c", b[0], b[1], endb);
		if (ret < 0) {
			return -1;
		}
		nbytes += ret;
		len -= 2;
		b += 2;
	}
	if (len) {
		if ((ret = fprintf(stream, "%02x", *b)) < 0) {
			return -1;
		}
		nbytes += ret;
	}
	fflush(stream);
	return nbytes;
}

/*
 * hex_read_arbitrary: consume arbitrary hex text i.e. any characters in
 * the range of 0..F (either lower or upper case).
 */
void *
hex_read_arbitrary(FILE *stream, size_t *outlen)
{
	size_t alloc_len = 0, nbytes = 0;
	uint8_t *buf = NULL;

	while (!feof(stream)) {
		uint8_t tmpbuf[BUF_SIZE];
		bool hf = false;
		size_t len;

		/*
		 * Grow the buffer as we go.
		 */
		if ((alloc_len - nbytes) < BUF_SIZE) {
			void *nbuf;

			alloc_len += BUF_GROW_SIZE;
			if ((nbuf = calloc(1, alloc_len)) == NULL) {
				free(buf);
				return NULL;
			}
			if (buf) {
				memcpy(nbuf, buf, nbytes);
				free(buf);
			}
			buf = nbuf;
		}

		/*
		 * Consume a block of data.  Read any hex characters
		 * and push bytes.
		 */
		if ((len = fread(tmpbuf, 1, BUF_SIZE, stream)) == 0) {
			break;
		}
		for (unsigned i = 0; i < len; i++) {
			unsigned char halfb = tolower((unsigned char)tmpbuf[i]);

			if (!isxdigit(halfb)) {
				continue;
			}
			halfb -= (halfb >= 'a') ? ('a' - 10) : '0';
			if (hf) {
				const size_t prev = nbytes - 1;
				buf[prev] = (buf[prev] << 4) | halfb;
			} else {
				buf[nbytes] = halfb;
				nbytes++;
			}
			hf = !hf;
		}
	}
	*outlen = nbytes;
	return buf;
}

void *
hex_read_arbitrary_buf(const void *buf, size_t len, size_t *outlen)
{
	void *rbuf;
	FILE *fp;

	if ((fp = fmemopen(__UNCONST(buf), len, "r")) == NULL) {
		return NULL;
	}
	rbuf = hex_read_arbitrary(fp, outlen);
	fclose(fp);
	return rbuf;
}

/*
 * PID file related helpers.
 */

static char *		pid_file = NULL;
static int		pid_file_fd = -1;

static void
cleanup_pid(void)
{
	if (pid_file) {
		close(pid_file_fd);
		unlink(pid_file);
		free(pid_file);
	}
}

void
setup_pid(const char *fmt, ...)
{
	va_list ap;
	ssize_t ret;
	int fd;

	va_start(ap, fmt);
	ret = vasprintf(&pid_file, fmt, ap);
	va_end(ap);
	if (ret == -1) {
		err(EXIT_FAILURE, "malloc");
	}

	if ((fd = open(pid_file, O_CREAT | O_RDWR, 0644)) == -1) {
		err(EXIT_FAILURE, "failed to create pid file `%s'", pid_file);
	}
	ret = flock(fd, LOCK_EX | LOCK_NB);
	if (ret == -1 && errno != EWOULDBLOCK) {
		err(EXIT_FAILURE, "flock");
	}
	if (ret) {
		char pid_buf[64];

		fs_read(fd, pid_buf, sizeof(pid_buf));
		pid_buf[sizeof(pid_buf) - 1] = '\0';
		close(fd);

		errx(EXIT_FAILURE,
		    "another process is already running with the vault "
		    "mounted.\nCheck the process ID (PID): %s", pid_buf
		);
	}
	if (ftruncate(fd, 0) == -1) {
		err(EXIT_FAILURE, "ftruncate");
	}
	dprintf(fd, "%d\n", getpid());
	fsync(fd);

	/*
	 * Hold the file descriptor and the lock until exit.
	 */
	if (atexit(cleanup_pid) == -1) {
		err(EXIT_FAILURE, "atexit");
	}
	pid_file_fd = fd;
}

/*
 * tmpfile_get_name: create a temporary file name for a given file path,
 * returning a path within the same directory.
 */
char *
tmpfile_get_name(const char *path)
{
	char *tpath = NULL, *cpath;
	ssize_t ret;

	if ((cpath = strdup(path)) == NULL) {
		return NULL;
	}
	ret = asprintf(&tpath, "%s/.%s.%ju.%u",
	    dirname(cpath), basename(cpath),
	    (uintmax_t)time(NULL), (unsigned)getpid());
	free(cpath);

	return ret == -1 ? NULL : tpath;
}

/*
 * String helpers.
 */

unsigned
str_tokenize(char *line, char **tokens, unsigned n)
{
	const char *sep = " \t";
	unsigned i = 0;
	char *token;

	while ((token = strsep(&line, sep)) != NULL && i < n) {
		if (*sep == '\0' || strpbrk(token, sep) != NULL) {
			continue;
		}
		tokens[i++] = token;
	}
	return i;
}

/*
 * Logging facility.
 */

static int		app_log_level = LOG_WARNING;
static FILE *		app_log_errfh = NULL;
static __thread char	app_log_buf[64 * 1024];

void
app_setlog(int level)
{
	app_log_level = level;
}

int
app_set_errorfile(const char *fmt, ...)
{
	char path[PATH_MAX];
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(path, sizeof(path), fmt, ap);
	va_end(ap);

	if (ret == -1 || (app_log_errfh = fopen(path, "a")) == NULL) {
		return -1;
	}
	return 0;
}

static void
app_log_fwrite(int level, const char *msg)
{
	FILE *fp = (level <= LOG_ERR) ? stderr : stdout;

	fprintf(fp, "%s\n", msg);
	if (level <= LOG_ERR && app_log_errfh) {
		const time_t now = time(NULL);
		struct tm tm;
		char time[64];

		localtime_r(&now, &tm);
		strftime(time, sizeof(time), "%d/%b/%Y:%H:%M:%S %z", &tm);
		fprintf(app_log_errfh, "[%s] %s\n", time, msg);
	}
}

void
app_log(int level, const char *fmt, ...)
{
	va_list ap;

	if (level > app_log_level) {
		return;
	}
	va_start(ap, fmt);
	vsnprintf(app_log_buf, sizeof(app_log_buf), fmt, ap);
	va_end(ap);

	app_log_fwrite(level, app_log_buf);
}

void
app_elog(int level, const char *fmt, ...)
{
	const int errno_saved = errno;
	ssize_t ret;
	va_list ap;

	if (level > app_log_level) {
		return;
	}
	va_start(ap, fmt);
	ret = vsnprintf(app_log_buf, sizeof(app_log_buf), fmt, ap);
	va_end(ap);

	if (ret < 0 || (size_t)ret >= sizeof(app_log_buf) ||
	    snprintf(app_log_buf + ret, sizeof(app_log_buf) - ret,
	    ": %s\n", strerror(errno_saved)) == -1) {
		return; // error;
	}
	app_log_fwrite(level, app_log_buf);
}
