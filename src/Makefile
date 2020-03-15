#
# This file is in the Public Domain.
#

BIN=		rvault
MANS1=		$(BIN).1

SYSNAME:=	$(shell uname -s)
SYSARCH:=	$(shell uname -m)

ifeq ($(DEBUG),1)
DEBUG=		1
endif
ifeq ($(MAKECMDGOALS),tests)
DEBUG=		1
endif
ifeq ($(MAKECMDGOALS),debug)
DEBUG=		1
endif

USE_OPENSSL?=	1

#
# Common C compiler flags.
#
CFLAGS+=	-std=gnu11 -O2 -g -Wall -Wextra -Werror
CFLAGS+=	-I core/ -I fuse/ -I sys/ -I crypto/ -I lua/ -I misc/

#
# Extended warning flags.
#
CFLAGS+=	-Wno-unknown-warning-option # gcc vs clang

CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CFLAGS+=	-Wmissing-declarations -Wredundant-decls -Wnested-externs
CFLAGS+=	-Wshadow -Wcast-qual -Wcast-align -Wwrite-strings
CFLAGS+=	-Wold-style-definition
CFLAGS+=	-Wsuggest-attribute=noreturn -Wjump-misses-init
CFLAGS+=	-Wduplicated-cond -Wmisleading-indentation -Wnull-dereference
CFLAGS+=	-Wduplicated-branches -Wrestrict

#
# System-specific or compiler-specific flags.
#

ifeq ($(SYSNAME),Linux)
CFLAGS+=	-D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -D_DEFAULT_SOURCE
endif
ifeq ($(SYSNAME),Darwin)
CFLAGS+=	-D__DARWIN_C_LEVEL=__DARWIN_C_FULL
USE_SQLITE?=	yes
endif
ifeq ($(SYSNAME),NetBSD)
CFLAGS+=	-D_NETBSD_SOURCE -D_KERNTYPES
endif
ifeq ($(shell echo $(SYSNAME) | sed 's/-.*//'),CYGWIN_NT)
CFLAGS+=	-D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -D_DEFAULT_SOURCE
CFLAGS+=	-D_FILE_OFFSET_BITS
endif

ifeq ($(CC),gcc)
ifeq ($(SYSNAME),Darwin)
else
CFLAGS+=	-Wa,--fatal-warnings -Wl,--fatal-warnings
endif
CFLAGS+=	-flto
LDFLAGS+=	-flto
endif
ifeq ($(CC),clang)
# TODO: LTO
endif

#
# Standard vs debug build flags.
#
ifdef DEBUG
CFLAGS+=	-Og -ggdb -fno-omit-frame-pointer -DDEBUG
ifeq ($(SYSARCH),x86_64)
CFLAGS+=	-fsanitize=address -fsanitize=undefined
LDFLAGS+=	-fsanitize=address -fsanitize=undefined
endif
else
CFLAGS+=	-DNDEBUG
endif

#
# Sqlite3 needs to be compiled with SQLITE_ENABLE_DESERIALIZE.
#

USE_SQLITE?=	try

ifeq ($(USE_SQLITE),try)
SQLITE3_SERIALIZE:=	$(shell echo '\
    \#include <stdio.h>\n\
    \#include <sqlite3.h>\n\
    int main() { sqlite3_serialize(NULL, "", NULL, 0); return 0; }' | \
    $(CC) $(CFLAGS) -Wno-error -o /dev/null -xc -lsqlite3 - \
    >/dev/null 2>/dev/null && echo 1 || echo 0)
USE_SQLITE=	$(SQLITE3_SERIALIZE)
else ifeq ($(USE_SQLITE),yes)
USE_SQLITE=	1
endif

#
# Dependencies: compiler flags and libraries to link.
#

ifeq ($(SYSNAME),Darwin)
# XXX
CFLAGS+=	-I/usr/local/include
CFLAGS+=	-I/usr/local/opt/openssl@1.1/include
LDFLAGS+=	-L/usr/local/opt/openssl@1.1/lib
endif

ifeq ($(SYSNAME),NetBSD)
LDFLAGS+=	-lrefuse
else
CFLAGS+=	$(shell pkg-config --cflags fuse)
LDFLAGS+=	$(shell pkg-config --libs fuse)
endif

ifeq ($(LIBSCRYPT_KDF),1)
CFLAGS+=	-DLIBSCRYPT_KDF
LDFLAGS+=	-lscrypt-kdf
else
LDFLAGS+=	-lscrypt
endif

ifeq ($(USE_LZ4),1)
CFLAGS+=	-DUSE_LZ4
LDFLAGS+=	$(shell pkg-config --libs liblz4)
endif

ifeq ($(USE_OPENSSL),1)
LDFLAGS+=	-lssl -lcrypto
endif

ifeq ($(USE_MBEDTLS),1)
LDFLAGS+=	-lmbedcrypto
endif

ifeq ($(USE_SODIUM),1)
CFLAGS+=	-DUSE_AE_CIPHERS_ONLY $(shell pkg-config --cflags libsodium)
LDFLAGS+=	$(shell pkg-config --libs libsodium)
endif

LDFLAGS+=	-lcurl

ifeq ($(USE_SQLITE),1)
CFLAGS+=	-DSQLITE3_SERIALIZE
LDFLAGS+=	-lsqlite3 -ledit
endif

#
# source
#
OBJS+=		core/rvault.o
OBJS+=		core/keyauth.o
OBJS+=		core/resolve.o
OBJS+=		core/cli.o
OBJS+=		core/buffer.o
OBJS+=		core/storage.o
OBJS+=		core/fileobj.o
OBJS+=		core/http_req.o
OBJS+=		core/recovery.o
ifeq ($(USE_SQLITE),1)
OBJS+=		core/sdb.o
endif
OBJS+=		fuse/rvaultfs.o
OBJS+=		sys/fs.o
OBJS+=		sys/mmap.o
OBJS+=		misc/utils.o

OBJS+=		crypto/generic.o
OBJS+=		crypto/crypto.o
OBJS+=		crypto/kdf.o
ifeq ($(USE_OPENSSL),1)
OBJS+=		crypto/openssl.o
endif
ifeq ($(USE_MBEDTLS),1)
OBJS+=		crypto/mbedtls.o
endif
ifeq ($(USE_SODIUM),1)
OBJS+=		crypto/sodium.o
endif

#
# libs
#

#
# object files for the tests
#
TEST_OBJS:=	$(shell echo $(OBJS) |			\
		    sed 's:core/cli.o::' |		\
		    sed 's:core/sdb.o::'		\
		)
TEST_OBJS+=	tests/mock.o
TESTS:=		$(patsubst tests/%.c,%,$(wildcard tests/t_*.c))

#
# Lua library
#

LUA_LIB=	crypto.so

LUA_OBJS+=	crypto/generic.o
LUA_OBJS+=	crypto/crypto.o
LUA_OBJS+=	crypto/kdf.o
LUA_OBJS+=	crypto/openssl.o
LUA_OBJS+=	sys/fs.o
LUA_OBJS+=	misc/utils.o
LUA_OBJS+=	lua/crypto_lua.o

ifeq ($(MAKECMDGOALS),lib)
CFLAGS+=	-fPIC
CFLAGS+=	$(shell pkg-config --cflags lua5.3)
# Override the LDFLAGS
LDFLAGS=	-L/usr/local/opt/openssl@1.1/lib
LDFLAGS+=	$(shell pkg-config --cflags --libs lua5.3)
LDFLAGS+=	-lssl -lcrypto -lscrypt
endif

#
# Targets
#

install:	IBINDIR=	$(DESTDIR)/$(BINDIR)
install:	IMAN1DIR=	$(DESTDIR)/$(MANDIR)/man1/
install:	LUA_ILIBDIR=	$(DESTDIR)/$(LUA_LIBDIR)/

all: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $(BIN) $(LDFLAGS)

lib: $(LUA_LIB)

$(LUA_LIB): $(LUA_OBJS)
	$(CC) -fPIC -shared -o $@ $^ $(LDFLAGS)

install:
	mkdir -p $(IBINDIR) && install -c $(BIN) $(IBINDIR)
	mkdir -p $(IMAN1DIR) && install -c $(MANS1) $(IMAN1DIR)

clean:
	rm -f $(BIN) $(OBJS) $(TESTS) $(TEST_OBJS)
	rm -f $(LUA_LIB) $(LUA_OBJS)

#
# Tests
#

t_%: $(TEST_OBJS)
	$(CC) $(CFLAGS) $^ tests/$@.c -o $@ $(LDFLAGS)

tests: $(TESTS)
	@ set -e && for T in $(TESTS); do echo ./$$T; ./$$T; done

lua-tests:
	@ set -e && for T in lua/*.lua; do echo ./$$T; lua5.3 ./$$T; done

#
# Debugging
#

debug: all

.PHONY: all debug tests clean
