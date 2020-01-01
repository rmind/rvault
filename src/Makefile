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
CFLAGS+=	-D_POSIX_C_SOURCE=200809L
CFLAGS+=	-D_GNU_SOURCE -D_DEFAULT_SOURCE
endif

ifeq ($(SYSNAME),Darwin)
CFLAGS+=	-D__DARWIN_C_LEVEL=__DARWIN_C_FULL
endif
ifeq ($(SYSNAME),NetBSD)
CFLAGS+=	-D_NETBSD_SOURCE -D_KERNTYPES
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
# Dependencies: compiler flags and libraries to link.
#

SQLITE3_SERIALIZE:=	$(shell echo "\#include <sqlite3.h>\n\
    main() { sqlite3_serialize(NULL, "", NULL, 0);}" | \
    $(CC) -o /dev/null -Werror -xc - \
    >/dev/null 2>/dev/null && echo 1 || echo 0)

ifeq ($(SYSNAME),Darwin)
# FIXME/XXX
CFLAGS+=	-I/usr/local/include
CFLAGS+=	-I/usr/local/Cellar/openssl@1.1/1.1.1d/include
LDFLAGS+=	-L/usr/local/Cellar/openssl@1.1/1.1.1d/lib
endif

ifeq ($(SYSNAME),NetBSD)
LDFLAGS+=	-lrefuse
else
CFLAGS+=	$(shell pkg-config fuse --cflags)
LDFLAGS+=	$(shell pkg-config fuse --libs)
endif

ifeq ($(LIBSCRYPT_KDF),1)
CFLAGS+=	-DLIBSCRYPT_KDF
LDFLAGS+=	-lscrypt-kdf
else
LDFLAGS+=	-lscrypt
endif
LDFLAGS+=	-lssl -lcrypto
LDFLAGS+=	-lcurl -lreadline
ifeq ($(SQLITE3_SERIALIZE),1)
CFLAGS+=	-DSQLITE3_SERIALIZE
LDFLAGS+=	-lsqlite3
endif

#
# source
#
OBJS+=		core/rvault.o
OBJS+=		core/keyauth.o
OBJS+=		core/resolve.o
OBJS+=		core/cli.o
OBJS+=		core/storage.o
OBJS+=		core/fileobj.o
OBJS+=		core/http_req.o
ifeq ($(SQLITE3_SERIALIZE),1)
OBJS+=		core/sdb.o
endif
OBJS+=		fuse/rvaultfs.o
OBJS+=		sys/fs.o
OBJS+=		sys/mmap.o
OBJS+=		misc/utils.o

OBJS+=		crypto/generic.o
OBJS+=		crypto/crypto.o
OBJS+=		crypto/kdf.o
OBJS+=		crypto/openssl.o

#
# libs
#

#
# object files for the tests
#
TEST_OBJS:=	$(shell echo $(OBJS) |			\
		    sed 's:core/cli.o::'		\
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
LUA_OBJS+=	lua/crypto_lua.o

ifeq ($(MAKECMDGOALS),lib)
CFLAGS+=	-fPIC
CFLAGS+=	$(shell pkg-config --cflags lua5.3)
# Override the LDFLAGS
LDFLAGS=	-L/usr/local/Cellar/openssl@1.1/1.1.1d/lib
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
	@ for T in $(TESTS); do echo ./$$T; ./$$T; done

lua-tests:
	@ for T in lua/*.lua; do echo ./$$T; lua5.3 ./$$T; done

#
# Debugging
#

debug: all tests

.PHONY: all debug tests clean
