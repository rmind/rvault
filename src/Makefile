#
# Makefile
#

BIN=		rvault

SYSNAME:=	$(shell uname -s)

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

# New GCC 6/7 flags:
#CFLAGS+=	-Wduplicated-cond -Wmisleading-indentation -Wnull-dereference
#CFLAGS+=	-Wduplicated-branches -Wrestrict

#
# Compiler-specific flags.
#
ifeq ($(CC),gcc)
CFLAGS+=	-Wa,--fatal-warnings -Wl,--fatal-warnings
endif
ifeq ($(CC),clang)
CFLAGS+=	-flto
LDFLAGS+=	-flto
endif

#
# Standard vs debug build flags.
#
ifdef DEBUG
CFLAGS+=	-Og -ggdb -fno-omit-frame-pointer -DDEBUG
CFLAGS+=	-fsanitize=address -fsanitize=undefined
else
CFLAGS+=	-DNDEBUG
endif

#
# System-specific compiler flags.
#

ifeq ($(SYSNAME),Linux)
CFLAGS+=	-D_POSIX_C_SOURCE=200809L
CFLAGS+=	-D_GNU_SOURCE -D_DEFAULT_SOURCE
LDFLAGS+=	-ljemalloc
endif

ifeq ($(SYSNAME),Darwin)
CFLAGS+=	-D__DARWIN_C_LEVEL=__DARWIN_C_FULL
# FIXME/XXX
CFLAGS+=	-I/usr/local/include
CFLAGS+=	-I/usr/local/Cellar/openssl@1.1/1.1.1d/include
LDFLAGS+=	-L/usr/local/Cellar/openssl@1.1/1.1.1d/lib
endif

#
# Linker flags.
#

CFLAGS+=	$(shell pkg-config fuse --cflags)
LDFLAGS+=	$(shell pkg-config fuse --libs)

# TODO: LDFLAGS+=	-lreadline
LDFLAGS+=	-lscrypt
LDFLAGS+=	-lssl -lcrypto

#
# source
#
OBJS+=		core/rvault.o
OBJS+=		core/cli.o
OBJS+=		core/storage.o
OBJS+=		core/fileobj.o
OBJS+=		fuse/rvaultfs.o
OBJS+=		sys/fs.o
OBJS+=		sys/mmap.o
OBJS+=		misc/utils.o

OBJS+=		crypto/common.o
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

LUA_OBJS+=	crypto/common.o
LUA_OBJS+=	crypto/kdf.o
LUA_OBJS+=	crypto/openssl.o
LUA_OBJS+=	sys/fs.o
LUA_OBJS+=	lua/crypto_lua.o

ifeq ($(MAKECMDGOALS),lib)
CFLAGS+=	-fPIC
CFLAGS+=	$(shell pkg-config --cflags lua)
LDFLAGS+=	$(shell pkg-config --cflags --libs lua)
endif

#
# Targets
#

install:	IBINDIR=	$(DESTDIR)/$(BINDIR)
install:	LUA_ILIBDIR=	$(DESTDIR)/$(LUA_LIBDIR)/

all: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $(BIN) $(LDFLAGS)

lib: $(LUA_LIB)

$(LUA_LIB): $(LUA_OBJS)
	$(CC) $(LDFLAGS) -fPIC -shared -o $@ $^

install:
	mkdir -p $(IBINDIR) && install -c $(BIN) $(IBINDIR)

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
	@ for T in lua/*.lua; do echo ./$$T; lua ./$$T; done

#
# Debugging
#

debug: all tests

.PHONY: all debug tests clean
