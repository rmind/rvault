/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * Lua wrappers for the crypto object.
 *
 * TODO:
 * - Wrap the IV and key into userdata; explicitly zero the key on free.
 */

#include <stdlib.h>
#include <inttypes.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "crypto.h"

int		luaopen_crypto(lua_State *);
static int	lua_crypto_new(lua_State *);
static int	lua_crypto_gc(lua_State *);
static int	lua_crypto_gen_iv(lua_State *);
static int	lua_crypto_gen_key(lua_State *);
static int	lua_crypto_set_iv(lua_State *);
static int	lua_crypto_set_key(lua_State *);
static int	lua_crypto_set_tag(lua_State *);
static int	lua_crypto_get_tag(lua_State *);
static int	lua_crypto_encrypt(lua_State *);
static int	lua_crypto_decrypt(lua_State *);

static const struct luaL_Reg crypto_lib_methods[] = {
	{ "new",		lua_crypto_new		},
	//{ "getrandbytes",	lua_cipher_getrandbytes	},
	{ NULL,			NULL			}
};

static const struct luaL_Reg crypto_methods[] = {
	{ "gen_iv",		lua_crypto_gen_iv	},
	{ "gen_key",		lua_crypto_gen_key	},

	{ "set_iv",		lua_crypto_set_iv	},
	{ "set_key",		lua_crypto_set_key	},
	{ "set_tag",		lua_crypto_set_tag	},

	{ "get_tag",		lua_crypto_get_tag	},

	/* Encrypt/decrypt. */
	{ "encrypt",		lua_crypto_encrypt	},
	{ "decrypt",		lua_crypto_decrypt	},

	{ "__gc",		lua_crypto_gc		},
	{ NULL,			NULL			}
};

#define	CRYPTO_METATABLE	"crypto-obj-methods"

typedef struct {
	crypto_cipher_t	cipher;
	crypto_t *	crypto;
} crypto_lua_t;

int
luaopen_crypto(lua_State *L)
{
	if (luaL_newmetatable(L, CRYPTO_METATABLE)) {
#if LUA_VERSION_NUM >= 502
		luaL_setfuncs(L, crypto_methods, 0);
#else
		luaL_register(L, NULL, crypto_methods);
#endif
		lua_pushliteral(L, "__index");
		lua_pushvalue(L, -2);
		lua_settable(L, -3);

		lua_pushliteral(L, "__metatable");
		lua_pushliteral(L, "must not access this metatable");
		lua_settable(L, -3);
	}
	lua_pop(L, 1);

#if LUA_VERSION_NUM >= 502
	luaL_newlib(L, crypto_lib_methods);
#else
	luaL_register(L, "crypto", crypto_lib_methods);
#endif
	return 1;
}

static int
lua_crypto_new(lua_State *L)
{
	crypto_lua_t *lctx;
	crypto_cipher_t cipher;
	crypto_t *crypto;
	const char *c;

	c = lua_tostring(L, 1);
	luaL_argcheck(L, c, 1, "`string' expected");

	if ((cipher = crypto_cipher_id(c)) == CIPHER_NONE) {
		luaL_error(L, "invalid cipher `%s'");
		return 0;
	}
	if ((crypto = crypto_create(cipher)) == NULL) {
		luaL_error(L, "OOM");
		return 0;
	}
	lctx = (crypto_lua_t *)lua_newuserdata(L, sizeof(crypto_lua_t));
	if (lctx == NULL) {
		crypto_destroy(crypto);
		luaL_error(L, "OOM");
		return 0;
	}
	lctx->cipher = cipher;
	lctx->crypto = crypto;
	luaL_getmetatable(L, CRYPTO_METATABLE);
	lua_setmetatable(L, -2);
	return 1;
}

static crypto_lua_t *
lua_crypto_getctx(lua_State *L)
{
	void *ud = luaL_checkudata(L, 1, CRYPTO_METATABLE);
	luaL_argcheck(L, ud != NULL, 1, "`" CRYPTO_METATABLE "' expected");
	return (crypto_lua_t *)ud;
}

static int
lua_crypto_gc(lua_State *L)
{
	crypto_lua_t *lctx = lua_crypto_getctx(L);
	crypto_destroy(lctx->crypto);
	return 0;
}

/*
 * GENERATION.
 */

static int
lua_crypto_gen_iv(lua_State *L)
{
	crypto_lua_t *lctx = lua_crypto_getctx(L);
	size_t len;
	void *buf;

	buf = crypto_gen_iv(lctx->crypto, &len);
	if (buf == NULL) {
		luaL_error(L, "OOM");
		return 0;
	}
	lua_pushlstring(L, buf, len);
	free(buf);
	return 1;
}

static int
lua_crypto_gen_key(lua_State *L)
{
	crypto_lua_t *lctx = lua_crypto_getctx(L);
	size_t len;
	void *key;

	len = crypto_get_keylen(lctx->crypto);
	if ((key = malloc(len)) == NULL) {
		luaL_error(L, "OOM");
		return 0;
	}
	if (crypto_getrandbytes(key, len) == -1) {
		luaL_error(L, "I/O error");
		free(key);
		return 0;
	}
	lua_pushlstring(L, key, len);
	free(key);
	return 1;
}

/*
 * SETTERS.
 */

static int
lua_crypto_set_iv(lua_State *L)
{
	crypto_lua_t *lctx = lua_crypto_getctx(L);
	const void *buf;
	size_t len;

	buf = lua_tolstring(L, 2, &len);
	luaL_argcheck(L, buf, 2, "binary `string' expected");
	if (crypto_set_iv(lctx->crypto, buf, len) == -1) {
		luaL_error(L, "OOM");
		return 0;
	}
	return 0;
}

static int
lua_crypto_set_key(lua_State *L)
{
	crypto_lua_t *lctx = lua_crypto_getctx(L);
	const void *buf;
	size_t len;

	buf = lua_tolstring(L, 2, &len);
	luaL_argcheck(L, buf, 2, "binary `string' expected");
	if (crypto_set_key(lctx->crypto, buf, len) == -1) {
		luaL_error(L, "OOM");
		return 0;
	}
	return 0;
}

static int
lua_crypto_set_tag(lua_State *L)
{
	crypto_lua_t *lctx = lua_crypto_getctx(L);
	const void *buf;
	size_t len;

	buf = lua_tolstring(L, 2, &len);
	luaL_argcheck(L, buf, 2, "binary `string' expected");
	if (crypto_set_tag(lctx->crypto, buf, len) == -1) {
		luaL_error(L, "OOM");
		return 0;
	}
	return 0;
}

static int
lua_crypto_get_tag(lua_State *L)
{
	crypto_lua_t *lctx = lua_crypto_getctx(L);
	const void *tag;
	size_t len;

	if ((tag = crypto_get_tag(lctx->crypto, &len)) == NULL) {
		return 0;
	}
	lua_pushlstring(L, tag, len);
	return 1;
}

/*
 * ENCRYPT/DECRYPT.
 */

typedef enum { CRYPTO_DO_ENCRYPT, CRYPTO_DO_DECRYPT } crypto_action_t;

static int
lua_crypto_process(lua_State *L, crypto_action_t action)
{
	crypto_lua_t *lctx = lua_crypto_getctx(L);
	size_t dlen, blen;
	const void *data;
	ssize_t nbytes;
	void *buf;

	data = lua_tolstring(L, 2, &dlen);
	luaL_argcheck(L, data, 2, "binary `string' expected");
	if (dlen == 0) {
		return 0;
	}

	blen = crypto_get_buflen(lctx->crypto, dlen);
	if ((buf = malloc(blen)) == NULL) {
		luaL_error(L, "OOM");
		return 0;
	}
	switch (action) {
	case CRYPTO_DO_ENCRYPT:
		nbytes = crypto_encrypt(lctx->crypto, data, dlen, buf, blen);
		break;
	case CRYPTO_DO_DECRYPT:
		nbytes = crypto_decrypt(lctx->crypto, data, dlen, buf, blen);
		break;
	}
	if (nbytes == -1) {
		free(buf);
		luaL_error(L, "%s failed");
		return 0;
	}
	lua_pushlstring(L, buf, nbytes);
	free(buf);
	return 1;
}

static int
lua_crypto_encrypt(lua_State *L)
{
	return lua_crypto_process(L, CRYPTO_DO_ENCRYPT);
}

static int
lua_crypto_decrypt(lua_State *L)
{
	return lua_crypto_process(L, CRYPTO_DO_DECRYPT);
}
