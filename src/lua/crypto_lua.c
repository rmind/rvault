/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * Lua wrappers for the crypto object.
 *
 * TODO:
 * - Wrap the IV and key into userdata; explicitly zero the key on free.
 * - Perhaps de-duplicate lua_crypto_encrypt() and lua_crypto_decrypt()?
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

/*
 * ENCRYPT/DECRYPT.
 */

static int
lua_crypto_encrypt(lua_State *L)
{
	crypto_lua_t *lctx = lua_crypto_getctx(L);
	size_t datalen, buflen;
	const void *data;
	void *enc_buf;
	ssize_t nbytes;

	data = lua_tolstring(L, 2, &datalen);
	luaL_argcheck(L, data, 2, "binary `string' expected");
	if (datalen == 0) {
		return 0;
	}

	buflen = crypto_get_buflen(lctx->crypto, datalen);
	if ((enc_buf = malloc(buflen)) == NULL) {
		luaL_error(L, "OOM");
		return 0;
	}
	nbytes = crypto_encrypt(lctx->crypto, data, datalen, enc_buf, buflen);
	if (nbytes == -1) {
		free(enc_buf);
		luaL_error(L, "crypto_encrypt failed");
		return 0;
	}
	lua_pushlstring(L, enc_buf, nbytes);
	free(enc_buf);
	return 1;
}

static int
lua_crypto_decrypt(lua_State *L)
{
	crypto_lua_t *lctx = lua_crypto_getctx(L);
	const void *data;
	void *dec_buf;
	size_t datalen;
	ssize_t nbytes;

	data = lua_tolstring(L, 2, &datalen);
	luaL_argcheck(L, data, 2, "binary `string' expected");
	if (datalen == 0) {
		return 0;
	}
	if ((dec_buf = malloc(datalen)) == NULL) {
		luaL_error(L, "OOM");
		return 0;
	}
	nbytes = crypto_decrypt(lctx->crypto, data, datalen, dec_buf, datalen);
	if (nbytes == -1) {
		free(dec_buf);
		luaL_error(L, "crypto_encrypt failed");
		return 0;
	}
	lua_pushlstring(L, dec_buf, nbytes);
	free(dec_buf);
	return 1;
}
