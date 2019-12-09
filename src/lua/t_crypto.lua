--
-- This file is in the Public Domain.
--

local crypto = require("crypto")

local c = crypto.new("chacha20")
local iv = c:gen_iv()
local key = c:gen_key()

c:set_iv(iv)
c:set_key(key)

local data = "the quick brown fox jumped over the lazy dog"
local enc_data = c:encrypt(data)
local dec_data = c:decrypt(enc_data)

assert(dec_data == data)

print("ok")
