--
-- This file is in the Public Domain.
--

local crypto = require("crypto")

function test_crypto(cipher, ae)
  local c = crypto.new(cipher)
  local iv = c:gen_iv()
  local key = c:gen_key()
  local akey = c:gen_key()

  c:set_iv(iv)
  c:set_key(key)
  c:set_auth_key(akey)

  local data = "the quick brown fox jumped over the lazy dog"

  local enc_data, ae_tag = c:encrypt(data, '$')
  assert(enc_data)

  local dec_data = c:decrypt(enc_data, ae_tag, '$')
  assert(dec_data == data)

  dec_data = c:decrypt(enc_data, ae_tag, '!')
  assert(dec_data ~= data)
end

test_crypto("aes-256-cbc")
test_crypto("aes-256-gcm")
test_crypto("chacha20-poly1305")

print("ok")
