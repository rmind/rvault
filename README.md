# rvault

[![Build Status](https://travis-ci.org/rmind/rvault.svg?branch=master)](https://travis-ci.org/rmind/rvault)

**rvault** is a secure and authenticated store for secrets (passwords,
keys, certificates) and small documents.  It uses _envelope encryption_
with one-time password (OTP) authentication.  The vault can be operated
as a filesystem in userspace.

It is written in C11 and distributed under the 2-clause BSD license.
Available on: Linux and MacOS.

## Features

Key features and cryptography:
- Envelope encryption with one-time password (OTP) authentication.
- Mounting vault as a filesystem in userspace using FUSE.
- Command line interface (CLI) to operate secrets (and auto-complete for keys).
- scrypt for the key derivation function (KDF); AES 256 or Chacha20 for encryption.
- Authentication with the server using TOTP (RFC 6238).

Small and lightweight code base, easy to audit, has many unit tests,
ASAN and UBSAN enabled, supports different CPU architectures.

## FAQ

#### Would my data be stored or processed remotely?

No, all data is stored and managed locally.  However, your double-encrypted
key is sent and stored on a remote server.  Because of envelope encryption,
your real encryption key is opaque to the server.

#### Can I access my data without Internet connectivity?

You need to authenticate with a remote server in order to access your data,
therefore you need connectivity during that moment.  Once authenticated,
you can work offline.

#### What if my data and passphrase get stolen?

It would still be insufficient to decrypt your data, unless the attacker
actively hacks into your device and reads the key that is resident in-memory.

#### What if the remote server is hacked?

An attacker may retrieve the double-encrypted key, but it would still not
be able to decrypt the data without obtaining your data and passphrase.

The attacker, however, could destroy the keys stored on the server-side.
Hence it is recommended to make a backup of the effective encryption key
and store it safely, e.g. print it on a paper and lock it in a safe.

#### What if I lost my authentication device?

A new authentication device can be set up in place, once user is verified
using other reliable means (e.g. physical identification).

#### What if I would forget my passphrase?

It would be impossible to decrypt the data.

## Caveats

rvault is not designed to be efficient with large files or large quantities
of data.  The files are generally expected to fit in physical memory.  The
application sacrifices performance in favour of security, data integrity and
simplicity.

## Dependencies

- OpenSSL 1.1 or newer
- FUSE (libfuse and system support)
- libcurl
- libreadline
- sqlite3 3.23 or newer with `SQLITE_ENABLE_DESERIALIZE` enabled

## Packages

To build the packages:
* RPM (tested on RHEL/CentOS 8): `cd pkg && make rpm`
* DEB (tested on Debian 11): `cd pkg && make deb`
