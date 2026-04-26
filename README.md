# 3ncr (Ruby)

[![Test](https://github.com/3ncr/tokencrypt-ruby/actions/workflows/test.yml/badge.svg)](https://github.com/3ncr/tokencrypt-ruby/actions/workflows/test.yml)
[![Gem Version](https://img.shields.io/gem/v/3ncr.svg)](https://rubygems.org/gems/3ncr)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/3ncr/tokencrypt-ruby/badge)](https://scorecard.dev/viewer/?uri=github.com/3ncr/tokencrypt-ruby)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[3ncr.org](https://3ncr.org/) is a tiny encrypted-string format for config
values, tokens, and app secrets — encrypt a UTF-8 string in one language,
store it as a recognizable value, and decrypt it in another. v1 uses AES-256-GCM for
authenticated encryption with a 12-byte random IV:

```
3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>
```

Encrypted values look like
`3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`.

This is the official Ruby implementation.

## Install

Add to your `Gemfile`:

```ruby
gem "3ncr"
```

Or install directly:

```bash
gem install 3ncr
```

Requires Ruby 3.1+.

## Usage

Pick a constructor based on the entropy of your secret — see the
[3ncr.org v1 KDF guidance](https://3ncr.org/1/#kdf) for the canonical
recommendation.

### Recommended: raw 32-byte key (high-entropy secrets)

If you already have a 32-byte AES-256 key, skip the KDF and pass it directly.

```ruby
require "securerandom"
require "3ncr"

key = SecureRandom.bytes(32) # or load from an env variable / secret store
tc = Threencr::TokenCrypt.from_raw_key(key)
```

For a high-entropy secret that is not already 32 bytes (e.g. a random API
token), hash it through SHA3-256:

```ruby
tc = Threencr::TokenCrypt.from_sha3("some-high-entropy-api-token")
```

### Recommended: Argon2id (passwords / low-entropy secrets)

For passwords or passphrases, use `Threencr::TokenCrypt.from_argon2id`. It
uses the parameters recommended by the
[3ncr.org v1 spec](https://3ncr.org/1/#kdf) (`m=19456 KiB, t=2, p=1`). The salt
must be at least 16 bytes.

```ruby
require "3ncr"

tc = Threencr::TokenCrypt.from_argon2id(
  "correct horse battery staple",
  "0123456789abcdef"
)
```

### Legacy: PBKDF2-SHA3 (existing data only)

This library does not implement the legacy PBKDF2-SHA3 KDF that earlier 3ncr.org
libraries (Go, Node.js, PHP) shipped for backward compatibility. If you need to
decrypt data produced by that KDF, derive the 32-byte key with
`OpenSSL::KDF.pbkdf2_hmac` using `digest: OpenSSL::Digest.new("SHA3-256")`
yourself and pass the result to `from_raw_key`:

```ruby
require "openssl"
require "3ncr"

key = OpenSSL::KDF.pbkdf2_hmac(
  secret,
  salt: salt,
  iterations: iterations,
  length: 32,
  hash: OpenSSL::Digest.new("SHA3-256")
)
tc = Threencr::TokenCrypt.from_raw_key(key)
```

### Encrypt / decrypt

```ruby
plaintext = "08019215-B205-4416-B2FB-132962F9952F"
encrypted = tc.encrypt_3ncr(plaintext)
# e.g. "3ncr.org/1#pHRu..."

tc.decrypt_if_3ncr(encrypted) # => plaintext
```

`decrypt_if_3ncr` returns the input unchanged when it does not start with the
`3ncr.org/1#` header. This makes it safe to route every configuration value
through it regardless of whether it was encrypted.

Decryption failures (bad tag, truncated input, malformed base64) raise
`Threencr::Error`.

## Cross-implementation interop

This implementation decrypts the canonical v1 envelope test vectors shared with
the [Go](https://github.com/3ncr/tokencrypt),
[Node.js](https://github.com/3ncr/nodencrypt),
[PHP](https://github.com/3ncr/tokencrypt-php),
[Python](https://github.com/3ncr/tokencrypt-python),
[Rust](https://github.com/3ncr/tokencrypt-rust),
[Java](https://github.com/3ncr/tokencrypt-java), and
[C#](https://github.com/3ncr/tokencrypt-csharp) reference libraries. The
32-byte AES key behind those vectors was originally derived via PBKDF2-SHA3-256
with `secret = "a"`, `salt = "b"`, `iterations = 1000`; the tests hardcode the
resulting key and verify the AES-256-GCM envelope round-trips exactly. See
`test/test_3ncr.rb`.

## Development

```bash
bundle install
bundle exec rake test
```

## License

MIT — see [LICENSE](LICENSE).
