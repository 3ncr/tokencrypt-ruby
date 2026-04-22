# tokencrypt (3ncr.org)

Ruby implementation of the [3ncr.org](https://3ncr.org/) v1 string encryption
standard.

3ncr.org is a small, interoperable format for encrypted strings, originally
intended for encrypting tokens in configuration files but usable for any UTF-8
string. v1 uses AES-256-GCM with a 12-byte random IV:

```
3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>
```

Encrypted values look like
`3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`.

## Install

Add to your `Gemfile`:

```ruby
gem "tokencrypt"
```

Or install directly:

```bash
gem install tokencrypt
```

Requires Ruby 3.1+.

## Usage

Pick a constructor based on the entropy of your secret.

### Recommended: Argon2id (low-entropy secrets)

For passwords or passphrases, use `TokenCrypt.from_argon2id`. It uses the
parameters recommended by the [3ncr.org v1 spec](https://3ncr.org/1/#kdf)
(m=19456 KiB, t=2, p=1). Salt must be at least 16 bytes.

```ruby
require "tokencrypt"

tc = Tokencrypt::TokenCrypt.from_argon2id(
  "correct horse battery staple",
  "0123456789abcdef"
)
```

### Recommended: raw 32-byte key (high-entropy secrets)

If you already have a 32-byte AES-256 key, skip the KDF and pass it directly.

```ruby
require "securerandom"
require "tokencrypt"

key = SecureRandom.bytes(32) # or load from an env variable / secret store
tc = Tokencrypt::TokenCrypt.from_raw_key(key)
```

For a high-entropy secret that is not already 32 bytes (e.g. a random API
token), hash it through SHA3-256:

```ruby
tc = Tokencrypt::TokenCrypt.from_sha3("some-high-entropy-api-token")
```

This library does not implement the legacy PBKDF2-SHA3 KDF that earlier 3ncr.org
libraries used for backward compatibility. If you need to decrypt data produced
by that KDF, derive the 32-byte key with
`OpenSSL::KDF.pbkdf2_hmac(secret, salt: salt, iterations: iterations, length: 32, hash: "SHA3-256")`
yourself and pass it to `from_raw_key`.

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
`Tokencrypt::Error`.

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
`test/test_tokencrypt.rb`.

## Development

```bash
bundle install
bundle exec rake test
```

## License

MIT
