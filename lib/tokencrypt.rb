# frozen_string_literal: true

require "argon2id"
require "base64"
require "openssl"
require "securerandom"

require_relative "tokencrypt/version"

# 3ncr.org v1 string encryption.
#
# Envelope format: +3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>+
# using AES-256-GCM and base64 without padding. The envelope is agnostic of
# how the 32-byte AES key was derived; pick a constructor based on the
# entropy of the input secret.
#
# See https://3ncr.org/1/ for the full specification.
module Tokencrypt
  HEADER_V1 = "3ncr.org/1#"

  AES_KEY_SIZE = 32
  IV_SIZE = 12
  TAG_SIZE = 16

  # 3ncr.org recommended Argon2id parameters (see https://3ncr.org/1/ —
  # Key Derivation section).
  ARGON2ID_MEMORY_KIB = 19_456
  ARGON2ID_TIME_COST = 2
  ARGON2ID_PARALLELISM = 1
  ARGON2ID_MIN_SALT_BYTES = 16

  # Raised when a 3ncr.org value cannot be decoded or decrypted.
  class Error < StandardError; end

  # A 3ncr.org v1 encrypter / decrypter bound to a 32-byte AES key.
  class TokenCrypt
    # Build a TokenCrypt from a raw 32-byte AES-256 key.
    #
    # Use this when your secret is already high-entropy and exactly 32 bytes
    # (for example, loaded from a key-management service).
    def self.from_raw_key(key)
      raise ArgumentError, "key must be a String" unless key.is_a?(String)

      bytes = key.b
      unless bytes.bytesize == AES_KEY_SIZE
        raise ArgumentError, "key must be exactly #{AES_KEY_SIZE} bytes, got #{bytes.bytesize}"
      end

      new(bytes)
    end

    # Derive the AES key from a high-entropy secret via a single SHA3-256
    # hash.
    #
    # Suitable for random pre-shared keys, UUIDs, or long random API tokens —
    # inputs that already carry at least 128 bits of unique entropy. For
    # low-entropy inputs such as user passwords, prefer +from_argon2id+.
    def self.from_sha3(secret)
      bytes = secret.is_a?(String) ? secret.b : String(secret).b
      key = OpenSSL::Digest.new("SHA3-256").digest(bytes)
      new(key)
    end

    # Derive the AES key from a low-entropy secret via Argon2id using the
    # 3ncr.org v1 recommended parameters (m=19456 KiB, t=2, p=1).
    #
    # +salt+ must be at least 16 bytes. For deterministic derivation across
    # implementations, pass the same salt.
    def self.from_argon2id(secret, salt)
      raise ArgumentError, "salt must be a String" unless salt.is_a?(String)

      salt_bytes = salt.b
      if salt_bytes.bytesize < ARGON2ID_MIN_SALT_BYTES
        raise ArgumentError,
              "salt must be at least #{ARGON2ID_MIN_SALT_BYTES} bytes, got #{salt_bytes.bytesize}"
      end

      secret_bytes = secret.is_a?(String) ? secret.b : String(secret).b

      # +Argon2id::Password.create+ generates its own random salt, so we drop
      # to the gem's underlying +hash_encoded+ primitive (private but stable
      # across releases) to derive with our caller-supplied salt. The encoded
      # string is then re-parsed via +Password.new+ to extract the raw
      # +output+ bytes.
      encoded = Argon2id::Password.send(
        :hash_encoded,
        ARGON2ID_TIME_COST,
        ARGON2ID_MEMORY_KIB,
        ARGON2ID_PARALLELISM,
        secret_bytes,
        salt_bytes,
        AES_KEY_SIZE
      )
      key = Argon2id::Password.new(encoded).output
      new(key)
    end

    def initialize(key)
      @key = key
    end

    # Encrypt a UTF-8 string and return a +3ncr.org/1#...+ value.
    def encrypt_3ncr(plaintext)
      raise ArgumentError, "plaintext must be a String" unless plaintext.is_a?(String)

      iv = SecureRandom.bytes(IV_SIZE)
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      cipher.key = @key
      cipher.iv = iv
      ciphertext = cipher.update(plaintext.dup.force_encoding(Encoding::UTF_8)) + cipher.final
      payload = iv + ciphertext + cipher.auth_tag(TAG_SIZE)
      HEADER_V1 + Base64.strict_encode64(payload).delete("=")
    end

    # Decrypt +value+ if it carries the +3ncr.org/1#+ header; otherwise
    # return it unchanged. This makes it safe to route every configuration
    # value through it regardless of whether it was encrypted.
    def decrypt_if_3ncr(value)
      raise ArgumentError, "value must be a String" unless value.is_a?(String)
      return value unless value.start_with?(HEADER_V1)

      decrypt(value[HEADER_V1.length..])
    end

    private

    def decrypt(body)
      # Spec emits no padding; decoders accept both for robustness.
      stripped = body.sub(/=+\z/, "")
      padded = stripped + ("=" * ((-stripped.length) % 4))
      buf = Base64.strict_decode64(padded)
      raise Error, "truncated 3ncr token" if buf.bytesize < IV_SIZE + TAG_SIZE

      iv = buf.byteslice(0, IV_SIZE)
      tag = buf.byteslice(buf.bytesize - TAG_SIZE, TAG_SIZE)
      ciphertext = buf.byteslice(IV_SIZE, buf.bytesize - IV_SIZE - TAG_SIZE)

      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.decrypt
      cipher.key = @key
      cipher.iv = iv
      cipher.auth_tag = tag
      plaintext = cipher.update(ciphertext) + cipher.final
      plaintext.force_encoding(Encoding::UTF_8)
    rescue OpenSSL::Cipher::CipherError
      raise Error, "authentication tag verification failed"
    rescue ArgumentError => e
      raise Error, "invalid base64 payload: #{e.message}"
    end
  end
end
