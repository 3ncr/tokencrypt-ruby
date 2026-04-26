# frozen_string_literal: true

require "minitest/autorun"
require "securerandom"
require "3ncr"

# Canonical v1 envelope test vectors -- shared with Go, Node, PHP, Python,
# Rust, Java, and C# implementations. The 32-byte AES key was originally
# derived via the legacy PBKDF2-SHA3-256 KDF with secret="a", salt="b",
# iterations=1000; this Ruby library only supports the modern KDFs, so the
# derived key is hardcoded here so we can still verify envelope-level
# interop.
CANONICAL_KEY = ["2f84151869d7d2255d62b3320e97429bde5aac04a0573b2468529a7417515f87"].pack("H*")
CANONICAL_VECTORS = [
  ["a", "3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8"],
  ["test", "3ncr.org/1#Y3/v2PY7kYQgveAn4AJ8zP+oOuysbs5btYLZ9vl8DLc"],
  [
    "08019215-B205-4416-B2FB-132962F9952F",
    "3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ"
  ],
  [
    "перевірка",
    "3ncr.org/1#EPw7S5+BG6hn/9Sjf6zoYUCdwlzweeB+ahBIabUD6NogAcevXszOGHz9Jzv4vQ"
  ]
].freeze

class TestCanonicalVectors < Minitest::Test
  def test_decrypts_canonical_vectors
    tc = Threencr::TokenCrypt.from_raw_key(CANONICAL_KEY)
    CANONICAL_VECTORS.each do |plaintext, encrypted|
      assert_equal plaintext, tc.decrypt_if_3ncr(encrypted)
    end
  end

  def test_round_trip_canonical_plaintexts
    tc = Threencr::TokenCrypt.from_raw_key(CANONICAL_KEY)
    CANONICAL_VECTORS.each do |plaintext, _|
      enc = tc.encrypt_3ncr(plaintext)
      assert enc.start_with?(Threencr::HEADER_V1), "missing v1 header in #{enc}"
      assert_equal plaintext, tc.decrypt_if_3ncr(enc)
    end
  end
end

class TestRoundTripEdgeCases < Minitest::Test
  PLAINTEXTS = [
    "",
    "x",
    "hello, world",
    "08019215-B205-4416-B2FB-132962F9952F",
    "перевірка 🌍 中文 ✓",
    "a" * 4096
  ].freeze

  def test_round_trip
    tc = Threencr::TokenCrypt.from_raw_key(SecureRandom.bytes(32))
    PLAINTEXTS.each do |plaintext|
      assert_equal plaintext, tc.decrypt_if_3ncr(tc.encrypt_3ncr(plaintext))
    end
  end
end

class TestEnvelopePassthrough < Minitest::Test
  def test_non_3ncr_returned_unchanged
    tc = Threencr::TokenCrypt.from_raw_key(SecureRandom.bytes(32))
    assert_equal "plain config value", tc.decrypt_if_3ncr("plain config value")
  end

  def test_empty_string_returned_unchanged
    tc = Threencr::TokenCrypt.from_raw_key(SecureRandom.bytes(32))
    assert_equal "", tc.decrypt_if_3ncr("")
  end
end

class TestIVUniqueness < Minitest::Test
  def test_two_encrypts_differ
    tc = Threencr::TokenCrypt.from_raw_key(SecureRandom.bytes(32))
    a = tc.encrypt_3ncr("same plaintext")
    b = tc.encrypt_3ncr("same plaintext")
    refute_equal a, b
  end
end

class TestTamperDetection < Minitest::Test
  def test_flipped_byte_in_payload_is_rejected
    tc = Threencr::TokenCrypt.from_raw_key(SecureRandom.bytes(32))
    enc = tc.encrypt_3ncr("sensitive value")
    body = enc[Threencr::HEADER_V1.length..]
    idx = body.length / 2
    flip = body[idx] == "A" ? "B" : "A"
    flipped = Threencr::HEADER_V1 + body[0...idx] + flip + body[(idx + 1)..]
    assert_raises(Threencr::Error) { tc.decrypt_if_3ncr(flipped) }
  end

  def test_truncated_payload_is_rejected
    tc = Threencr::TokenCrypt.from_raw_key(SecureRandom.bytes(32))
    assert_raises(Threencr::Error) do
      tc.decrypt_if_3ncr("#{Threencr::HEADER_V1}AAAA")
    end
  end
end

class TestBase64PaddingRobustness < Minitest::Test
  def test_decoder_accepts_padded_input
    tc = Threencr::TokenCrypt.from_raw_key(CANONICAL_KEY)
    plaintext, encrypted = CANONICAL_VECTORS.first
    body = encrypted[Threencr::HEADER_V1.length..]
    padded = body + ("=" * ((-body.length) % 4))
    assert_equal plaintext, tc.decrypt_if_3ncr(Threencr::HEADER_V1 + padded)
  end

  def test_encoder_emits_no_padding
    tc = Threencr::TokenCrypt.from_raw_key(SecureRandom.bytes(32))
    enc = tc.encrypt_3ncr("some value")
    refute_includes enc, "="
  end
end

class TestKDFs < Minitest::Test
  def test_raw_key_requires_32_bytes
    assert_raises(ArgumentError) { Threencr::TokenCrypt.from_raw_key("\x00" * 31) }
    assert_raises(ArgumentError) { Threencr::TokenCrypt.from_raw_key("\x00" * 33) }
  end

  def test_sha3_round_trip
    tc = Threencr::TokenCrypt.from_sha3("some-high-entropy-api-token")
    assert_equal "hello", tc.decrypt_if_3ncr(tc.encrypt_3ncr("hello"))
  end

  def test_sha3_matches_known_vector
    # SHA3-256("a") = 80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b
    expected_key = ["80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b"].pack("H*")
    expected = Threencr::TokenCrypt.from_raw_key(expected_key)
    actual = Threencr::TokenCrypt.from_sha3("a")
    enc = expected.encrypt_3ncr("hello")
    assert_equal "hello", actual.decrypt_if_3ncr(enc)
  end

  def test_argon2id_round_trip
    tc = Threencr::TokenCrypt.from_argon2id(
      "correct horse battery staple", "0123456789abcdef"
    )
    CANONICAL_VECTORS.each do |plaintext, _|
      assert_equal plaintext, tc.decrypt_if_3ncr(tc.encrypt_3ncr(plaintext))
    end
  end

  def test_argon2id_short_salt_rejected
    assert_raises(ArgumentError) do
      Threencr::TokenCrypt.from_argon2id("secret", "short")
    end
  end

  def test_argon2id_wrong_secret_fails
    salt = "0123456789abcdef"
    tc = Threencr::TokenCrypt.from_argon2id("right secret", salt)
    enc = tc.encrypt_3ncr("hello")

    other = Threencr::TokenCrypt.from_argon2id("wrong secret", salt)
    assert_raises(Threencr::Error) { other.decrypt_if_3ncr(enc) }
  end

  def test_argon2id_matches_cross_implementation_key
    # Verify the 3ncr.org-specified Argon2id parameters produce the same
    # 32-byte key as the Python reference implementation. The expected key
    # below was computed from secret="correct horse battery staple",
    # salt="0123456789abcdef" with m=19456, t=2, p=1.
    expected_key = ["832e52b959b967b570ee4781f6c7bda7ced019ca266ac781fd2d94d4e853b0cd"].pack("H*")
    expected = Threencr::TokenCrypt.from_raw_key(expected_key)
    actual = Threencr::TokenCrypt.from_argon2id(
      "correct horse battery staple", "0123456789abcdef"
    )
    enc = expected.encrypt_3ncr("interop check")
    assert_equal "interop check", actual.decrypt_if_3ncr(enc)
  end
end
