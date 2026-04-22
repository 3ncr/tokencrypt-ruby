# frozen_string_literal: true

require_relative "lib/tokencrypt/version"

Gem::Specification.new do |spec|
  spec.name = "tokencrypt"
  spec.version = Tokencrypt::VERSION
  spec.authors = ["3ncr.org"]
  spec.summary = "Ruby implementation of the 3ncr.org v1 string encryption standard (AES-256-GCM)."
  spec.description = <<~DESC
    A Ruby library for encrypting and decrypting strings in the
    3ncr.org/1#... envelope format (AES-256-GCM with a 12-byte random IV).
    Supports raw 32-byte AES keys, SHA3-256 derivation for high-entropy
    secrets, and Argon2id derivation for low-entropy secrets such as
    passwords.
  DESC
  spec.homepage = "https://3ncr.org/"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"

  spec.metadata = {
    "homepage_uri" => "https://3ncr.org/",
    "source_code_uri" => "https://github.com/3ncr/tokencrypt-ruby",
    "specification_uri" => "https://3ncr.org/1/",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir[
    "lib/**/*.rb",
    "README.md",
    "LICENSE"
  ]
  spec.require_paths = ["lib"]

  spec.add_dependency "argon2id", "~> 0.10"
  spec.add_dependency "base64", "~> 0.2"
end
