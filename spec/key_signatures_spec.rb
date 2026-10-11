# frozen_string_literal: true

require "spec_helper"
require "openssl"

# The backend checks device signatures against the JWK it stored from
# certify_key, so the verifier must accept what a TPM emits (raw r||s for
# ECDSA, PKCS#1 v1.5 for RSA) and what most libraries emit (DER), and must
# refuse everything else quietly.
RSpec.describe RootHerald::KeySignatures do
  let(:message) { "transfer 100 to acct-42" }

  def b64url(bytes)
    [bytes].pack("m0").tr("+/", "-_").delete("=")
  end

  def ec_fixture
    key = OpenSSL::PKey::EC.generate("prime256v1")
    octets = key.public_key.to_octet_string(:uncompressed) # 0x04 || x || y
    {
      key: key,
      jwk: { "kty" => "EC", "crv" => "P-256",
             "x" => b64url(octets.byteslice(1, 32)), "y" => b64url(octets.byteslice(33, 32)) }
    }
  end

  def rsa_fixture(bits = 2048)
    key = OpenSSL::PKey::RSA.generate(bits)
    {
      key: key,
      jwk: { "kty" => "RSA", "n" => b64url(key.n.to_s(2)), "e" => b64url(key.e.to_s(2)) }
    }
  end

  def sign_der(f, message)
    f[:key].dsa_sign_asn1(OpenSSL::Digest.new("SHA256").digest(message))
  end

  def sign_rsa(f, message)
    f[:key].sign(OpenSSL::Digest.new("SHA256"), message)
  end

  # DER SEQUENCE { INTEGER r, INTEGER s } to fixed-width r||s.
  def der_to_raw(der, size)
    r, s = OpenSSL::ASN1.decode(der).value.map { |i| i.value.to_s(2) }
    r.rjust(size, "\x00") + s.rjust(size, "\x00")
  end

  it "accepts a DER signature for P-256" do
    f = ec_fixture
    expect(described_class.verify(f[:jwk], message, sign_der(f, message))).to be(true)
  end

  it "accepts a raw r||s signature for P-256" do
    f = ec_fixture
    raw = der_to_raw(sign_der(f, message), 32)
    expect(raw.bytesize).to eq(64)
    expect(described_class.verify(f[:jwk], message, raw)).to be(true)
  end

  it "accepts a symbol-keyed jwk" do
    f = ec_fixture
    jwk = f[:jwk].transform_keys(&:to_sym)
    expect(described_class.verify(jwk, message, sign_der(f, message))).to be(true)
  end

  it "rejects a tampered message" do
    f = ec_fixture
    sig = sign_der(f, message)
    expect(described_class.verify(f[:jwk], "transfer 999 to acct-42", sig)).to be(false)
    expect(described_class.verify(f[:jwk], "transfer 999 to acct-42", der_to_raw(sig, 32))).to be(false)
  end

  it "rejects a tampered signature" do
    f = ec_fixture
    raw = der_to_raw(sign_der(f, message), 32)
    raw.setbyte(10, raw.getbyte(10) ^ 0x01)
    expect(described_class.verify(f[:jwk], message, raw)).to be(false)
  end

  it "rejects a signature from another key" do
    signer = ec_fixture
    other = ec_fixture
    expect(described_class.verify(other[:jwk], message, sign_der(signer, message))).to be(false)
  end

  it "returns false, not an error, for malformed signatures" do
    f = ec_fixture
    ["", "\x30\x01".b, "\x00".b * 64, "\x00".b * 96, "not a signature", nil].each do |sig|
      expect(described_class.verify(f[:jwk], message, sig)).to be(false)
    end
  end

  it "raises ArgumentError for a jwk it cannot use" do
    f = ec_fixture
    good = f[:jwk]
    sig = sign_der(f, message)
    [
      good.merge("kty" => "oct"),
      good.merge("crv" => "P-384"),
      good.merge("crv" => "P-521"),
      good.merge("x" => ""),
      good.merge("x" => "!!not-base64url!!"),
      good.merge("x" => b64url("\x01".b * 33)),
      good.merge("y" => good["x"]), # well-formed coordinates, not a point on the curve
      "not a hash"
    ].each do |jwk|
      expect { described_class.verify(jwk, message, sig) }.to raise_error(ArgumentError), jwk.inspect
    end
  end

  it "re-encodes raw r||s as DER OpenSSL verifies" do
    f = ec_fixture
    raw = der_to_raw(sign_der(f, message), 32)
    digest = OpenSSL::Digest.new("SHA256").digest(message)
    expect(f[:key].dsa_verify_asn1(digest, described_class.raw_to_der(raw))).to be(true)
  end

  # ── RSA-2048, RS256 (PKCS#1 v1.5 over SHA-256) ──

  it "accepts an RS256 signature from an RSA-2048 key" do
    f = rsa_fixture
    sig = sign_rsa(f, message)
    expect(sig.bytesize).to eq(256)
    expect(described_class.verify(f[:jwk], message, sig)).to be(true)
    expect(described_class.verify(f[:jwk].transform_keys(&:to_sym), message, sig)).to be(true)
  end

  it "rejects a tampered RSA message or signature, and another key's signature" do
    f = rsa_fixture
    sig = sign_rsa(f, message)
    expect(described_class.verify(f[:jwk], "transfer 999 to acct-42", sig)).to be(false)
    flipped = sig.dup
    flipped.setbyte(10, flipped.getbyte(10) ^ 0x01)
    expect(described_class.verify(f[:jwk], message, flipped)).to be(false)
    expect(described_class.verify(rsa_fixture[:jwk], message, sig)).to be(false)
  end

  it "returns false for an RSA signature that is not exactly the modulus length" do
    f = rsa_fixture
    sig = sign_rsa(f, message)
    ["", sig + "\x00".b, sig.byteslice(0, 255), "\x00".b * 256, nil].each do |bad|
      expect(described_class.verify(f[:jwk], message, bad)).to be(false)
    end
  end

  it "raises ArgumentError for an RSA jwk below 2048 bits or missing a field" do
    small = rsa_fixture(1024)
    expect { described_class.verify(small[:jwk], message, sign_rsa(small, message)) }
      .to raise_error(ArgumentError, /2048/)
    good = rsa_fixture[:jwk]
    [
      good.reject { |k, _| k == "e" },
      good.merge("n" => ""),
      good.merge("n" => "!!not-base64url!!")
    ].each do |jwk|
      expect { described_class.verify(jwk, message, "x" * 256) }.to raise_error(ArgumentError), jwk.inspect
    end
  end
end
