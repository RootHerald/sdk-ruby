# frozen_string_literal: true

require "spec_helper"
require "openssl"

# The backend checks device signatures against the JWK it stored from the
# attestation, so the verifier must accept what a TPM emits (raw r||s) and
# what most libraries emit (DER), and must refuse everything else quietly.
RSpec.describe RootHerald::KeySignatures do
  let(:message) { "transfer 100 to acct-42" }

  def b64url(bytes)
    [bytes].pack("m0").tr("+/", "-_").delete("=")
  end

  def fixture(crv)
    name, size, digest = crv == "P-256" ? ["prime256v1", 32, "SHA256"] : ["secp384r1", 48, "SHA384"]
    key = OpenSSL::PKey::EC.generate(name)
    octets = key.public_key.to_octet_string(:uncompressed) # 0x04 || x || y
    {
      key: key,
      jwk: { "kty" => "EC", "crv" => crv,
             "x" => b64url(octets.byteslice(1, size)), "y" => b64url(octets.byteslice(1 + size, size)) },
      digest: digest,
      size: size
    }
  end

  def sign_der(f, message)
    f[:key].dsa_sign_asn1(OpenSSL::Digest.new(f[:digest]).digest(message))
  end

  # DER SEQUENCE { INTEGER r, INTEGER s } to fixed-width r||s.
  def der_to_raw(der, size)
    r, s = OpenSSL::ASN1.decode(der).value.map { |i| i.value.to_s(2) }
    r.rjust(size, "\x00") + s.rjust(size, "\x00")
  end

  it "accepts a DER signature for P-256" do
    f = fixture("P-256")
    expect(described_class.verify(f[:jwk], message, sign_der(f, message))).to be(true)
  end

  it "accepts a raw r||s signature for P-256" do
    f = fixture("P-256")
    raw = der_to_raw(sign_der(f, message), f[:size])
    expect(raw.bytesize).to eq(64)
    expect(described_class.verify(f[:jwk], message, raw)).to be(true)
  end

  it "accepts DER and raw for P-384" do
    f = fixture("P-384")
    der = sign_der(f, message)
    expect(described_class.verify(f[:jwk], message, der)).to be(true)
    raw = der_to_raw(der, f[:size])
    expect(raw.bytesize).to eq(96)
    expect(described_class.verify(f[:jwk], message, raw)).to be(true)
  end

  it "accepts a symbol-keyed jwk" do
    f = fixture("P-256")
    jwk = f[:jwk].transform_keys(&:to_sym)
    expect(described_class.verify(jwk, message, sign_der(f, message))).to be(true)
  end

  it "rejects a tampered message" do
    f = fixture("P-256")
    sig = sign_der(f, message)
    expect(described_class.verify(f[:jwk], "transfer 999 to acct-42", sig)).to be(false)
    expect(described_class.verify(f[:jwk], "transfer 999 to acct-42", der_to_raw(sig, 32))).to be(false)
  end

  it "rejects a tampered signature" do
    f = fixture("P-256")
    raw = der_to_raw(sign_der(f, message), 32)
    raw.setbyte(10, raw.getbyte(10) ^ 0x01)
    expect(described_class.verify(f[:jwk], message, raw)).to be(false)
  end

  it "rejects a signature from another key" do
    signer = fixture("P-256")
    other = fixture("P-256")
    expect(described_class.verify(other[:jwk], message, sign_der(signer, message))).to be(false)
  end

  it "returns false, not an error, for malformed signatures" do
    f = fixture("P-256")
    ["", "\x30\x01".b, "\x00".b * 64, "\x00".b * 96, "not a signature", nil].each do |sig|
      expect(described_class.verify(f[:jwk], message, sig)).to be(false)
    end
  end

  it "treats a raw signature of the wrong curve width as false" do
    p256 = fixture("P-256")
    p384 = fixture("P-384")
    raw384 = der_to_raw(sign_der(p384, message), 48)
    expect(described_class.verify(p256[:jwk], message, raw384)).to be(false)
  end

  it "raises ArgumentError for a jwk it cannot use" do
    f = fixture("P-256")
    good = f[:jwk]
    sig = sign_der(f, message)
    [
      good.merge("kty" => "RSA"),
      good.merge("crv" => "P-521"),
      good.merge("x" => ""),
      good.merge("x" => "!!not-base64url!!"),
      good.merge("x" => b64url("\x01".b * 33)),
      good.merge("y" => good["x"]), # well-formed coordinates, not a point on the curve
      "not a hash"
    ].each do |jwk|
      expect { described_class.verify(jwk, message, sig) }.to raise_error(ArgumentError)
    end
  end

  it "re-encodes raw r||s as DER OpenSSL verifies" do
    f = fixture("P-256")
    raw = der_to_raw(sign_der(f, message), 32)
    digest = OpenSSL::Digest.new("SHA256").digest(message)
    expect(f[:key].dsa_verify_asn1(digest, described_class.raw_to_der(raw))).to be(true)
  end
end
