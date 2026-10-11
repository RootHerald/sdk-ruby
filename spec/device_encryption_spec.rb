# frozen_string_literal: true

require "spec_helper"
require "openssl"
require "json"

# The envelope must be exactly what the device's whitelist parser opens: one
# header shape, the header as AAD, a fresh ephemeral key per call; and every
# key that cannot open it is refused before anything is encrypted.
RSpec.describe RootHerald::DeviceEncryption do
  let(:plaintext) { '{"session":"s-1","exp":1893456000}' }

  def b64url(bytes)
    [bytes].pack("m0").tr("+/", "-_").delete("=")
  end

  def decode(value)
    std = value.tr("-_", "+/")
    std += "=" * ((4 - (std.length % 4)) % 4)
    std.unpack1("m0")
  end

  def certified(purpose: "decrypt", alg:, format: "jwe", jwk:)
    RootHerald::Client::CertifiedKey.new(device_id: "dev-alias", key_id: "key-1", purpose: purpose, alg: alg,
                                         format: format, jwk: jwk, hardware_bound: true, certified_at: Time.at(0))
  end

  def with(key, **changes)
    RootHerald::Client::CertifiedKey.new(**key.to_h.merge(changes))
  end

  def ec_fixture
    priv = OpenSSL::PKey::EC.generate("prime256v1")
    octets = priv.public_key.to_octet_string(:uncompressed)
    jwk = { "kty" => "EC", "crv" => "P-256", "x" => b64url(octets.byteslice(1, 32)), "y" => b64url(octets.byteslice(33, 32)) }
    { key: certified(alg: "ECDH-ES", jwk: jwk), priv: priv }
  end

  def rsa_fixture(bits = 2048)
    priv = OpenSSL::PKey::RSA.generate(bits)
    jwk = { "kty" => "RSA", "n" => b64url(priv.n.to_s(2)), "e" => b64url(priv.e.to_s(2)) }
    { key: certified(alg: "RSA-OAEP-256", jwk: jwk), priv: priv }
  end

  # The device's parser in software: a whitelist over the header, fixed
  # sizes, the header as AAD, and the same Concat KDF. Returns nil when the
  # envelope does not open. With strict false the header members are not
  # checked, so an edited header can be tried against the tag.
  def open_envelope(compact, priv, strict: true)
    parts = compact.split(".", -1)
    expect(parts.length).to eq(5)
    header = JSON.parse(decode(parts[0]))
    expect(header["enc"]).to eq("A256GCM")
    iv = decode(parts[2])
    ciphertext = decode(parts[3])
    tag = decode(parts[4])
    expect(iv.bytesize).to eq(12)
    expect(tag.bytesize).to eq(16)

    cek =
      if priv.is_a?(OpenSSL::PKey::EC)
        expect(header.keys).to eq(%w[alg enc epk]) if strict
        expect(header["alg"]).to eq("ECDH-ES")
        expect(parts[1]).to eq("")
        epk = header["epk"]
        expect(epk.keys).to eq(%w[kty crv x y]) if strict
        expect(epk.values_at("kty", "crv")).to eq(%w[EC P-256])
        x = decode(epk["x"])
        y = decode(epk["y"])
        expect(x.bytesize).to eq(32)
        expect(y.bytesize).to eq(32)
        point = OpenSSL::PKey::EC::Point.new(priv.group, OpenSSL::BN.new("\x04".b + x + y, 2))
        described_class.concat_kdf(priv.dh_compute_key(point))
      else
        expect(header.keys).to eq(%w[alg enc]) if strict
        expect(header["alg"]).to eq("RSA-OAEP-256")
        priv.decrypt(decode(parts[1]), rsa_padding_mode: "oaep", rsa_oaep_md: "sha256", rsa_mgf1_md: "sha256")
      end

    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.decrypt
    cipher.key = cek
    cipher.iv = iv
    cipher.auth_tag = tag
    cipher.auth_data = parts[0]
    cipher.update(ciphertext) + cipher.final
  rescue OpenSSL::Cipher::CipherError
    nil
  end

  describe "ECDH-ES" do
    it "differs between two encryptions and both open" do
      f = ec_fixture
      a = described_class.encrypt_to_device(f[:key], plaintext)
      b = described_class.encrypt_to_device(f[:key], plaintext)

      expect(a).not_to eq(b)
      expect(open_envelope(a, f[:priv])).to eq(plaintext)
      expect(open_envelope(b, f[:priv])).to eq(plaintext)
    end

    it "writes a header of exactly alg, enc and epk" do
      parts = described_class.encrypt_to_device(ec_fixture[:key], plaintext).split(".", -1)
      header = decode(parts[0])
      h = JSON.parse(header)

      expect(h.keys).to eq(%w[alg enc epk])
      expect(h["epk"].keys).to eq(%w[kty crv x y])
      expect(header).to eq(%({"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"EC","crv":"P-256","x":"#{h['epk']['x']}","y":"#{h['epk']['y']}"}}))
      expect(decode(h["epk"]["x"]).bytesize).to eq(32)
      expect(decode(h["epk"]["y"]).bytesize).to eq(32)
      expect(parts[1]).to eq("")
      expect(decode(parts[2]).bytesize).to eq(12)
      expect(decode(parts[3]).bytesize).to eq(plaintext.bytesize)
      expect(decode(parts[4]).bytesize).to eq(16)
    end
  end

  describe "RSA-OAEP-256" do
    it "differs between two encryptions and both open" do
      f = rsa_fixture
      a = described_class.encrypt_to_device(f[:key], plaintext)
      b = described_class.encrypt_to_device(f[:key], plaintext)

      expect(a).not_to eq(b)
      expect(open_envelope(a, f[:priv])).to eq(plaintext)
      expect(open_envelope(b, f[:priv])).to eq(plaintext)
    end

    it "writes a header of exactly alg and enc, and wraps with OAEP SHA-256 / MGF1-SHA-256" do
      f = rsa_fixture
      parts = described_class.encrypt_to_device(f[:key], plaintext).split(".", -1)

      expect(decode(parts[0])).to eq('{"alg":"RSA-OAEP-256","enc":"A256GCM"}')
      encrypted_key = decode(parts[1])
      expect(encrypted_key.bytesize).to eq(256)
      cek = f[:priv].decrypt(encrypted_key, rsa_padding_mode: "oaep", rsa_oaep_md: "sha256", rsa_mgf1_md: "sha256")
      expect(cek.bytesize).to eq(32)
      expect do
        f[:priv].decrypt(encrypted_key, rsa_padding_mode: "oaep", rsa_oaep_md: "sha1", rsa_mgf1_md: "sha1")
      end.to raise_error(OpenSSL::PKey::PKeyError)
    end
  end

  describe "the protected header as AAD" do
    it "does not open after the header is edited" do
      [ec_fixture, rsa_fixture].each do |f|
        parts = described_class.encrypt_to_device(f[:key], plaintext).split(".", -1)
        # Equivalent JSON, different bytes: the AAD must be the bytes.
        parts[0] = b64url(decode(parts[0]).sub('"enc":', '"enc": '))
        expect(open_envelope(parts.join("."), f[:priv], strict: false)).to be_nil
      end
    end
  end

  describe "refusals" do
    it "refuses a sign key" do
      dec = ec_fixture[:key]
      [with(dec, purpose: "sign", alg: "ES256", format: nil),
       with(dec, purpose: "sign", alg: "ES256"),
       with(dec, alg: "ES256")].each do |key|
        expect { described_class.encrypt_to_device(key, plaintext) }
          .to raise_error(ArgumentError) { |e| expect(e).not_to be_a(RootHerald::EnvelopeFormatNotSupportedError) }
      end
    end

    it "refuses an apple-ecies key by name" do
      apple = with(ec_fixture[:key], format: "apple-ecies", hardware_bound: false)
      expect { described_class.encrypt_to_device(apple, plaintext) }
        .to raise_error(RootHerald::EnvelopeFormatNotSupportedError) do |e|
          expect(e.format).to eq("apple-ecies")
          expect(e.message).to include("apple-ecies")
          expect(e).to be_a(ArgumentError)
        end
    end

    it "refuses a decrypt key without a format" do
      expect { described_class.encrypt_to_device(with(ec_fixture[:key], format: nil), plaintext) }
        .to raise_error(ArgumentError)
    end

    it "refuses P-384" do
      priv = OpenSSL::PKey::EC.generate("secp384r1")
      octets = priv.public_key.to_octet_string(:uncompressed)
      jwk = { "kty" => "EC", "crv" => "P-384", "x" => b64url(octets.byteslice(1, 48)), "y" => b64url(octets.byteslice(49, 48)) }
      expect { described_class.encrypt_to_device(certified(alg: "ECDH-ES", jwk: jwk), plaintext) }
        .to raise_error(ArgumentError)
    end

    [31, 33].each do |length|
      it "refuses a #{length}-byte coordinate" do
        dec = ec_fixture[:key]
        jwk = dec.jwk.merge("x" => b64url("\x00".b * length))
        expect { described_class.encrypt_to_device(with(dec, jwk: jwk), plaintext) }.to raise_error(ArgumentError)
      end
    end

    it "refuses a point off the curve" do
      dec = ec_fixture[:key]
      y = decode(dec.jwk["y"]).b
      y.setbyte(31, y.getbyte(31) ^ 1)
      expect { described_class.encrypt_to_device(with(dec, jwk: dec.jwk.merge("y" => b64url(y))), plaintext) }
        .to raise_error(ArgumentError)
    end

    it "refuses a short RSA modulus" do
      expect { described_class.encrypt_to_device(rsa_fixture(1024)[:key], plaintext) }.to raise_error(ArgumentError)
    end

    it "refuses a mismatched alg and kty" do
      ec = ec_fixture[:key]
      rsa = rsa_fixture[:key]
      [with(ec, alg: "RSA-OAEP-256"), with(rsa, alg: "ECDH-ES")].each do |key|
        expect { described_class.encrypt_to_device(key, plaintext) }
          .to raise_error(ArgumentError) { |e| expect(e).not_to be_a(RootHerald::EnvelopeFormatNotSupportedError) }
      end
    end
  end

  describe "the seam" do
    it "makes the envelope reproducible" do
      eph = OpenSSL::PKey::EC.generate("prime256v1")
      counting = ->(n) { (1..n).map(&:chr).join.b }
      f = ec_fixture
      a = described_class.encrypt_to_device(f[:key], plaintext, ephemeral: -> { eph }, random: counting)
      b = described_class.encrypt_to_device(f[:key], plaintext, ephemeral: -> { eph }, random: counting)

      expect(a).to eq(b)
      expect(open_envelope(a, f[:priv])).to eq(plaintext)
    end
  end
end
