# frozen_string_literal: true

require "openssl"
require "securerandom"

module RootHerald
  # Encrypts to a certified key minted with +Client::KEY_PURPOSE_DECRYPT+,
  # using only OpenSSL.
  #
  # The result is the one JWE compact serialization the device's
  # RootHeraldDecrypt opens: ECDH-ES with the Concat KDF (RFC 7518 §4.6:
  # AlgorithmID the enc name, PartyU and PartyV empty, 256-bit key) and a
  # fresh ephemeral P-256 key per call for an EC key, RSA-OAEP-256 (OAEP
  # SHA-256, MGF1-SHA-256) wrapping a random 32-byte CEK for an RSA key,
  # A256GCM for both with the protected header as the additional data. The
  # header carries alg, enc and (ECDH-ES only) epk, nothing else, because the
  # device refuses any other member rather than ignoring it.
  #
  # Encryption uses the public half, so anyone holding the JWK can encrypt to
  # the device; what the chip guarantees is that only it can open the result.
  module DeviceEncryption
    FORMAT_JWE = "jwe"
    ALG_ECDH_ES = "ECDH-ES"
    ALG_RSA_OAEP_256 = "RSA-OAEP-256"
    ENC = "A256GCM"
    COORDINATE_BYTES = 32
    IV_BYTES = 12
    TAG_BYTES = 16
    CEK_BYTES = 32
    MIN_RSA_MODULUS_BITS = 2048

    # @param key [Client::CertifiedKey] the decrypt key, as +Client#certify_key+ returned it
    # @param plaintext [String] the bytes only the device may read
    # @param ephemeral [Proc, nil] the seam the known-answer tests inject the
    #   ephemeral P-256 key through; returns an +OpenSSL::PKey::EC+ private key
    # @param random [Proc, nil] the seam for the CEK (32 bytes, RSA only) and
    #   then the IV (12 bytes); takes a byte count
    # @return [String] the JWE compact serialization to send to the device
    # @raise [ArgumentError] for a key that cannot open the result: a sign
    #   key, a key without a format, a curve other than P-256, a coordinate
    #   that is not 32 bytes, or an RSA modulus under 2048 bits
    # @raise [EnvelopeFormatNotSupportedError] for an apple-ecies key, which a
    #   macOS enclave opens and needs an Apple-side encryptor
    def self.encrypt_to_device(key, plaintext, ephemeral: nil, random: nil)
      ephemeral ||= -> { OpenSSL::PKey::EC.generate("prime256v1") }
      random ||= ->(n) { SecureRandom.random_bytes(n) }
      purpose = key.purpose
      unless purpose == Client::KEY_PURPOSE_DECRYPT
        raise ArgumentError, "key purpose is #{purpose.inspect}; only a decrypt key opens an envelope"
      end
      raise ArgumentError, "key has no envelope format; a decrypt key names jwe or apple-ecies" if key.format.nil?
      raise EnvelopeFormatNotSupportedError, key.format unless key.format == FORMAT_JWE

      jwk = key.jwk
      raise ArgumentError, "key.jwk must be a Hash" unless jwk.is_a?(Hash)

      field = ->(k) { jwk.key?(k) ? jwk[k] : jwk[k.to_sym] }
      kty = field.call("kty")
      if kty == "EC" && key.alg == ALG_ECDH_ES
        encrypt_ecdh_es(field, plaintext.to_s.b, ephemeral, random)
      elsif kty == "RSA" && key.alg == ALG_RSA_OAEP_256
        encrypt_rsa_oaep(field, plaintext.to_s.b, random)
      else
        raise ArgumentError,
              "key alg #{key.alg.inspect} with kty #{kty.inspect} is not ECDH-ES on an EC key or RSA-OAEP-256 on an RSA key"
      end
    end

    def self.encrypt_ecdh_es(field, plaintext, ephemeral, random)
      crv = field.call("crv")
      raise ArgumentError, "jwk.crv #{crv.inspect} is not P-256; no device certifies another curve" unless crv == "P-256"

      x = coordinate(field.call("x"), "x")
      y = coordinate(field.call("y"), "y")
      recipient = KeySignatures.ec_public_key(x, y)

      eph = ephemeral.call
      z = eph.dh_compute_key(recipient.public_key)
      raise ArgumentError, "jwk is not a usable P-256 public key" unless z.bytesize == COORDINATE_BYTES

      cek = concat_kdf(z)
      epk = eph.public_key.to_octet_string(:uncompressed) # 0x04 || X || Y, each at the curve width
      header = %({"alg":"#{ALG_ECDH_ES}","enc":"#{ENC}","epk":{"kty":"EC","crv":"P-256",) +
               %("x":"#{b64url(epk.byteslice(1, COORDINATE_BYTES))}",) +
               %("y":"#{b64url(epk.byteslice(1 + COORDINATE_BYTES, COORDINATE_BYTES))}"}})
      seal(header, "", cek, plaintext, random)
    rescue OpenSSL::PKey::PKeyError, OpenSSL::PKey::EC::Point::Error => e
      raise ArgumentError, "jwk is not a usable P-256 public key: #{e.message}"
    end
    private_class_method :encrypt_ecdh_es

    def self.encrypt_rsa_oaep(field, plaintext, random)
      n = OpenSSL::BN.new(decode_base64url(field.call("n"), "n"), 2)
      e = OpenSSL::BN.new(decode_base64url(field.call("e"), "e"), 2)
      if n.num_bits < MIN_RSA_MODULUS_BITS
        raise ArgumentError, "jwk.n must be a modulus of at least #{MIN_RSA_MODULUS_BITS} bits (got #{n.num_bits})"
      end

      recipient = KeySignatures.rsa_public_key(n, e)
      cek = random.call(CEK_BYTES)
      encrypted_key = recipient.encrypt(cek, rsa_padding_mode: "oaep", rsa_oaep_md: "sha256", rsa_mgf1_md: "sha256")
      header = %({"alg":"#{ALG_RSA_OAEP_256}","enc":"#{ENC}"})
      seal(header, encrypted_key, cek, plaintext, random)
    end
    private_class_method :encrypt_rsa_oaep

    def self.seal(header, encrypted_key, cek, plaintext, random)
      protected_header = b64url(header)
      iv = random.call(IV_BYTES)
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      cipher.key = cek
      cipher.iv = iv
      cipher.auth_data = protected_header
      ciphertext = cipher.update(plaintext) + cipher.final
      tag = cipher.auth_tag(TAG_BYTES)
      [protected_header, b64url(encrypted_key), b64url(iv), b64url(ciphertext), b64url(tag)].join(".")
    end
    private_class_method :seal

    # Concat KDF, one round: SHA-256(counter ‖ Z ‖ AlgorithmID ‖ PartyUInfo ‖
    # PartyVInfo ‖ SuppPubInfo), each info field length-prefixed, keydatalen 256.
    def self.concat_kdf(z)
      OpenSSL::Digest.new("SHA256").digest(
        [1].pack("N") + z + [ENC.bytesize].pack("N") + ENC + [0].pack("N") + [0].pack("N") + [256].pack("N")
      )
    end

    def self.coordinate(value, field)
      raw = decode_base64url(value, field)
      unless raw.bytesize == COORDINATE_BYTES
        raise ArgumentError, "jwk.#{field} must decode to exactly #{COORDINATE_BYTES} bytes (got #{raw.bytesize})"
      end

      raw
    end
    private_class_method :coordinate

    def self.decode_base64url(value, field)
      raise ArgumentError, "jwk.#{field} is required" unless value.is_a?(String) && !value.empty?

      std = value.tr("-_", "+/")
      std += "=" * ((4 - (std.length % 4)) % 4)
      std.unpack1("m0")
    rescue ArgumentError
      raise ArgumentError, "jwk.#{field} is not base64url"
    end
    private_class_method :decode_base64url

    def self.b64url(bytes)
      [bytes].pack("m0").tr("+/", "-_").delete("=")
    end
    private_class_method :b64url
  end
end
