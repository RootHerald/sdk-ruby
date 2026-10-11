# frozen_string_literal: true

require "openssl"

module RootHerald
  # Verifies signatures made by a certified device key, using only OpenSSL.
  #
  # The device signs with the key its chip holds; the backend checks the
  # signature against the JWK it stored from +Client#certify_key+. The key is
  # ECC P-256 or RSA-2048, chosen by the device. An EC key checks ES256
  # (ECDSA over SHA-256), with the signature either the raw +r||s+ the TPM
  # emits (64 bytes) or ASN.1 DER; an RSA key checks RS256 (PKCS#1 v1.5 over
  # SHA-256), with the signature exactly the modulus length (256 bytes for
  # RSA-2048).
  #
  # A signature proves possession of the key at that moment, not how the
  # machine booted; run an attest challenge for that.
  module KeySignatures
    CURVE_NAME = "prime256v1"
    COORDINATE_BYTES = 32
    MIN_RSA_MODULUS_BITS = 2048

    # @param jwk [Hash] the certified key's public half: kty, crv, x, y (EC)
    #   or kty, n, e (RSA); string or symbol keys
    # @param message [String] the bytes that were signed (hashed here; do not pre-hash)
    # @param signature [String] raw +r||s+ or DER-encoded ECDSA signature, or
    #   a PKCS#1 v1.5 RSA signature
    # @return [Boolean] true only when the signature verifies; false for any
    #   malformed or non-matching signature — never raises for one
    # @raise [ArgumentError] when the JWK itself is not a P-256 EC key or an
    #   RSA key of at least 2048 bits with decodable fields
    def self.verify(jwk, message, signature)
      raise ArgumentError, "jwk must be a Hash" unless jwk.is_a?(Hash)

      field = ->(k) { jwk.key?(k) ? jwk[k] : jwk[k.to_sym] }
      signature = signature.to_s.b
      digest = OpenSSL::Digest.new("SHA256")

      case field.call("kty")
      when "EC" then verify_ec(field, digest, message, signature)
      when "RSA" then verify_rsa(field, digest, message, signature)
      else raise ArgumentError, "jwk.kty must be EC or RSA"
      end
    end

    def self.verify_ec(field, digest, message, signature)
      raise ArgumentError, "jwk.crv must be P-256" unless field.call("crv") == "P-256"

      x = coordinate(field.call("x"), "x")
      y = coordinate(field.call("y"), "y")
      key = ec_public_key(x, y)
      return false if signature.empty?

      if signature.bytesize == 2 * COORDINATE_BYTES
        return true if verify_der(key, digest, message, raw_to_der(signature))

        # A DER signature is very unlikely to be exactly this long, but it is
        # possible; try it as DER before giving up.
        return signature.getbyte(0) == 0x30 && verify_der(key, digest, message, signature)
      end

      verify_der(key, digest, message, signature)
    end
    private_class_method :verify_ec

    def self.verify_rsa(field, digest, message, signature)
      n = OpenSSL::BN.new(decode_base64url(field.call("n"), "n"), 2)
      e = OpenSSL::BN.new(decode_base64url(field.call("e"), "e"), 2)
      raise ArgumentError, "jwk.n must be at least #{MIN_RSA_MODULUS_BITS} bits" if n.num_bits < MIN_RSA_MODULUS_BITS

      key = rsa_public_key(n, e)
      return false if signature.bytesize != (n.num_bits + 7) / 8

      key.verify(digest, signature, message.to_s.b)
    rescue OpenSSL::PKey::PKeyError
      false
    end
    private_class_method :verify_rsa

    # Encode raw +r||s+ as the DER +SEQUENCE { INTEGER r, INTEGER s }+ OpenSSL expects.
    def self.raw_to_der(raw)
      half = raw.bytesize / 2
      r = OpenSSL::BN.new(raw.byteslice(0, half), 2)
      s = OpenSSL::BN.new(raw.byteslice(half, half), 2)
      OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(r), OpenSSL::ASN1::Integer.new(s)]).to_der
    end

    def self.verify_der(key, digest, message, der)
      key.dsa_verify_asn1(digest.digest(message.to_s.b), der)
    rescue OpenSSL::PKey::PKeyError
      # Malformed DER, r/s out of range: all "not verified".
      false
    end
    private_class_method :verify_der

    def self.decode_base64url(value, field)
      raise ArgumentError, "jwk.#{field} is required" unless value.is_a?(String) && !value.empty?

      std = value.tr("-_", "+/")
      std += "=" * ((4 - (std.length % 4)) % 4)
      std.unpack1("m0")
    rescue ArgumentError
      raise ArgumentError, "jwk.#{field} is not base64url"
    end
    private_class_method :decode_base64url

    def self.coordinate(value, field)
      decoded = decode_base64url(value, field)
      if decoded.bytesize > COORDINATE_BYTES
        raise ArgumentError, "jwk.#{field} is too long for #{COORDINATE_BYTES}-byte coordinates"
      end

      decoded.rjust(COORDINATE_BYTES, "\x00")
    end
    private_class_method :coordinate

    # Keys are built through SubjectPublicKeyInfo DER: on OpenSSL 3 a pkey is
    # immutable once created, so its components cannot be assigned. A point off
    # the curve is refused when OpenSSL parses it.
    # @api private
    def self.ec_public_key(x, y)
      group = OpenSSL::PKey::EC::Group.new(CURVE_NAME)
      point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new("\x04".b + x + y, 2))
      spki = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"),
          OpenSSL::ASN1::ObjectId.new(CURVE_NAME)
        ]),
        OpenSSL::ASN1::BitString.new(point.to_octet_string(:uncompressed))
      ])
      OpenSSL::PKey::EC.new(spki.to_der)
    rescue OpenSSL::PKey::PKeyError, OpenSSL::PKey::EC::Point::Error => e
      raise ArgumentError, "jwk is not a usable EC public key: #{e.message}"
    end
    # @api private
    def self.rsa_public_key(n, e)
      rsa_key = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(n), OpenSSL::ASN1::Integer.new(e)])
      spki = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new("rsaEncryption"), OpenSSL::ASN1::Null.new(nil)]),
        OpenSSL::ASN1::BitString.new(rsa_key.to_der)
      ])
      OpenSSL::PKey::RSA.new(spki.to_der)
    rescue OpenSSL::PKey::PKeyError => e
      raise ArgumentError, "jwk is not a usable RSA public key: #{e.message}"
    end
  end
end
