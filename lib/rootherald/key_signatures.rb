# frozen_string_literal: true

require "openssl"

module RootHerald
  # Verifies signatures made by a certified device key, using only OpenSSL.
  #
  # The device signs with the TPM-resident key; the backend checks the
  # signature against the JWK it stored from the attestation
  # (+AttestResult#key+). ECDSA over SHA-256 for P-256 and SHA-384 for P-384.
  # The signature may be either the raw +r||s+ the TPM emits (64 bytes for
  # P-256, 96 for P-384) or ASN.1 DER.
  module KeySignatures
    CURVES = {
      "P-256" => { name: "prime256v1", coordinate: 32, digest: "SHA256" },
      "P-384" => { name: "secp384r1", coordinate: 48, digest: "SHA384" }
    }.freeze

    # @param jwk [Hash] the certified key's public half: kty, crv, x, y
    #   (string or symbol keys)
    # @param message [String] the bytes that were signed (hashed here; do not pre-hash)
    # @param signature [String] raw +r||s+ or DER-encoded ECDSA signature
    # @return [Boolean] true only when the signature verifies; false for any
    #   malformed or non-matching signature — never raises for one
    # @raise [ArgumentError] when the JWK itself is not a P-256 / P-384 EC key
    #   with decodable coordinates
    def self.verify(jwk, message, signature)
      raise ArgumentError, "jwk must be a Hash" unless jwk.is_a?(Hash)

      field = ->(k) { jwk.key?(k) ? jwk[k] : jwk[k.to_sym] }
      raise ArgumentError, "jwk.kty must be EC" unless field.call("kty") == "EC"

      curve = CURVES[field.call("crv")]
      raise ArgumentError, "jwk.crv must be P-256 or P-384" unless curve

      x = coordinate(field.call("x"), "x", curve[:coordinate])
      y = coordinate(field.call("y"), "y", curve[:coordinate])
      key = public_key(curve, x, y)

      signature = signature.to_s.b
      return false if signature.empty?

      digest = OpenSSL::Digest.new(curve[:digest])
      if signature.bytesize == 2 * curve[:coordinate]
        return true if verify_der(key, digest, message, raw_to_der(signature))

        # A DER signature is very unlikely to be exactly this long, but it is
        # possible; try it as DER before giving up.
        return signature.getbyte(0) == 0x30 && verify_der(key, digest, message, signature)
      end

      verify_der(key, digest, message, signature)
    end

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

    def self.coordinate(value, field, length)
      raise ArgumentError, "jwk.#{field} is required" unless value.is_a?(String) && !value.empty?

      std = value.tr("-_", "+/")
      std += "=" * ((4 - (std.length % 4)) % 4)
      decoded = begin
        std.unpack1("m0")
      rescue ArgumentError
        raise ArgumentError, "jwk.#{field} is not base64url"
      end
      raise ArgumentError, "jwk.#{field} is too long for #{length}-byte coordinates" if decoded.bytesize > length

      decoded.rjust(length, "\x00")
    end
    private_class_method :coordinate

    def self.public_key(curve, x, y)
      group = OpenSSL::PKey::EC::Group.new(curve[:name])
      point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new("\x04".b + x + y, 2))
      # Build through DER so this works on OpenSSL 3, where EC keys are immutable.
      spki = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"),
          OpenSSL::ASN1::ObjectId.new(curve[:name])
        ]),
        OpenSSL::ASN1::BitString.new(point.to_octet_string(:uncompressed))
      ])
      OpenSSL::PKey::EC.new(spki.to_der)
    rescue OpenSSL::PKey::PKeyError, OpenSSL::PKey::EC::Point::Error => e
      raise ArgumentError, "jwk is not a usable EC public key: #{e.message}"
    end
    private_class_method :public_key
  end
end
