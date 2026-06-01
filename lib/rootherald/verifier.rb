# frozen_string_literal: true

require "jwt"

module RootHerald
  # Verifies Root Herald composite attestation token JWTs.
  class Verifier
    ALLOWED_ALGORITHMS = %w[RS256 ES256].freeze
    EXPECTED_EAT_PROFILE = "tag:rootherald.io,2026:tpm20-v1"

    # @param issuer [String]
    # @param jwks [JwksFetcher]
    # @param audience [String, nil]
    # @param leeway_seconds [Integer]
    def initialize(issuer:, jwks:, audience: nil, leeway_seconds: 5)
      raise ArgumentError, "issuer is required" if issuer.nil? || issuer.empty?

      @issuer = issuer
      @jwks = jwks
      @audience = audience
      @leeway = leeway_seconds
    end

    # @param token [String] compact JWT
    # @return [AttestationClaims]
    # @raise [VerificationError, TokenExpiredError]
    def verify(token)
      header = decode_header(token)
      kid = header["kid"].to_s
      raise VerificationError, "JWT header missing 'kid'" if kid.empty?

      alg = header["alg"].to_s
      unless ALLOWED_ALGORITHMS.include?(alg)
        raise VerificationError, "Unsupported JWT alg=#{alg.inspect}; allowed: #{ALLOWED_ALGORITHMS}"
      end

      key = begin
        @jwks.get_key(kid)
      rescue JwksError => e
        raise VerificationError, "JWKS lookup failed: #{e.message}"
      end

      decode_options = {
        algorithm: alg,
        iss: @issuer,
        verify_iss: true,
        leeway: @leeway
      }
      if @audience
        decode_options[:aud] = @audience
        decode_options[:verify_aud] = true
      end

      begin
        payload, = JWT.decode(token, key, true, decode_options)
      rescue JWT::ExpiredSignature => e
        raise TokenExpiredError, e.message
      rescue JWT::InvalidIssuerError => e
        raise VerificationError, "Issuer mismatch: #{e.message}"
      rescue JWT::InvalidAudError => e
        raise VerificationError, "Audience mismatch: #{e.message}"
      rescue JWT::VerificationError, JWT::DecodeError => e
        raise VerificationError, "JWT validation failed: #{e.message}"
      end

      validate_schema(payload)
      AttestationClaims.from_payload(payload)
    end

    private

    def decode_header(token)
      raise VerificationError, "Token is not a compact JWT" unless token.is_a?(String) && token.count(".") == 2

      JSON.parse(JWT::Base64.url_decode(token.split(".", 3)[0]))
    rescue JSON::ParserError => e
      raise VerificationError, "Malformed JWT header: #{e.message}"
    end

    def validate_schema(payload)
      %w[acr amr auth_time].each do |claim|
        raise VerificationError, "missing OIDC claim: #{claim}" if payload[claim].nil?
      end

      device = payload["rootherald_device"].is_a?(Hash) ? payload["rootherald_device"] : {}
      eat_profile = device["eat_profile"] || payload["eat_profile"]
      if !eat_profile.nil? && eat_profile != EXPECTED_EAT_PROFILE
        raise VerificationError, "Unexpected eat_profile: #{eat_profile.inspect}"
      end

      ueid = device["ueid"] || payload["ueid"]
      raise VerificationError, "Missing required EAT claim: ueid" if ueid.nil? || ueid.to_s.empty?
    end
  end
end
