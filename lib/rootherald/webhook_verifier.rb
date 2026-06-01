# frozen_string_literal: true

require "jwt"

module RootHerald
  # Verifies CAEP SET JWTs sent by the Root Herald webhook subsystem.
  class WebhookVerifier
    ALLOWED_ALGORITHMS = %w[RS256 ES256].freeze

    def initialize(issuer:, jwks:, audience: nil, leeway_seconds: 30)
      raise ArgumentError, "issuer is required" if issuer.nil? || issuer.empty?

      @issuer = issuer
      @jwks = jwks
      @audience = audience
      @leeway = leeway_seconds
    end

    # @param signed_jwt [String]
    # @return [WebhookEvent]
    # @raise [WebhookSignatureError]
    def verify_set(signed_jwt)
      body = signed_jwt.to_s.strip
      raise WebhookSignatureError, "Body is not a compact JWT" unless body.count(".") == 2

      header =
        begin
          JSON.parse(JWT::Base64.url_decode(body.split(".", 3)[0]))
        rescue StandardError => e
          raise WebhookSignatureError, "Malformed SET header: #{e.message}"
        end

      typ = header["typ"]
      raise WebhookSignatureError, "SET typ must be 'secevent+jwt'; got #{typ.inspect}" unless typ == "secevent+jwt"

      kid = header["kid"].to_s
      raise WebhookSignatureError, "SET header missing 'kid'" if kid.empty?

      alg = header["alg"].to_s
      unless ALLOWED_ALGORITHMS.include?(alg)
        raise WebhookSignatureError, "Unsupported SET alg=#{alg.inspect}"
      end

      key = begin
        @jwks.get_key(kid)
      rescue JwksError => e
        raise WebhookSignatureError, "JWKS lookup failed: #{e.message}"
      end

      decode_options = {
        algorithm: alg,
        iss: @issuer,
        verify_iss: true,
        verify_expiration: false, # SET envelopes have no exp
        leeway: @leeway
      }
      if @audience
        decode_options[:aud] = @audience
        decode_options[:verify_aud] = true
      end

      payload, = begin
        JWT.decode(body, key, true, decode_options)
      rescue JWT::DecodeError => e
        raise WebhookSignatureError, "SET signature verification failed: #{e.message}"
      end

      events = payload["events"]
      raise WebhookSignatureError, "SET 'events' map missing or empty" unless events.is_a?(Hash) && !events.empty?

      event_type, event_payload = events.first
      sub_id = payload["sub_id"].is_a?(Hash) ? payload["sub_id"] : {}

      WebhookEvent.new(
        issuer: payload["iss"].to_s,
        audience: payload["aud"]&.to_s,
        issued_at: Time.at((payload["iat"] || 0).to_i),
        jwt_id: payload["jti"].to_s,
        subject_id_format: sub_id["format"].to_s,
        device_id: sub_id["id"].to_s,
        event_type: event_type.to_s,
        event_payload: event_payload.is_a?(Hash) ? event_payload : {},
        raw: payload
      )
    end
  end
end
