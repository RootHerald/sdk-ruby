# frozen_string_literal: true

module RootHerald
  # Base class for all Root Herald SDK errors.
  class Error < StandardError
    # Stable string code for log correlation across SDKs.
    def code
      "rootherald_error"
    end
  end

  # Attestation token failed verification (signature / claims / schema).
  class VerificationError < Error
    def code = "verification_failed"
  end

  # The token's +exp+ claim is in the past.
  class TokenExpiredError < VerificationError
    def code = "token_expired"
  end

  # CAEP webhook (SET JWT) failed verification.
  class WebhookSignatureError < Error
    def code = "webhook_signature_invalid"
  end

  # JWKS could not be fetched or parsed.
  class JwksError < Error
    def code = "jwks_error"
  end

  # The Root Herald REST API returned a non-2xx response.
  class HttpError < Error
    attr_reader :status, :body

    def initialize(status, body, message = nil)
      @status = status
      @body = body
      super(message || "HTTP #{status}: #{body.to_s[0, 200]}")
    end

    def code = "http_error"
  end
end
