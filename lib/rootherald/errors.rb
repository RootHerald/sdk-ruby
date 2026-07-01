# frozen_string_literal: true

module RootHerald
  # Base class for all Root Herald SDK errors.
  class Error < StandardError
    # Stable string code for log correlation across SDKs.
    def code = "rootherald_error"
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

  # Background-Check (server -> server) typed errors. Each maps an HTTP status
  # from the Root Herald API, mirroring the @rootherald/node taxonomy.

  # The secret key was rejected by the API (HTTP 401). A locally-detected bad
  # key (empty / not rh_sk_) is raised as ArgumentError at construction time.
  class InvalidSecretKeyError < HttpError
    def code = "invalid_secret_key"
  end

  # The named policy is unknown or not owned by this tenant (HTTP 422).
  class UnknownPolicyError < HttpError
    def code = "unknown_policy"
  end

  # The challenge is unknown, expired, or already consumed (HTTP 409).
  class ChallengeError < HttpError
    def code = "challenge_error"
  end

  # The submitted evidence blob was malformed or unparseable (HTTP 400). Note:
  # an un-enrolled / failing device is NOT this error — it returns a verdict.
  class InvalidEvidenceError < HttpError
    def code = "invalid_evidence"
  end

  # The account's attestation quota or rate limit was exceeded (HTTP 429).
  class QuotaExceededError < HttpError
    def code = "quota_exceeded"
  end
end
