# frozen_string_literal: true

module RootHerald
  # Base class for all Root Herald SDK errors.
  class Error < StandardError
    # Stable string code for log correlation across SDKs.
    def code = "rootherald_error"
  end

  # The Root Herald REST API returned a non-2xx response.
  class HttpError < Error
    attr_reader :status, :body, :server_error

    # @param server_error [String, nil] the server's +error+ discriminator from
    #   the response body (e.g. "unknown_policy", "admission_refused"), or nil
    #   when the body carried none
    def initialize(status, body, message = nil, server_error = nil)
      @status = status
      @body = body
      @server_error = server_error
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

  # A policy bound to the API key no longer exists; nothing is substituted
  # (HTTP 422, server code "unknown_policy"). Rebind the key from the
  # dashboard or PUT /api/v1/admin/api-keys/{id}/policies.
  class UnknownPolicyError < HttpError
    def code = "unknown_policy"
  end

  # Enrollment was refused because the device can never satisfy the identity
  # policy bound to the API key — for example a firmware TPM under a
  # discrete-TPM-only policy (HTTP 422, server code "admission_refused"). The
  # server names the TPM class in the message.
  class AdmissionRefusedError < HttpError
    def code = "admission_refused"
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
