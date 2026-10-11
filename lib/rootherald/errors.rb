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
  # A 401 carrying "activation_refused" is ActivationRefusedError instead.
  class InvalidSecretKeyError < HttpError
    def code = "invalid_secret_key"
  end

  # POST /api/v1/attest/activate refused the enrollment (HTTP 401, server code
  # "activation_refused"): the enrollmentId is unknown, spent or foreign, or
  # the proof did not match. The secret key was accepted; this is not a
  # credential problem. Every activation refusal reason produces this one
  # answer.
  class ActivationRefusedError < HttpError
    def code = "activation_refused"
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

  # The challenge is unknown, expired, or already consumed (HTTP 409). A 409
  # carrying "key_rotation_conflict" is a plain HttpError instead.
  class ChallengeError < HttpError
    def code = "challenge_error"
  end

  # The submitted blob was malformed or unparseable (HTTP 400), including a
  # 7.0-shaped enroll body ("wire_version_unsupported") and a nested body
  # whose qualifiedName does not match ("invalid_enroll_shape"). Note: an
  # un-enrolled / failing device is NOT this error — it returns a verdict.
  class InvalidEvidenceError < HttpError
    def code = "invalid_evidence"
  end

  # The challenge named an ask the server does not know, such as the retired
  # "key" (HTTP 400, server code "invalid_ask"), or the key challenge named a
  # purpose it does not know (server code "invalid_purpose"; #server_error
  # carries which). The backend's code is wrong, not the device.
  class InvalidAskError < HttpError
    def code = "invalid_ask"
  end

  # DeviceEncryption.encrypt_to_device was given a key whose +format+ it cannot
  # produce: "apple-ecies", the Security.framework ECIES envelope a macOS
  # enclave key opens, needs an Apple-side encryptor.
  class EnvelopeFormatNotSupportedError < ArgumentError
    # @return [String] the key's format
    attr_reader :format

    def initialize(format)
      @format = format
      super("key format #{format.inspect} is not produced here: encrypt_to_device writes the jwe envelope a TPM " \
            "decrypt key opens; an apple-ecies key needs an Apple-side encryptor")
    end
  end

  # Client#verify was given expected_key / expected_devices and the verdict
  # did not echo them under +expected+: the server did not enforce the
  # binding, so the verdict says nothing about which device answered. The
  # HTTP exchange succeeded; +status+ is 200.
  class ExpectedNotEnforcedError < HttpError
    def code = "expected_not_enforced"
  end

  # The budget that refused a device, as the server names it.
  Budget = Struct.new(:id, :name, keyword_init: true)

  # The API key's budget cannot pay for a device new to the period (HTTP 429
  # with server code "budget_exhausted" or an X-RootHerald-Quota header).
  # +budget+ names the budget that refused. A 429 without that signal is
  # RateLimitedError.
  class QuotaExceededError < HttpError
    # @return [Budget, nil] the budget that refused, when the server named it
    attr_reader :budget

    def initialize(status, body, message = nil, server_error = nil, budget = nil)
      @budget = budget
      super(status, body, message, server_error)
    end

    def code = "budget_exhausted"
  end

  # The request-rate limiter refused the call (HTTP 429 without a budget
  # signal). Retry after +retry_after_seconds+. Distinct from
  # QuotaExceededError, the metered budget ceiling.
  class RateLimitedError < HttpError
    # @return [Integer, nil] seconds to wait before retrying: the Retry-After
    #   header, else the body's +retryAfterSeconds+, else nil
    attr_reader :retry_after_seconds

    def initialize(status, body, message = nil, server_error = nil, retry_after_seconds = nil)
      @retry_after_seconds = retry_after_seconds
      super(status, body, message, server_error)
    end

    def code = "rate_limited"
  end
end
