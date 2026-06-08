# frozen_string_literal: true

module RootHerald
  # Verified composite attestation token claims. Treat instances as
  # immutable value objects.
  class AttestationClaims
    attr_reader :issuer, :subject, :audience, :issued_at, :expires_at,
                :jwt_id, :acr, :amr, :auth_time, :requested_acr_values,
                :device_id, :attestation_type, :platform, :tpm_class,
                :ear_status, :verdict, :device, :raw

    # @param payload [Hash] verified JWT payload (hash-string-keyed).
    def self.from_payload(payload)
      device = payload["rootherald_device"].is_a?(Hash) ? payload["rootherald_device"] : {}
      pick = ->(key, default = nil) { device.fetch(key) { payload.fetch(key, default) } }

      ear_status = pick.call("ear_status", "warning")

      new(
        issuer: payload["iss"].to_s,
        subject: payload["sub"].to_s,
        audience: payload["aud"].is_a?(Array) ? payload["aud"].first.to_s : payload["aud"].to_s,
        issued_at: Time.at((payload["iat"] || 0).to_i),
        expires_at: Time.at((payload["exp"] || 0).to_i),
        jwt_id: payload["jti"].to_s,
        acr: payload["acr"].to_s,
        amr: Array(payload["amr"]),
        auth_time: Time.at((payload["auth_time"] || 0).to_i),
        requested_acr_values: Array(payload["requested_acr_values"]),
        device_id: pick.call("ueid", "").to_s,
        attestation_type: pick.call("attestation_type", "unknown").to_s,
        platform: pick.call("platform", "").to_s,
        tpm_class: pick.call("tpm_class", "").to_s,
        ear_status: ear_status.to_s,
        verdict: Verdict.from_ear_status(ear_status),
        device: device,
        raw: payload
      )
    end

    def initialize(**kwargs)
      kwargs.each { |k, v| instance_variable_set(:"@#{k}", v) }
      freeze
    end

    def allow?
      verdict == Verdict::ALLOW
    end

    def warn?
      verdict == Verdict::WARN
    end

    def deny?
      verdict == Verdict::DENY
    end
  end
end
