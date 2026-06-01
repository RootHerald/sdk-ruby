# frozen_string_literal: true

module RootHerald
  # Friendly tri-state verdict mapped from the EAR status carried in the
  # attestation token. Exposed as symbols (+:allow+, +:warn+, +:deny+) for
  # idiomatic Ruby pattern matching.
  module Verdict
    ALLOW = :allow
    WARN = :warn
    DENY = :deny

    # @param ear_status [String, nil]
    # @return [Symbol] one of +:allow+, +:warn+, +:deny+
    def self.from_ear_status(ear_status)
      case ear_status
      when "affirming" then ALLOW
      when "contraindicated" then DENY
      else WARN
      end
    end
  end
end
