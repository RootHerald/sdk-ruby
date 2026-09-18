# frozen_string_literal: true

module RootHerald
  # The verdict values the server emits at +verdict.device.verdict+, as
  # +AttestResult#verdict+ returns them: symbols +:pass+, +:warn+, +:fail+,
  # the same vocabulary in every Root Herald SDK. A response carrying any
  # other token is refused.
  module Verdict
    # The device satisfied the policy.
    PASS = :pass
    # The device passed with reduced assurance; the policy says whether to proceed.
    WARN = :warn
    # The device did not satisfy the policy, or is not enrolled (see
    # +AttestResult#enrollment_required+).
    FAIL = :fail

    # Read the +verdict.device.verdict+ token. Anything outside the three
    # values the server emits is nil, never a guessed verdict.
    #
    # @param raw [String, nil]
    # @return [Symbol, nil] one of +:pass+, +:warn+, +:fail+
    def self.from_raw(raw)
      case raw
      when "pass" then PASS
      when "warn" then WARN
      when "fail" then FAIL
      end
    end
  end
end
