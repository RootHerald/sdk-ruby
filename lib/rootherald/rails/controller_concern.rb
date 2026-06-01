# frozen_string_literal: true

module RootHerald
  # Rails controller concern: enforces an attestation token on the
  # specified actions before they run.
  #
  #     class SignupsController < ApplicationController
  #       include RootHerald::Guard
  #       guard_device :create, action: "signup"
  #
  #       def create; end
  #     end
  #
  # Configure the SDK client once in an initializer
  # (+config/initializers/rootherald.rb+):
  #
  #     RootHerald::Guard.client = RootHerald::Client.new(
  #       issuer: ENV.fetch("ROOTHERALD_ISSUER"),
  #     )
  module Guard
    class << self
      attr_accessor :client
    end

    def self.included(base)
      base.extend(ClassMethods)
    end

    module ClassMethods
      # @param actions [Array<Symbol>] controller actions to guard
      # @param action [String, nil] business action label (e.g. "signup")
      # @param deny_on_warn [Boolean] reject WARN verdicts in addition to DENY
      def guard_device(*actions, action: nil, deny_on_warn: false)
        before_action(only: actions) do
          token = rootherald_extract_token
          if token.nil? || token.empty?
            render json: { error: "missing_attestation_token" }, status: :unauthorized
            next
          end

          client = RootHerald::Guard.client or raise "RootHerald::Guard.client not configured"
          claims =
            begin
              client.verify_token(token)
            rescue RootHerald::TokenExpiredError
              render json: { error: "token_expired" }, status: :unauthorized
              next
            rescue RootHerald::VerificationError => e
              render json: { error: "token_invalid", message: e.message }, status: :unauthorized
              next
            end

          if claims.verdict == RootHerald::Verdict::DENY
            render json: { error: "device_denied", action: action }, status: :forbidden
            next
          end
          if deny_on_warn && claims.verdict == RootHerald::Verdict::WARN
            render json: { error: "device_warned", action: action }, status: :forbidden
            next
          end

          @rootherald_claims = claims
        end
      end
    end

    private

    def rootherald_extract_token
      auth = request.headers["Authorization"].to_s
      return auth[7..].strip if auth.downcase.start_with?("bearer ")

      request.headers["X-RootHerald-Token"].to_s.strip
    end

    # @return [AttestationClaims, nil]
    def rootherald_claims
      @rootherald_claims
    end
  end
end
