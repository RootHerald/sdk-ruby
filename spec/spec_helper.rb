# frozen_string_literal: true

require "rootherald"
require "jwt"
require "openssl"

RSpec.configure do |c|
  c.expect_with :rspec do |e|
    e.syntax = :expect
  end
  c.filter_run_when_matching :focus
  c.example_status_persistence_file_path = ".rspec_status"
  c.disable_monkey_patching!
end

# Shared test fixtures.
module Fixtures
  ISSUER = "https://rootherald.io/testorg"
  AUDIENCE = "client-abc"
  JWKS_URI = "https://rootherald.io/.well-known/jwks.json"
  KID = "test-key-1"

  module_function

  def keypair
    @keypair ||= OpenSSL::PKey::RSA.new(2048)
  end

  def jwk
    @jwk ||= begin
      base = JWT::JWK.new(keypair.public_key).export
      base["kid"] = KID
      base["use"] = "sig"
      base["alg"] = "RS256"
      base
    end
  end

  def jwks_document
    { "keys" => [jwk] }
  end

  def jwks_fetcher
    @jwks_fetcher ||= RootHerald::JwksFetcher.new(
      jwks_uri: JWKS_URI,
      http_fetcher: ->(_url) { JSON.generate(jwks_document) }
    )
  end

  def make_token(issuer: ISSUER, audience: AUDIENCE, subject: "user-uuid",
                 exp_in: 300, iat: nil, acr: "urn:rootherald:user:phr",
                 eat_profile: "tag:rootherald.io,2026:tpm20-v1",
                 ueid: "device-uuid-1234", ear_status: "affirming",
                 device_overrides: {}, top_overrides: {},
                 algorithm: "RS256", kid: KID)
    now = iat || Time.now.to_i
    device = {
      "eat_profile" => eat_profile,
      "ueid" => ueid,
      "ear_status" => ear_status,
      "verdict" => "pass",
      "attestation_type" => "tpm20",
      "attested_at" => now - 10,
      "quote_verified" => true,
      "secure_boot_verified" => true,
      "platform" => "windows",
      "hardware_model" => "TPM 2.0",
      "tpm_class" => "hardware-discrete-infineon"
    }.merge(device_overrides.transform_keys(&:to_s))

    payload = {
      "iss" => issuer,
      "sub" => subject,
      "aud" => audience,
      "iat" => now,
      "nbf" => now,
      "exp" => now + exp_in,
      "jti" => "jti-#{now}",
      "acr" => acr,
      "amr" => %w[pwd hwk user mfa],
      "auth_time" => now - 30,
      "requested_acr_values" => [acr],
      "rootherald_device" => device
    }.merge(top_overrides.transform_keys(&:to_s))

    JWT.encode(payload, keypair, algorithm, { "kid" => kid })
  end

  def make_set(issuer: ISSUER, audience: nil, sub_id: "device-uuid-1234",
               events: nil, iat: nil, jti: nil, typ: "secevent+jwt",
               algorithm: "RS256", kid: KID)
    now = iat || Time.now.to_i
    body = {
      "iss" => issuer,
      "iat" => now,
      "jti" => jti || "set-#{now}",
      "sub_id" => { "format" => "opaque", "id" => sub_id },
      "events" => events || {
        "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change" => {
          "current_status" => "compliant",
          "previous_status" => "non-compliant"
        }
      }
    }
    body["aud"] = audience if audience
    headers = { "kid" => kid }
    headers["typ"] = typ if typ
    JWT.encode(body, keypair, algorithm, headers)
  end
end
