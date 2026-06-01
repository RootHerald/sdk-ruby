# frozen_string_literal: true

require_relative "rootherald/version"
require_relative "rootherald/verdict"
require_relative "rootherald/errors"
require_relative "rootherald/attestation_claims"
require_relative "rootherald/webhook_event"
require_relative "rootherald/jwks_fetcher"
require_relative "rootherald/verifier"
require_relative "rootherald/webhook_verifier"
require_relative "rootherald/client"

# Root Herald server SDK.
#
# Verifies attestation token JWTs and CAEP webhook events (SET JWTs)
# emitted by the Root Herald cloud. Pure Ruby — depends on +jwt+ and
# +faraday+.
#
#   client = RootHerald::Client.new(
#     issuer: "https://rootherald.io/myorg",
#     jwks_uri: "https://rootherald.io/.well-known/jwks.json"
#   )
#   claims = client.verify_token(token)
#   proceed_with_signup if claims.verdict == :allow
module RootHerald
end
