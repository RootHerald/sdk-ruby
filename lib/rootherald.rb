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
require_relative "rootherald/background_check"

# Root Herald server SDK. Two paths:
#
# * Background-Check (server -> server) via RootHerald::BackgroundCheck: your
#   dumb client collects an opaque evidence blob and hands it to your server,
#   which appraises it with Root Herald using its +rh_sk_+ secret key. The
#   client never holds a key or talks to Root Herald.
# * Badge tier (offline verify) via RootHerald::Client#verify_token and
#   RootHerald::Guard: verify a Root Herald-issued EAT (JWT) and CAEP webhook
#   events against the JWKS.
#
# Pure Ruby — depends on +jwt+ and +faraday+.
#
#   # Background-Check (relay the keyless client's opaque blobs with rh_sk_)
#   rh = RootHerald::BackgroundCheck.new(secret_key: ENV.fetch("ROOTHERALD_SECRET_KEY"))
#
#   # One-time device enroll (relay the client's EnrollBegin/EnrollComplete blobs)
#   enroll = rh.relay_enroll(enroll_request_blob)
#   unless enroll.already_enrolled?
#     # hand enroll.challenge to the client's EnrollComplete, then:
#     rh.relay_activate(activation_response)
#   end
#   device_id = enroll.device_id
#
#   # Per-attestation appraisal
#   challenge = rh.issue_challenge
#   result = rh.verify(evidence, challenge_id: challenge.challenge_id)
#   proceed_with_signup if result.verdict == :allow
#
#   # Badge tier
#   client = RootHerald::Client.new(issuer: "https://rootherald.io/myorg")
#   claims = client.verify_token(token)
#   proceed_with_signup if claims.verdict == :allow
module RootHerald
end
