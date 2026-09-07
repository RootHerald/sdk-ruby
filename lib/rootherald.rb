# frozen_string_literal: true

require_relative "rootherald/version"
require_relative "rootherald/verdict"
require_relative "rootherald/errors"
require_relative "rootherald/key_signatures"
require_relative "rootherald/client"

# Root Herald server SDK.
#
# Background-Check (server -> server) via RootHerald::Client: your
# dumb client collects an opaque evidence blob and hands it to your server,
# which appraises it with Root Herald using its +rh_sk_+ secret key. The
# client never holds a key or talks to Root Herald.
#
# Pure Ruby — depends on +faraday+.
#
#   # Background-Check (relay the keyless client's opaque blobs with rh_sk_)
#   rh = RootHerald::Client.new(secret_key: ENV.fetch("ROOTHERALD_SECRET_KEY"))
#
#   # One-time device enroll (relay the client's EnrollBegin/EnrollComplete blobs)
#   enroll = rh.relay_enroll(enroll_request_blob)
#   # hand enroll.challenge to the client's EnrollComplete, then:
#   rh.relay_activate(activation_response)
#   device_id = enroll.device_id
#
#   # Per-attestation appraisal; the challenge carries the ask
#   challenge = rh.issue_challenge(ask: %w[identity posture])
#   result = rh.verify(evidence, challenge_id: challenge.challenge_id)
#   proceed_with_signup if result.verdict == :allow
#
#   # Ask for a key too, and verify later device signatures locally
#   challenge = rh.issue_challenge(ask: %w[identity key], key_purpose: "sign")
#   key = rh.verify(evidence, challenge_id: challenge.challenge_id).key
#   RootHerald::KeySignatures.verify(key.jwk, message, signature)
module RootHerald
end
