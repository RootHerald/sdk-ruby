# frozen_string_literal: true

require_relative "rootherald/version"
require_relative "rootherald/verdict"
require_relative "rootherald/errors"
require_relative "rootherald/background_check"

# Root Herald server SDK.
#
# Background-Check (server -> server) via RootHerald::BackgroundCheck: your
# dumb client collects an opaque evidence blob and hands it to your server,
# which appraises it with Root Herald using its +rh_sk_+ secret key. The
# client never holds a key or talks to Root Herald.
#
# Pure Ruby — depends on +faraday+.
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
module RootHerald
end
