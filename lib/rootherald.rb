# frozen_string_literal: true

require_relative "rootherald/version"
require_relative "rootherald/verdict"
require_relative "rootherald/errors"
require_relative "rootherald/key_signatures"
require_relative "rootherald/device_encryption"
require_relative "rootherald/client"

# Root Herald server SDK.
#
# Background-Check (server -> server) via RootHerald::Client: your
# keyless client collects opaque blobs and hands them to your server,
# which relays them to Root Herald using its +rh_sk_+ secret key. The
# client never holds a key or talks to Root Herald.
#
# Pure Ruby — depends on +faraday+.
#
#   rh = RootHerald::Client.new(secret_key: ENV.fetch("ROOTHERALD_SECRET_KEY"))
#
#   # Enroll an installation (relay the client's EnrollBegin/EnrollComplete blobs)
#   enroll = rh.relay_enroll(enroll_request_blob)
#   # hand enroll.challenge.to_wire to the client's EnrollComplete, then:
#   device_id = rh.relay_activate(activation_response).device_id
#
#   # Attest; the challenge carries the ask and may name the device expected
#   challenge = rh.issue_challenge(ask: %w[identity posture], expected_devices: [device_id])
#   result = rh.verify(evidence, nonce: challenge.nonce, expected_devices: [device_id])
#   proceed_with_signup if result.verdict == :pass
#
#   # Mint a device-bound signing key, then verify its signatures locally
#   kc = rh.issue_key_challenge(purpose: "sign", expected_devices: [device_id])
#   key = rh.certify_key(certification, nonce: kc.nonce)
#   RootHerald::KeySignatures.verify(key.jwk, message, signature)
#
#   # Mint a device-bound decrypt key, then send it what only that device can read
#   kc = rh.issue_key_challenge(purpose: "decrypt", expected_devices: [device_id])
#   key = rh.certify_key(certification, nonce: kc.nonce)
#   jwe = RootHerald::DeviceEncryption.encrypt_to_device(key, session_token)
module RootHerald
end
