# frozen_string_literal: true

# Server -> server flow with a certified device key. The dumb client POSTs its
# opaque evidence blob to YOUR server; your server appraises it with Root Herald
# using the rh_sk_ secret key. The client never holds a key or calls Root Herald
# directly.
#
#   post "/challenges",   to: "attestations#challenge"
#   post "/attestations", to: "attestations#create"
#   post "/signatures",   to: "attestations#verify_signature"
class AttestationsController < ApplicationController
  # Configured once in config/initializers/rootherald.rb (see RH below).
  RH = RootHerald::Client.new(secret_key: ENV.fetch("ROOTHERALD_SECRET_KEY"))

  # 1) Mint a challenge that carries the ask — identity, posture and a signing
  #    key — and hand `challenge` to the client verbatim. What the device must
  #    prove is fixed here, not at verify time.
  def challenge
    c = RH.issue_challenge(
      ask: [RootHerald::Client::ASK_IDENTITY, RootHerald::Client::ASK_POSTURE, RootHerald::Client::ASK_KEY],
      key_purpose: RootHerald::Client::KEY_PURPOSE_SIGN
    )
    render json: { challengeId: c.challenge_id, challenge: c.challenge, expiresAt: c.expires_at }
  end

  # 2) The client quoted over the challenge and posts its opaque evidence here
  #    with the challenge id; appraise it with the rh_sk_ secret key.
  def create
    result = RH.verify(params.require(:evidence).to_unsafe_h,
                       challenge_id: params.require(:challengeId))

    if result.verdict == :allow
      # The key is present only on a pass for a challenge that asked for one.
      # A real app stores it against the user; the Rails cache stands in here.
      key = result.key
      Rails.cache.write("rootherald:key:#{key.key_id}", key.jwk) if key
      render json: { ok: true, verdict: result.verdict, keyId: key&.key_id }
    else
      # An un-enrolled / failing device is a verdict, not an error.
      render json: { ok: false, verdict: result.verdict }, status: :forbidden
    end
  end

  # 3) Later, the device signs something with its TPM-resident key. Check it
  #    against the JWK from the attestation — locally, no Root Herald call.
  #    `message` and `signature` are base64; the signature may be raw r||s or DER.
  def verify_signature
    jwk = Rails.cache.read("rootherald:key:#{params.require(:keyId)}")
    return render json: { error: "unknown keyId" }, status: :not_found unless jwk

    valid = RootHerald::KeySignatures.verify(
      jwk,
      params.require(:message).unpack1("m0"),
      params.require(:signature).unpack1("m0")
    )
    render json: { valid: valid }, status: valid ? :ok : :forbidden
  end
end
